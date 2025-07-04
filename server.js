require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const admin = require('firebase-admin'); // For Firestore
const cors = require('cors');

// --- Firebase Admin SDK Initialization ---
try {
  const serviceAccountJsonString = process.env.GCP_SERVICE_ACCOUNT_KEY_B64 
    ? Buffer.from(process.env.GCP_SERVICE_ACCOUNT_KEY_B64, 'base64').toString('utf8')
    : process.env.GCP_SERVICE_ACCOUNT_KEY_JSON;
  
  const serviceAccount = JSON.parse(serviceAccountJsonString);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: process.env.GCP_PROJECT_ID,
  });

  console.log('[Firebase] Admin SDK initialized successfully.');
} catch (error) {
  console.error('[Firebase] ERROR initializing Admin SDK:', error.message);
  console.error('[Firebase] Ensure GCP_SERVICE_ACCOUNT_KEY_B64 or GCP_SERVICE_ACCOUNT_KEY_JSON is a valid JSON string.');
  process.exit(1);
}

const firestore = admin.firestore();

const transactionsCollection = firestore.collection('transactions');
const salesCollection = firestore.collection('sales');
const errorsCollection = firestore.collection('errors');
const floatCollection = firestore.collection('float_balances');
const configAirtimeNetworksCollection = firestore.collection('config_airtime_networks');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS configuration
const corsOptions = {
  origin: 'https://daima-pay-portal.onrender.com', 
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
};

app.use(cors(corsOptions));
app.options('/*splat', cors(corsOptions)); 
app.use(bodyParser.json());

// --- Global Caches for M-Pesa Airtime Token ---
let cachedAirtimeToken = null;
let tokenExpiryTimestamp = 0;

// Africa's Talking SDK Initialization (already present)
const africastalking = require('africastalking')({
  apiKey: process.env.AT_API_KEY,
  username: process.env.AT_USERNAME,
});


// --- Helper Functions (Copied from offline server for consistency) ---

function detectCarrier(phoneNumber) {
  const normalized = phoneNumber.replace(/^(\+254|254)/, '0').trim();
  const prefix3 = normalized.substring(1, 4); // after '0'
  const safaricom = new Set([
    '110', '111', '112', '113', '114', '115', '116', '117', '118', '119',
    ...range(701, 709),
    ...range(710, 719),
    ...range(720, 729),
    '740', '741', '742', '743', '745', '746', '748',
    '757', '758', '759', '768',
    ...range(790, 799)
  ]);
  const airtel = new Set([
    '100', '101', '102',
    ...range(730, 739),
    ...range(750, 756),
    ...range(780, 789)
  ]);
  const telkom = new Set(range(770, 779));
  const equitel = new Set(['763', '764', '765', '766']);
  const faiba = new Set(['747']);

  if (safaricom.has(prefix3)) return 'Safaricom';
  if (airtel.has(prefix3)) return 'Airtel';
  if (telkom.has(prefix3)) return 'Telkom';
  if (equitel.has(prefix3)) return 'Equitel';
  if (faiba.has(prefix3)) return 'Faiba';
  return 'Unknown';

  function range(a, b) {
    const arr = [];
    for (let i = a; i <= b; i++) arr.push(String(i));
    return arr;
  }
}

function normalizePhoneForCarrier(phoneNumber, carrier) {
  let phone = String(phoneNumber).trim();
  if (!phone) {
    throw new Error("Phone number is empty or invalid.");
  }

  if (carrier.toLowerCase() === 'safaricom') {
    if (phone.startsWith('254')) {
      phone = '0' + phone.slice(3);
    } else if (phone.startsWith('+254')) {
      phone = '0' + phone.slice(4);
    }
    if (!phone.startsWith('0')) {
      phone = '0' + phone;
    }
    return phone;
  } else if (['airtel', 'telkom', 'faiba', 'equitel'].includes(carrier.toLowerCase())) {
    if (phone.startsWith('+254')) {
      return phone;
    } else if (phone.startsWith('0')) {
      return '+254' + phone.slice(1);
    } else if (phone.startsWith('254')) {
      return '+' + phone;
    } else {
      if (phone.length === 9 && (phone.startsWith('7') || phone.startsWith('1'))) {
         return '+254' + phone;
      }
      throw new Error(`Africa's Talking recipients must start with +254, 254, or 0. Received: ${phoneNumber}`);
    }
  }
  return phone;
}

async function getCachedAirtimeToken() {
  const now = Date.now();
  if (cachedAirtimeToken && now < tokenExpiryTimestamp) {
    console.log('🔑 [M-Pesa Token] Using cached dealer token');
    return cachedAirtimeToken;
  }

  console.log('🔄 [M-Pesa Token] Fetching new dealer token...');
  // Ensure consistent environment variable names
  const auth = Buffer.from(`${process.env.MPESA_AIRTIME_CONSUMER_KEY}:${process.env.MPESA_AIRTIME_CONSUMER_SECRET}`).toString('base64');

  try {
    const response = await axios.post(
      process.env.MPESA_GRANT_URL,
      {},
      {
        headers: {
          Authorization: `Basic ${auth}`,
          'Content-Type': 'application/json',
        },
      }
    );
    const token = response.data.access_token;
    cachedAirtimeToken = token;
    tokenExpiryTimestamp = now + 3599 * 1000;
    console.log('✅ [M-Pesa Token] New dealer token acquired.');
    return token;
  } catch (error) {
    console.error('❌ [M-Pesa Token] Failed to get dealer token:', error.response ? error.response.data : error.message);
    throw new Error('Failed to acquire M-Pesa airtime dealer token.');
  }
}

async function getCarrierBonus(carrier, amount) {
    console.log(`[getCarrierBonus] Fetching bonus for ${carrier} with amount ${amount}`);
    try {
        const docRef = configAirtimeNetworksCollection.doc(carrier.toLowerCase());
        const doc = await docRef.get();

        if (doc.exists) {
            const data = doc.data();
            const commissionRate = Number(data.commission_rate) || 0;
            const bonus = parseFloat((amount * commissionRate).toFixed(2));
            console.log(`[getCarrierBonus] Found ${carrier} commission rate: ${commissionRate}, calculated bonus: ${bonus}`);
            return { bonus, commission_rate: commissionRate };
        } else {
            console.warn(`[getCarrierBonus] No configuration found for carrier: ${carrier}. Returning 0 bonus.`);
            return { bonus: 0, commission_rate: 0 };
        }
    } catch (error) {
        console.error(`❌ [getCarrierBonus] Error fetching bonus for ${carrier}:`, error.message);
        return { bonus: 0, commission_rate: 0 }; // Default to no bonus on error
    }
}

async function sendSafaricomAirtime(receiverNumber, amount) {
  const { bonus, commission_rate } = await getCarrierBonus('Safaricom', amount);
  const totalAmount = parseFloat((amount + bonus).toFixed(2));

  console.log(`[Safaricom Airtime] Base Amount: ${amount}, Bonus: ${bonus}, Total Amount for Top-up: ${totalAmount}`);

  const token = await getCachedAirtimeToken();
  const normalizedReceiver = normalizePhoneForCarrier(receiverNumber, 'Safaricom');
  const adjustedAmount = totalAmount * 100;

  if (!process.env.DEALER_SENDER_MSISDN || !process.env.DEALER_SERVICE_PIN || !process.env.MPESA_AIRTIME_URL) {
      console.error('[Safaricom Airtime] Missing environment variables for dealer API.');
      throw new Error('Missing Safaricom dealer API configuration.');
  }

  const body = {
    senderMsisdn: process.env.DEALER_SENDER_MSISDN,
    amount: adjustedAmount,
    servicePin: process.env.DEALER_SERVICE_PIN,
    receiverMsisdn: normalizedReceiver,
  };

  console.log('[Safaricom Airtime] Sending dealer airtime request to:', process.env.MPESA_AIRTIME_URL);
  console.log('Request Body (masked servicePin):', { ...body, servicePin: '*****' });

  try {
    const response = await axios.post(
      process.env.MPESA_AIRTIME_URL,
      body,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      }
    );
    console.log('✅ [Safaricom Airtime] Dealer airtime API response:', response.data);
    return {
        ...response.data,
        bonus,
        commission_rate,
        total_sent_to_api: totalAmount
    };
  } catch (error) {
    console.error('❌ [Safaricom Airtime] Dealer airtime send failed:', error.response ? error.response.data : error.message);
    throw new Error(`Safaricom airtime send failed: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
  }
}

async function sendAfricasTalkingAirtime(receiverNumber, amount, carrier) {
    const { bonus, commission_rate } = await getCarrierBonus(carrier, amount);
    const totalAmount = parseFloat((amount + bonus).toFixed(2));

    console.log(`[Africa's Talking] Base Amount: ${amount}, Bonus: ${bonus}, Total Amount for Top-up: ${totalAmount}`);

    const formattedAmount = `KES ${totalAmount}`;
    const normalizedPhone = normalizePhoneForCarrier(receiverNumber, carrier);

    console.log(`[Africa's Talking] Sending airtime to ${normalizedPhone} (${carrier}) for ${formattedAmount}`);

    try {
        const response = await africastalking.AIRTIME.send({
            recipients: [{ phoneNumber: normalizedPhone, amount: formattedAmount }],
        });
        console.log('✅ [Africa\'s Talking] Airtime sent:', response);

        if (response && response.responses && response.responses.length > 0 && response.responses[0].status === 'Sent') {
            return {
                status: 'SUCCESS',
                message: 'Airtime sent successfully via Africa\'s Talking',
                atResponse: response,
                bonus,
                commission_rate,
                total_sent_to_api: totalAmount
            };
        } else {
            const errorMessage = (response && response.responses && response.responses[0] && response.responses[0].errorMessage) ||
                                 (response && response.errorMessage) ||
                                 'Africa\'s Talking API error (unspecified)';
            throw new Error(errorMessage);
        }
    } catch (error) {
        console.error('❌ [Africa\'s Talking] Airtime send failed:', error.message || error);
        throw new Error(`Africa's Talking airtime send failed: ${error.message || JSON.stringify(error)}`);
    }
}

async function updateFloatBalance(carrier, amount, transactionId, status, type = 'debit') {
    const floatDocRef = floatCollection.doc(carrier.toLowerCase());

    try {
        await firestore.runTransaction(async (t) => {
            const doc = await t.get(floatDocRef);

            let currentBalance = 0;
            if (doc.exists) {
                currentBalance = doc.data().balance || 0;
            }

            let newBalance = currentBalance;
            if (status === 'COMPLETED' && type === 'debit') {
                newBalance = currentBalance - parseFloat(amount);
            }

            t.set(floatDocRef, {
                balance: newBalance,
                lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
                lastTransactionId: transactionId,
                lastTransactionAmount: parseFloat(amount),
                lastTransactionStatus: status,
                lastTransactionType: type,
            }, { merge: true });

            console.log(`✅ [Float] Updated ${carrier} float: ${currentBalance} -> ${newBalance}`);
        });
    } catch (error) {
        console.error(`❌ [Float] Failed to update float balance for ${carrier}:`, error.message);
        // Log this float update failure to errors collection
        await errorsCollection.doc(`FLOAT_UPDATE_ERROR_${transactionId}_${Date.now()}`).set({
          type: 'FLOAT_UPDATE_ERROR',
          transactionId: transactionId,
          carrier: carrier,
          amount: amount,
          status: status,
          error: error.message,
          stack: error.stack,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
    }
}


// --- API Endpoints ---

// STK Push Payment Initiation
app.post('/pay', async (req, res) => {
  const { topupNumber, amount, mpesaNumber } = req.body;
  const now = admin.firestore.FieldValue.serverTimestamp();

  if (!topupNumber || !amount || !mpesaNumber) {
    // Log error to errorsCollection
    await errorsCollection.add({
      type: 'STKPUSH_INIT_ERROR',
      error: 'Missing required fields for STK Push initiation.',
      requestBody: req.body,
      createdAt: now,
    });
    return res.status(400).json({ error: 'Missing fields! All fields are required.' });
  }

  if (isNaN(amount) || parseFloat(amount) <= 0) {
    // Log error to errorsCollection
    await errorsCollection.add({
      type: 'STKPUSH_INIT_ERROR',
      error: `Invalid amount provided: ${amount}. Amount must be a positive number.`,
      requestBody: req.body,
      createdAt: now,
    });
    return res.status(400).json({ error: 'Invalid amount. Amount must be a positive number.' });
  }

  const carrier = detectCarrier(topupNumber);
  console.log(`📡 Detected Carrier for ${topupNumber}: ${carrier}`);

  if (carrier === 'Unknown') {
    // Log error to errorsCollection
    await errorsCollection.add({
      type: 'STKPUSH_INIT_ERROR',
      error: `Unsupported carrier prefix for phone number: ${topupNumber}.`,
      requestBody: req.body,
      createdAt: now,
    });
    return res.status(400).json({ error: 'Unsupported carrier prefix. Please check the top-up number.' });
  }

  try {
    const auth = Buffer.from(
      `${process.env.DARAJA_CONSUMER_KEY}:${process.env.DARAJA_CONSUMER_SECRET}`
    ).toString('base64');

    const authResponse = await axios.get(
      'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
      {
        headers: { Authorization: `Basic ${auth}` },
      }
    );

    const access_token = authResponse.data.access_token;

    const timestamp = new Date().toISOString().replace(/[-T:.Z]/g, '').slice(0, 14);
    const password = Buffer.from(
      `${process.env.BUSINESS_SHORTCODE}${process.env.DARAJA_PASSKEY}${timestamp}`
    ).toString('base64');

    const stkPushPayload = {
      BusinessShortCode: process.env.BUSINESS_SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: parseFloat(amount), 
      PartyA: mpesaNumber,
      PartyB: process.env.TILL_SHORTCODE, 
      PhoneNumber: mpesaNumber,
      CallBackURL: `${process.env.BASE_URL}/stk-callback`, 
      AccountReference: 'DaimaPayAirtime', 
      TransactionDesc: 'Airtime Purchase',
    };

    const stkResponse = await axios.post(
      'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
      stkPushPayload,
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      }
    );

    console.log('✅ STK Push Initiated Response:', stkResponse.data);

    const checkoutRequestID = stkResponse.data.CheckoutRequestID;
    const merchantRequestId = stkResponse.data.MerchantRequestID;

    // --- Store initial transaction in both collections ---
    // 1. transactionsCollection (minimal)
    await transactionsCollection.doc(checkoutRequestID).set({
      date: now,
      transactionID: checkoutRequestID,
      amount: parseFloat(amount),
      recipient: topupNumber,
      source: 'ONLINE_STK',
      status: 'PENDING',
    });
    console.log(`📈 [transactions] Initial record for ${checkoutRequestID} created.`);

    // 2. salesCollection
    await salesCollection.doc(checkoutRequestID).set({
      date: now,
      customerName: `Online User (${mpesaNumber})`, 
      phone: mpesaNumber, 
      carrier,
      status: 'PENDING',
      transactionCode: checkoutRequestID, 
      originalAmountPaid: parseFloat(amount),
      stkPushInitiationResponse: stkResponse.data, 
      stkPushPayload: stkPushPayload, 
      merchantRequestId: merchantRequestId,
      topupNumber: topupNumber, 
      lastUpdated: now,
    });
    console.log(`📈 [sales] Initial record for ${checkoutRequestID} created.`);

    res.json({
      message: `STK push initiated for ${carrier}. Please complete the payment on your phone.`,
      CheckoutRequestID: checkoutRequestID,
    });

  } catch (err) {
    console.error('❌ STK Push Error:', err.response ? err.response.data : err.message);
    let errorMessage = 'STK push failed. An unexpected error occurred.';
    if (err.response && err.response.data && err.response.data.errorMessage) {
        errorMessage = err.response.data.errorMessage;
    } else if (err.message) {
        errorMessage = err.message;
    }

    // Log error to errorsCollection
    await errorsCollection.add({
      type: 'STKPUSH_INIT_FAILURE',
      error: errorMessage,
      requestBody: req.body,
      mpesaApiResponse: err.response ? err.response.data : null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.status(500).json({ error: errorMessage });
  }
});

// M-Pesa STK Callback Handler
app.post('/stk-callback', async (req, res) => {
  const callback = req.body;
  const now = admin.firestore.FieldValue.serverTimestamp();

  console.log('📞 Received STK Callback:', JSON.stringify(callback));

  const resultCode = callback.Body.stkCallback.ResultCode;
  const checkoutRequestID = callback.Body.stkCallback.CheckoutRequestID;
  const mpesaReceiptNumber = callback.Body.stkCallback.CallbackMetadata?.Item.find(item => item.Name === 'MpesaReceiptNumber')?.Value || null;
  const transactionDateFromMpesa = callback.Body.stkCallback.CallbackMetadata?.Item.find(item => item.Name === 'TransactionDate')?.Value || null;
  const phoneNumberUsedForPayment = callback.Body.stkCallback.CallbackMetadata?.Item.find(item => item.Name === 'PhoneNumber')?.Value || null;


  const txDocRef = transactionsCollection.doc(checkoutRequestID);
  const txDoc = await txDocRef.get();

  if (!txDoc.exists) {
    console.error('❌ No matching transaction for CheckoutRequestID in Firestore:', checkoutRequestID);
    // Log this critical error
    await errorsCollection.doc(`STK_CALLBACK_NO_TX_${checkoutRequestID}_${Date.now()}`).set({
      type: 'STK_CALLBACK_ERROR',
      error: 'No matching transaction found in transactionsCollection for CheckoutRequestID.',
      checkoutRequestID: checkoutRequestID,
      callbackData: callback,
      createdAt: now,
    });
    return res.json({ resultCode: 0, resultDesc: 'No matching transaction found locally for this callback.' });
  }

  const txData = txDoc.data();
  const { topupNumber, amount: originalAmount, carrier, payer } = txData; 

  let finalTxStatus = 'FAILED'; 
  let finalSalesStatus = 'FAILED'; 
  let airtimeResult = null;
  let bonusAmount = 0;
  let commissionRate = 0;
  let totalSentAmount = originalAmount;


  if (resultCode === 0) {
    // M-Pesa payment was successful
    try {
      if (carrier === 'Safaricom' || ['Airtel', 'Telkom', 'Faiba', 'Equitel'].includes(carrier)) {
        const bonusData = await getCarrierBonus(carrier, originalAmount);
        bonusAmount = bonusData.bonus;
        commissionRate = bonusData.commission_rate;
        totalSentAmount = parseFloat((originalAmount + bonusAmount).toFixed(2));

        if (carrier === 'Safaricom') {
          airtimeResult = await sendSafaricomAirtime(topupNumber, originalAmount); // Pass original amount, function handles bonus
          if (airtimeResult && airtimeResult.responseStatus === '200') {
            finalTxStatus = 'SUCCESS';
            finalSalesStatus = 'COMPLETED';
          } else {
            console.error(`❌ Safaricom airtime send indicates non-200 status:`, airtimeResult);
            // Log specific error
            await errorsCollection.doc(`SAF_API_FAIL_${checkoutRequestID}`).set({
              type: 'AIRTIME_SEND_ERROR',
              subType: 'SAFARICOM_API_FAILURE',
              error: `Safaricom API returned non-200 status: ${JSON.stringify(airtimeResult)}`,
              transactionCode: checkoutRequestID,
              originalAmount: originalAmount,
              airtimeResponse: airtimeResult,
              callbackData: callback,
              createdAt: now,
            });
          }
        } else { // Africa's Talking carriers
          airtimeResult = await sendAfricasTalkingAirtime(topupNumber, originalAmount, carrier); // Pass original amount
          if (airtimeResult && airtimeResult.status === 'SUCCESS') {
            finalTxStatus = 'SUCCESS';
            finalSalesStatus = 'COMPLETED';
          } else {
            console.error(`❌ Africa's Talking airtime send indicates non-SUCCESS status:`, airtimeResult);
            // Log specific error
            await errorsCollection.doc(`AT_API_FAIL_${checkoutRequestID}`).set({
              type: 'AIRTIME_SEND_ERROR',
              subType: 'AFRICASTALKING_API_FAILURE',
              error: `Africa's Talking API returned non-SUCCESS status: ${JSON.stringify(airtimeResult)}`,
              transactionCode: checkoutRequestID,
              originalAmount: originalAmount,
              airtimeResponse: airtimeResult,
              callbackData: callback,
              createdAt: now,
            });
          }
        }
      } else {
        console.warn(`⚠️ Airtime top-up not supported for carrier: ${carrier}.`);
        airtimeResult = { error: 'Unsupported carrier for airtime top-up.' };
        // Log specific error
        await errorsCollection.doc(`UNSUPPORTED_CARRIER_ONLINE_${checkoutRequestID}`).set({
          type: 'AIRTIME_SEND_ERROR',
          subType: 'UNSUPPORTED_CARRIER',
          error: `Airtime top-up not supported for carrier: ${carrier}.`,
          transactionCode: checkoutRequestID,
          callbackData: callback,
          createdAt: now,
        });
      }

      // Update float balance ONLY if airtime send was COMPLETED
      if (finalSalesStatus === 'COMPLETED') {
        await updateFloatBalance(carrier, totalSentAmount, checkoutRequestID, 'COMPLETED', 'debit');
      }

    } catch (err) {
      console.error('❌ Airtime send failed (exception caught):', err.message);
      // Log critical error
      await errorsCollection.doc(`AIRTIME_EXCEPTION_ONLINE_${checkoutRequestID}`).set({
        type: 'AIRTIME_SEND_ERROR',
        subType: 'RUNTIME_EXCEPTION',
        error: err.message,
        stack: err.stack,
        transactionCode: checkoutRequestID,
        callbackData: callback,
        createdAt: now,
      });
    }
  } else {
    // M-Pesa payment failed or was cancelled by user
    console.log(`❌ Payment failed for ${checkoutRequestID}. ResultCode: ${resultCode}, Desc: ${callback.Body.stkCallback.ResultDesc}`);
    finalTxStatus = 'FAILED';
    finalSalesStatus = 'FAILED';

    // Log payment failure to errors collection
    await errorsCollection.doc(`STK_PAYMENT_FAILED_${checkoutRequestID}`).set({
      type: 'STK_PAYMENT_ERROR',
      error: `STK Payment failed or was cancelled. ResultCode: ${resultCode}, ResultDesc: ${callback.Body.stkCallback.ResultDesc}`,
      checkoutRequestID: checkoutRequestID,
      callbackData: callback,
      createdAt: now,
    });
  }

  // --- Final Updates to Firestore ---
  await transactionsCollection.doc(checkoutRequestID).update({
    status: finalTxStatus,
    lastUpdated: now,
  });
  console.log(`✅ [transactions] Final status for ${checkoutRequestID} updated to: ${finalTxStatus}`);

  // 2. Update 'sales' collection (detailed final record)
  await salesCollection.doc(checkoutRequestID).update({
    status: finalSalesStatus,
    airtimeResult: airtimeResult,
    completedAt: now,
    lastUpdated: now,
    bonus: bonusAmount,
    commission_rate: commissionRate,
    total_sent: totalSentAmount,
    mpesaReceiptNumber: mpesaReceiptNumber,
    balanceAfterPayment: callback.Body.stkCallback.CallbackMetadata?.Item.find(item => item.Name === 'Balance')?.Value || null,
    transactionDateFromMpesa: transactionDateFromMpesa,
    phoneNumberUsedForPayment: phoneNumberUsedForPayment,
    resultCode: resultCode,
    resultDesc: callback.Body.stkCallback.ResultDesc,
    errorDetails: (finalSalesStatus === 'FAILED' && airtimeResult && airtimeResult.error) ? airtimeResult.error : null,
  });
  console.log(`✅ [sales] Final status for ${checkoutRequestID} updated to: ${finalSalesStatus}`);
  res.json({ resultCode: 0, resultDesc: 'Callback received and processed by DaimaPay server.' });
});


app.get('/transaction-status/:checkoutRequestID', async (req, res) => {
    const { checkoutRequestID } = req.params;
    try {
        const txDoc = await transactionsCollection.doc(checkoutRequestID).get();

        if (!txDoc.exists) {
            console.warn(`Attempted to fetch status for non-existent CheckoutRequestID: ${checkoutRequestID}`);
            return res.status(404).json({ error: 'Transaction not found.' });
        }

        const data = txDoc.data();
        const createdAtISO = data.date ? data.date.toDate().toISOString() : null; 
        const completedAtISO = data.lastUpdated ? data.lastUpdated.toDate().toISOString() : null;

        res.json({
            status: data.status,
            completedAt: completedAtISO,
            createdAt: createdAtISO,
            transactionID: data.transactionID,
            amount: data.amount,
            recipient: data.recipient, 
            source: data.source,
        });
    } catch (error) {
        console.error('Error fetching transaction status for:', checkoutRequestID, error);
        res.status(500).json({ error: 'Failed to fetch transaction status.' });
    }
});


// Default route for health check
app.get('/', (req, res) => {
  res.send('DaimaPay backend is live ✅');
});

// Start the server
app.listen(PORT, () => {
  console.log(`🚀 Web server running on port ${PORT}`);
});
