require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const africastalking = require('africastalking')({
    apiKey: process.env.AT_API_KEY,
    username: process.env.AT_USERNAME,
});
const { Firestore } = require('@google-cloud/firestore');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

const firestore = new Firestore({
    projectId: process.env.GCP_PROJECT_ID,
    keyFilename: process.env.GCP_KEY_FILE,
});

// Using a single collection for transactions, good.
const txCollection = firestore.collection('transactions');
const errorsCollection = firestore.collection('errors'); // Added for more robust error logging

const corsOptions = {
    origin: 'https://daima-pay-portal.onrender.com', // Ensure this is your actual frontend URL
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
};

app.use(cors(corsOptions));
app.options('/*splat', cors(corsOptions)); // Handle pre-flight requests
app.use(bodyParser.json());

let cachedAirtimeToken = null;
let tokenExpiryTimestamp = 0;

// Carrier detection helper
function detectCarrier(phoneNumber) {
    const normalized = phoneNumber.replace(/^(\+254|254)/, '0').trim();
    // Ensure the number is 9 digits after '0'
    if (normalized.length !== 10 || !normalized.startsWith('0')) {
        return 'Unknown';
    }
    const prefix3 = normalized.substring(1, 4); // after '0'

    const safaricom = new Set([
        '110', '111', '112', '113', '114', '115', '116', '117', '118', '119', // 07xx -> 011x
        '701', '702', '703', '704', '705', '706', '707', '708', '709',
        '710', '711', '712', '713', '714', '715', '716', '717', '718', '719',
        '720', '721', '722', '723', '724', '725', '726', '727', '728', '729',
        '740', '741', '742', '743', '745', '746', '748',
        '757', '758', '759',
        '768',
        '790', '791', '792', '793', '794', '795', '796', '797', '798', '799'
    ]);
    const airtel = new Set([
        '100', '101', '102', // 010x
        '730', '731', '732', '733', '734', '735', '736', '737', '738', '739',
        '750', '751', '752', '753', '754', '755', '756',
        '780', '781', '782', '783', '784', '785', '786', '787', '788', '789'
    ]);
    const telkom = new Set([
        '770', '771', '772', '773', '774', '775', '776', '777', '778', '779'
    ]);
    // Added Equitel and Faiba (assuming common prefixes) - You might need to verify these.
    const equitel = new Set([
        '764', '765', '766', '767',
        '769', // Some sources list 0769
    ]);
    const faiba = new Set([
        '747',
    ]);


    if (safaricom.has(prefix3)) return 'Safaricom';
    if (airtel.has(prefix3)) return 'Airtel';
    if (telkom.has(prefix3)) return 'Telkom';
    if (equitel.has(prefix3)) return 'Equitel'; // Added Equitel
    if (faiba.has(prefix3)) return 'Faiba';     // Added Faiba
    return 'Unknown';
}

// ✅ Safaricom dealer token
async function getCachedAirtimeToken() {
    const now = Date.now();
    if (cachedAirtimeToken && now < tokenExpiryTimestamp) {
        console.log('🔑 Using cached dealer token');
        return cachedAirtimeToken;
    }
    try {
        const auth = Buffer.from(`${process.env.MPESA_AIRTIME_KEY}:${process.env.MPESA_AIRTIME_SECRET}`).toString('base64');
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
        tokenExpiryTimestamp = now + 3599 * 1000; // Token expires in 1 hour (3600 seconds)
        console.log('✅ Fetched new dealer token.');
        return token;
    } catch (error) {
        console.error('❌ Failed to get Safaricom airtime token:', error.response ? error.response.data : error.message);
        throw new Error('Failed to obtain Safaricom airtime token.');
    }
}

function normalizeReceiverPhoneNumber(num) {
    // Ensures the number starts with 0 and is 10 digits long.
    let normalized = num.replace(/^(\+254|254)/, '0').trim();
    if (normalized.startsWith('0') && normalized.length === 10) {
        return normalized;
    }
    // If it's 7xx or 1xx, prepend 0
    if (normalized.length === 9 && !normalized.startsWith('0')) {
        return `0${normalized}`;
    }
    // Return as is if it doesn't fit common Kenyan formats for now,
    // carrier detection should catch it if invalid.
    return num;
}

// ✅ Send Safaricom dealer airtime
async function sendSafaricomAirtime(receiverNumber, amount) {
    try {
        const token = await getCachedAirtimeToken();
        const normalizedReceiver = normalizeReceiverPhoneNumber(receiverNumber);
        // Safaricom Airtime API expects amount in cents, so multiply by 100
        const adjustedAmount = Math.round(amount * 100); 

        const body = {
            senderMsisdn: process.env.DEALER_SENDER_MSISDN,
            amount: adjustedAmount,
            servicePin: process.env.DEALER_SERVICE_PIN,
            receiverMsisdn: normalizedReceiver,
        };

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

        console.log('✅ Safaricom dealer airtime API response:', response.data);
        return {
            status: 'SUCCESS',
            message: 'Safaricom airtime sent',
            data: response.data,
        };
    } catch (error) {
        console.error('❌ Safaricom dealer airtime send failed:', error.response ? error.response.data : error.message);
        return {
            status: 'FAILED',
            message: 'Safaricom airtime send failed',
            error: error.response ? error.response.data : error.message,
        };
    }
}

// Function to send Africa's Talking Airtime
async function sendAfricasTalkingAirtime(phoneNumber, amount, carrier) {
    try {
        const result = await africastalking.AIRTIME.send({
            recipients: [{ phoneNumber: normalizeReceiverPhoneNumber(phoneNumber), amount: `KES ${amount}` }],
        });
        console.log(`✅ Africa's Talking airtime sent to ${carrier}:`, result);
        // AT response structure varies, typically check result.responses[0].status
        if (result && result.responses && result.responses.length > 0 && result.responses[0].status === 'Success') {
            return {
                status: 'SUCCESS',
                message: 'Africa\'s Talking airtime sent',
                data: result,
            };
        } else {
            console.error(`❌ Africa's Talking airtime send indicates non-success status:`, result);
            return {
                status: 'FAILED',
                message: 'Africa\'s Talking airtime send failed or not successful.',
                error: result,
            };
        }
    } catch (error) {
        console.error(`❌ Africa's Talking airtime send failed for ${carrier} (exception caught):`, error.message);
        return {
            status: 'FAILED',
            message: 'Africa\'s Talking airtime send failed (exception)',
            error: error.message,
        };
    }
}


// --- C2B (Offline Paybill) Callbacks ---

// C2B Validation Endpoint (Optional but Recommended)
app.post('/c2b-validation', async (req, res) => {
    const callbackData = req.body;
    const now = new Date().toISOString();

    console.log('📞 Received C2B Validation Callback:', JSON.stringify(callbackData));

    // Extract relevant data from callbackData
    const {
        TransactionType,
        TransID,
        TransTime,
        TransAmount,
        BusinessShortCode,
        BillRefNumber, // This is the Account Number entered by the customer
        InvoiceNumber,
        OrgAccountBalance,
        ThirdPartyTransID,
        MSISDN,
        FirstName,
        MiddleName,
        LastName,
    } = callbackData;

    // IMPORTANT: Implement your business validation logic here
    // For example, check if BillRefNumber (intended topup number) is valid or if it corresponds
    // to an existing account in your system, or if TransAmount is within acceptable limits.

    // Example Validation: If BillRefNumber is "INVALID", reject the transaction.
    // In a real scenario, you'd check if `BillRefNumber` is a valid phone number or order ID.
    if (!BillRefNumber || detectCarrier(BillRefNumber) === 'Unknown') {
        console.warn(`⚠️ C2B Validation rejected: Invalid or missing BillRefNumber (${BillRefNumber})`);
        await errorsCollection.add({
            type: 'C2B_VALIDATION_REJECT',
            error: 'Invalid or missing BillRefNumber (Account Number) provided.',
            callbackData: callbackData,
            createdAt: now,
        });
        // Respond to M-Pesa to reject the transaction
        return res.json({
            "ResultCode": 1, // 0 for Accept, 1 for Reject
            "ResultDesc": "Invalid Account Number (BillRefNumber) provided."
        });
    }

    // You could also check if the amount is reasonable, etc.
    if (TransAmount <= 0) {
        console.warn(`⚠️ C2B Validation rejected: Invalid amount (${TransAmount})`);
        await errorsCollection.add({
            type: 'C2B_VALIDATION_REJECT',
            error: 'Transaction amount must be greater than zero.',
            callbackData: callbackData,
            createdAt: now,
        });
        return res.json({
            "ResultCode": 1,
            "ResultDesc": "Transaction amount must be greater than zero."
        });
    }

    // If all validation passes, accept the transaction
    console.log('✅ C2B Validation successful.');
    res.json({
        "ResultCode": 0, // 0 for Accept, 1 for Reject
        "ResultDesc": "Validation successful."
    });
});

// C2B Confirmation Endpoint (Mandatory)
app.post('/c2b-confirmation', async (req, res) => {
    const callbackData = req.body;
    const now = new Date().toISOString();

    console.log('📞 Received C2B Confirmation Callback:', JSON.stringify(callbackData));

    // Extract relevant data from callbackData
    const {
        TransactionType,
        TransID,            // M-Pesa Transaction ID
        TransTime,
        TransAmount,
        BusinessShortCode,
        BillRefNumber,      // This is the Account Number entered by the customer
        InvoiceNumber,
        OrgAccountBalance,
        ThirdPartyTransID,
        MSISDN,             // Customer's phone number
        FirstName,
        MiddleName,
        LastName,
    } = callbackData;

    // Use TransID as the document ID to prevent duplicates and make it easily searchable
    const transactionId = TransID;
    const topupNumber = BillRefNumber; // Assuming BillRefNumber is the number to top up
    const amount = parseFloat(TransAmount);
    const mpesaNumber = MSISDN;
    const customerName = `${FirstName || ''} ${MiddleName || ''} ${LastName || ''}`.trim();

    let finalTxStatus = 'FAILED';
    let airtimeResult = null;
    let errorMessage = null;

    try {
        // First, check if this transaction ID has already been processed to prevent duplicates
        const existingTxDoc = await txCollection.doc(transactionId).get();
        if (existingTxDoc.exists) {
            console.warn(`⚠️ Duplicate C2B confirmation for TransID: ${transactionId}. Skipping processing.`);
            // Acknowledge M-Pesa even if it's a duplicate
            return res.json({ "ResultCode": 0, "ResultDesc": "Duplicate C2B confirmation received and ignored." });
        }

        // Record the initial transaction as PENDING
        await txCollection.doc(transactionId).set({
            transactionID: transactionId,
            date: now,
            amount: amount,
            recipient: topupNumber,
            payer: mpesaNumber,
            source: 'C2B_OFFLINE', // Indicate it's an offline C2B payment
            status: 'PENDING_AIRTIME', // Waiting for airtime dispatch
            mpesaReceiptNumber: transactionId, // For C2B, TransID acts as receipt
            phoneNumberUsedForPayment: mpesaNumber,
            customerName: customerName,
            c2bCallbackData: callbackData, // Store raw callback data for debugging
            lastUpdated: now,
        });

        // Determine carrier and send airtime
        const carrier = detectCarrier(topupNumber);
        if (carrier === 'Unknown') {
            errorMessage = `Unsupported carrier prefix for C2B phone number: ${topupNumber}`;
            console.error(`❌ ${errorMessage}`);
            await errorsCollection.add({
                type: 'C2B_AIRTIME_ERROR',
                subType: 'UNKNOWN_CARRIER',
                error: errorMessage,
                callbackData: callbackData,
                createdAt: now,
            });
            finalTxStatus = 'FAILED_UNKNOWN_CARRIER';
        } else {
            console.log(`📡 Detected Carrier for C2B: ${carrier}`);
            if (carrier === 'Safaricom') {
                airtimeResult = await sendSafaricomAirtime(topupNumber, amount);
            } else { // Airtel, Telkom, Equitel, Faiba via Africa's Talking
                airtimeResult = await sendAfricasTalkingAirtime(topupNumber, amount, carrier);
            }

            if (airtimeResult && airtimeResult.status === 'SUCCESS') {
                finalTxStatus = 'COMPLETED';
                console.log(`✅ Airtime successfully sent for C2B TransID: ${transactionId}`);
            } else {
                errorMessage = airtimeResult ? airtimeResult.error : 'Airtime send failed with no specific error message.';
                console.error(`❌ Airtime send failed for C2B TransID ${transactionId}:`, errorMessage);
                await errorsCollection.add({
                    type: 'C2B_AIRTIME_ERROR',
                    subType: `AIRTIME_API_FAIL_${carrier.toUpperCase()}`,
                    error: errorMessage,
                    transactionCode: transactionId,
                    originalAmount: amount,
                    airtimeResponse: airtimeResult,
                    callbackData: callbackData,
                    createdAt: now,
                });
                finalTxStatus = 'FAILED_AIRTIME_DISPATCH';
            }
        }
    } catch (err) {
        errorMessage = `Processing error for C2B TransID ${transactionId}: ${err.message}`;
        console.error(`❌ ${errorMessage}`, err);
        await errorsCollection.add({
            type: 'C2B_PROCESSING_EXCEPTION',
            error: errorMessage,
            stack: err.stack,
            transactionCode: transactionId,
            callbackData: callbackData,
            createdAt: now,
        });
        finalTxStatus = 'FAILED_SERVER_ERROR';
    } finally {
        // Update the transaction document with the final status and airtime result
        await txCollection.doc(transactionId).update({
            status: finalTxStatus,
            airtimeResult: airtimeResult,
            errorMessage: errorMessage,
            lastUpdated: now,
            // You might want to add float balance updates here, similar to your old script's salesCollection logic
        }).catch(updateErr => {
            console.error(`❌ Failed to update transaction ${transactionId} in Firestore:`, updateErr.message);
            errorsCollection.add({
                type: 'FIRESTORE_UPDATE_ERROR',
                error: `Failed to update transaction ${transactionId} after C2B processing: ${updateErr.message}`,
                transactionCode: transactionId,
                callbackData: callbackData,
                createdAt: new Date().toISOString(),
            });
        });

        // Always respond with a success code to M-Pesa, even if internal processing failed.
        // This tells M-Pesa that your server received the callback.
        res.json({ "ResultCode": 0, "ResultDesc": "C2B confirmation received by DaimaPay server." });
    }
});


// Health check endpoint
app.get('/', (req, res) => {
    res.send('DaimaPay C2B backend is live ✅');
});

// Start the server
app.listen(PORT, () => {
    console.log(`🚀 C2B Server running on port ${PORT}`);
});