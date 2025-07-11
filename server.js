require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const crypto = require('crypto');
const { Firestore } = require('@google-cloud/firestore');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
require('winston-daily-rotate-file');

// --- Global Error Handlers (VERY IMPORTANT FOR PRODUCTION) ---
process.on('uncaughtException', (err) => {
    console.error('UNCAUGHT EXCEPTION! Shutting down...', err.name, err.message, err.stack);
    logger.error('UNCAUGHT EXCEPTION! Shutting down...', { error: err.message, stack: err.stack, name: err.name });
    // Give a short grace period for logs to flush before exiting
    setTimeout(() => process.exit(1), 1000);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('UNHANDLED REJECTION! Shutting down...', reason);
    logger.error('UNHANDLED REJECTION! Shutting down...', { reason: reason, promise: promise });
    // Give a short grace period for logs to flush before exiting
    setTimeout(() => process.exit(1), 1000);
});

// --- Winston Logger Setup ---
const transports = [
    new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        ),
        level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    }),
];

if (process.env.NODE_ENV === 'production') {
    transports.push(
        new winston.transports.DailyRotateFile({
            filename: 'logs/application-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '14d',
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
        }),
        new winston.transports.DailyRotateFile({
            filename: 'logs/error-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '30d',
            level: 'error',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
        })
    );
}

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.splat(),
        winston.format.json()
    ),
    defaultMeta: { service: 'daimapay-c2b-server' },
    transports: transports,
});

// Function to hash sensitive data like MSISDN
function hashString(str) {
    if (!str) return null;
    return crypto.createHash('sha256').update(str).digest('hex');
}

// --- Express App Setup ---
const app = express();
const PORT = process.env.PORT || 3000;

// --- Firestore Initialization ---
const firestore = new Firestore({
    projectId: process.env.GCP_PROJECT_ID,
    keyFilename: process.env.GCP_KEY_FILE,
});

const transactionsCollection = firestore.collection('transactions');
const salesCollection = firestore.collection('sales');
const errorsCollection = firestore.collection('errors');
const safaricomFloatDocRef = firestore.collection('Saf_float').doc('current');
const africasTalkingFloatDocRef = firestore.collection('AT_Float').doc('current');

// --- Africa's Talking Initialization ---
// FIX 1: Import and initialize Africa's Talking
const AfricasTalking = require('africastalking');
const africastalking = AfricasTalking({
    apiKey: process.env.AT_API_KEY,
    username: process.env.AT_USERNAME
});


// --- Middleware ---
app.use(helmet());
app.use(bodyParser.json({ limit: '1mb' }));

const c2bLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 60,
    message: 'Too many requests from this IP for C2B callbacks, please try again later.',
    handler: (req, res, next, options) => {
        logger.warn(`Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
        res.status(options.statusCode).json({
            "ResultCode": 1,
            "ResultDesc": options.message
        });
    }
});
app.use('/c2b-confirmation', c2bLimiter);
app.use('/c2b-validation', c2bLimiter);


let cachedAirtimeToken = null;
let tokenExpiryTimestamp = 0;

//service pin
async function generateServicePin(rawPin) {
  // FIX 4: Use Buffer.from().toString('base64') instead of btoa for Node.js compatibility
  console.log('[generateServicePin] subscriberNumber:', rawPin);
  try {
    const encodedPin = Buffer.from(rawPin).toString('base64');
    console.log('[generateServicePin] encodedPin:', encodedPin);
    return encodedPin;
  } catch (error) {
    console.error('[generateServicePin] error:', error);
    throw new Error(`Service PIN generation failed: ${error.message}`);
  }
}


// Carrier detection helper
function detectCarrier(phoneNumber) {
    const normalized = phoneNumber.replace(/^(\+254|254)/, '0').trim();
    if (normalized.length !== 10 || !normalized.startsWith('0')) {
        logger.debug(`Invalid phone number format for carrier detection: ${phoneNumber}`);
        return 'Unknown';
    }
    const prefix3 = normalized.substring(1, 4);

    const safaricom = new Set([
        '110', '111', '112', '113', '114', '115', '116', '117', '118', '119',
        '700', '701', '702', '703', '704', '705', '706', '707', '708', '709',
        '710', '711', '712', '713', '714', '715', '716', '717', '718', '719',
        '720', '721', '722', '723', '724', '725', '726', '727', '728', '729',
        '740', '741', '742', '743', '744', '745', '746', '748', '749',
        '757', '758', '759',
        '768', '769',
        '790', '791', '792', '793', '794', '795', '796', '797', '798', '799'
    ]);
    const airtel = new Set([
        '100', '101', '102', '103', '104', '105', '106', '107', '108', '109',
        '730', '731', '732', '733', '734', '735', '736', '737', '738', '739',
        '750', '751', '752', '753', '754', '755', '756',
        '780', '781', '782', '783', '784', '785', '786', '787', '788', '789'
    ]);
    const telkom = new Set([
        '770', '771', '772', '773', '774', '775', '776', '777', '778', '779'
    ]);
    const equitel = new Set([
        '764', '765', '766', '767',
    ]);
    const faiba = new Set([
        '747',
    ]);

    if (safaricom.has(prefix3)) return 'Safaricom';
    if (airtel.has(prefix3)) return 'Airtel';
    if (telkom.has(prefix3)) return 'Telkom';
    if (equitel.has(prefix3)) return 'Equitel';
    if (faiba.has(prefix3)) return 'Faiba';
    return 'Unknown';
}

// ✅ Safaricom dealer token
async function getCachedAirtimeToken() {
    const now = Date.now();
    if (cachedAirtimeToken && now < tokenExpiryTimestamp) {
        logger.info('🔑 Using cached dealer token');
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
        tokenExpiryTimestamp = now + 3599 * 1000;
        logger.info('✅ Fetched new dealer token.');
        return token;
    } catch (error) {
        logger.error('❌ Failed to get Safaricom airtime token:', {
            message: error.message,
            response_data: error.response ? error.response.data : 'N/A',
            stack: error.stack
        });
        throw new Error('Failed to obtain Safaricom airtime token.');
    }
}

function normalizeReceiverPhoneNumber(num) {
    let normalized = String(num).replace(/^(\+254|254)/, '0').trim();
    // This function originally aimed for '07XXXXXXXX' but then '7XXXXXXXX' for Safaricom API.
    // The Safaricom API expects the 9-digit format (e.g., 712345678).
    // The Africa's Talking API expects +254XXXXXXXXX.
    // Let's refine this function to normalize for Safaricom's specific needs,
    // and Africa's Talking will handle its own normalization internally if needed.
    if (normalized.startsWith('0') && normalized.length === 10) {
        return normalized.slice(1); // Converts '0712345678' to '712345678'
    }
    // If it's already 9 digits and doesn't start with 0, assume it's good for Safaricom.
    if (normalized.length === 9 && !normalized.startsWith('0')) {
        return normalized;
    }
    logger.warn(`Phone number could not be normalized to 7XXXXXXXX format for Safaricom: ${num}. Returning as is.`);
    return num; // Return as is, let the API potentially fail for incorrect format
}

// ✅ Send Safaricom dealer airtime
async function sendSafaricomAirtime(receiverNumber, amount) {
    try {
        const token = await getCachedAirtimeToken();
        const normalizedReceiver = normalizeReceiverPhoneNumber(receiverNumber);
        const adjustedAmount = Math.round(amount * 100); // Amount in cents

        // Check if environment variables are set before making the call
        if (!process.env.DEALER_SENDER_MSISDN || !process.env.DEALER_SERVICE_PIN || !process.env.MPESA_AIRTIME_URL) {
            const missingEnvError = 'Missing Safaricom Dealer API environment variables (DEALER_SENDER_MSISDN, DEALER_SERVICE_PIN, MPESA_AIRTIME_URL).';
            logger.error(missingEnvError);
            return { status: 'FAILED', message: missingEnvError };
        }
        const servicePin = await generateServicePin(process.env.DEALER_SERVICE_PIN);

        const body = {
            senderMsisdn: process.env.DEALER_SENDER_MSISDN,
            amount: adjustedAmount,
            servicePin: servicePin,
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

        let safaricomInternalTransId = null;
        let newSafaricomFloatBalance = null;

        if (response.data && response.data.responseDesc) {
            const desc = response.data.responseDesc;
            const idMatch = desc.match(/^(R\d{6}\.\d{4}\.\d{6})/); // Regex for the transaction ID
            if (idMatch && idMatch[1]) {
                safaricomInternalTransId = idMatch[1];
            }
            const balanceMatch = desc.match(/New balance is Ksh\. (\d+\.\d{2})/); // Regex for the balance
            if (balanceMatch && balanceMatch[1]) {
                newSafaricomFloatBalance = parseFloat(balanceMatch[1]);
            }
        }
        logger.info('✅ Safaricom dealer airtime API response:', { receiver: normalizedReceiver, amount: amount, response_data: response.data });
        return {
            status: 'SUCCESS',
            message: 'Safaricom airtime sent',
            data: response.data,
            safaricomInternalTransId: safaricomInternalTransId,
            newSafaricomFloatBalance: newSafaricomFloatBalance,
        };
    } catch (error) {
        logger.error('❌ Safaricom dealer airtime send failed:', {
            receiver: receiverNumber,
            amount: amount,
            message: error.message,
            response_data: error.response ? error.response.data : 'N/A',
            stack: error.stack
        });
        return {
            status: 'FAILED',
            message: 'Safaricom airtime send failed',
            error: error.response ? error.response.data : error.message,
        };
    }
}


// Function to send Africa's Talking Airtime
async function sendAfricasTalkingAirtime(phoneNumber, amount, carrier) {
  let normalizedPhone = phoneNumber;

  // AT expects E.164 format (+254XXXXXXXXX)
  if (phoneNumber.startsWith('0')) {
    normalizedPhone = '+254' + phoneNumber.slice(1);
  } else if (phoneNumber.startsWith('254') && !phoneNumber.startsWith('+')) {
    normalizedPhone = '+' + phoneNumber;
  } else if (!phoneNumber.startsWith('+254')) {
    logger.error('[sendAfricasTalkingAirtime] Invalid phone format:', { phoneNumber: phoneNumber });
    return {
      status: 'FAILED',
      message: 'Invalid phone number format for Africa\'s Talking',
      details: {
        error: 'Phone must start with +254, 254, or 0'
      }
    };
  }

  if (!process.env.AT_API_KEY || !process.env.AT_USERNAME) {
    logger.error('Missing Africa\'s Talking API environment variables.');
    return { status: 'FAILED', message: 'Missing Africa\'s Talking credentials.' };
  }

  try {
    const result = await africastalking.AIRTIME.send({
      recipients: [{
        phoneNumber: normalizedPhone,
        amount: amount,
        currencyCode: 'KES'
      }]
    });

    // Defensive check
    const response = result?.responses?.[0];
    const status = response?.status;
    const errorMessage = response?.errorMessage;

    if (status === 'Sent' && errorMessage === 'None') {
      logger.info(`✅ Africa's Talking airtime successfully sent to ${carrier}:`, {
        recipient: normalizedPhone,
        amount: amount,
        at_response: result
      });
      return {
        status: 'SUCCESS',
        message: 'Africa\'s Talking airtime sent',
        data: result,
      };
    } else {
      logger.error(`❌ Africa's Talking airtime send indicates non-success for ${carrier}:`, {
        recipient: normalizedPhone,
        amount: amount,
        at_response: result
      });
      return {
        status: 'FAILED',
        message: 'Africa\'s Talking airtime send failed or not successful.',
        error: result,
      };
    }

  } catch (error) {
    logger.error(`❌ Africa's Talking airtime send failed for ${carrier} (exception caught):`, {
      recipient: normalizedPhone,
      amount: amount,
      message: error.message,
      stack: error.stack
    });
    return {
      status: 'FAILED',
      message: 'Africa\'s Talking airtime send failed (exception)',
      error: error.message,
    };
  }
}

/**
 * Updates the float balance for a specific carrier.
 * @param {string} carrierLogicalName - 'safaricomFloat' or 'africasTalkingFloat'
 * @param {number} amount - The amount to add (positive) or subtract (negative)
 * @returns {Promise<object>} - { success: true, newBalance: number }
 * @throws {Error} if balance goes below zero or doc is invalid
 */
async function updateCarrierFloatBalance(carrierLogicalName, amount) {
    return firestore.runTransaction(async t => {
        let floatDocRef;
        if (carrierLogicalName === 'safaricomFloat') {
            floatDocRef = safaricomFloatDocRef;
        } else if (carrierLogicalName === 'africasTalkingFloat') {
            floatDocRef = africasTalkingFloatDocRef;
        } else {
            const errorMessage = `Invalid float logical name provided: ${carrierLogicalName}`;
            logger.error(`❌ ${errorMessage}`);
            throw new Error(errorMessage);
        }

        const floatDocSnapshot = await t.get(floatDocRef);

        let currentFloat = 0;
        if (floatDocSnapshot.exists) {
            currentFloat = parseFloat(floatDocSnapshot.data().balance); // Assuming 'balance' field as per your frontend
            if (isNaN(currentFloat)) {
                const errorMessage = `Float balance in document '${carrierLogicalName}' is invalid!`;
                logger.error(`❌ ${errorMessage}`);
                throw new Error(errorMessage);
            }
        } else {
            // If the document doesn't exist, create it with initial balance 0
            logger.warn(`Float document '${carrierLogicalName}' not found. Initializing with balance 0.`);
            t.set(floatDocRef, { balance: 0, lastUpdated: new Date() }); // FIX 5: Use native Date object
            currentFloat = 0; // Set currentFloat to 0 for this transaction's calculation
        }

        const newFloat = currentFloat + amount; // amount can be negative for debit
        // Allow negative float if the update is a CREDIT (amount > 0) AND the previous float was negative.
        // This handles cases where we might manually add funds to a float that went negative.
        // For debits (amount < 0), ensure it doesn't go below zero.
        if (amount < 0 && newFloat < 0) {
            const errorMessage = `Attempt to debit ${carrierLogicalName} float below zero. Current: ${currentFloat}, Attempted debit: ${-amount}`;
            logger.warn(`⚠️ ${errorMessage}`);
            throw new Error('Insufficient carrier-specific float balance for this transaction.');
        }

        t.update(floatDocRef, { balance: newFloat, lastUpdated: new Date() }); // FIX 5: Use native Date object
        logger.info(`✅ Updated ${carrierLogicalName} float balance. Old: ${currentFloat}, New: ${newFloat}, Change: ${amount}`);
        return { success: true, newBalance: newFloat };
    });
}


// --- C2B (Offline Paybill) Callbacks ---

// C2B Validation Endpoint (Optional but Recommended)
app.post('/c2b-validation', async (req, res) => {
    const callbackData = req.body;
    const now = new Date();
    const transactionIdentifier = callbackData.TransID || `C2B_VALIDATION_${Date.now()}`;

    logger.info('📞 Received C2B Validation Callback:', { TransID: transactionIdentifier, callback: callbackData });

    const { TransAmount } = callbackData;
    const amount = parseFloat(TransAmount);
    const MIN_AMOUNT = 5.00; // Minimum amount for airtime purchase

    // --- Validation Check: Amount KES 10 and above ---
    if (isNaN(amount) || amount < MIN_AMOUNT) {
        logger.warn(`⚠️ C2B Validation rejected [TransID: ${transactionIdentifier}]: Invalid amount (${TransAmount}). Must be KES ${MIN_AMOUNT} or more.`);
        await errorsCollection.add({
            type: 'C2B_VALIDATION_REJECT',
            subType: 'INVALID_AMOUNT_TOO_LOW',
            error: `Transaction amount must be KES ${MIN_AMOUNT} or more: ${TransAmount}`,
            callbackData: callbackData,
            createdAt: now,
        });
        return res.json({
            "ResultCode": 1, // Reject
            "ResultDesc": `Transaction amount must be KES ${MIN_AMOUNT} or more.`
        });
    }

    // If only amount validation is needed and passed
    logger.info('✅ C2B Validation successful (amount check only):', { TransID: transactionIdentifier, Amount: TransAmount });
    res.json({
        "ResultCode": 0, // Accept
        "ResultDesc": "Validation successful."
    });
});

// C2B Confirmation Endpoint (Mandatory)
app.post('/c2b-confirmation', async (req, res) => {
    const callbackData = req.body;
    const now = new Date();
    const transactionId = callbackData.TransID;

    logger.info('📞 Received C2B Confirmation Callback:', { TransID: transactionId, callback: callbackData });

    const {
        TransTime,
        TransAmount,
        BillRefNumber,
        MSISDN,
        FirstName,
        MiddleName,
        LastName,
    } = callbackData;

    const topupNumber = BillRefNumber;
    const amount = parseFloat(TransAmount);
    const mpesaNumber = MSISDN;
    const customerName = `${FirstName || ''} ${MiddleName || ''} ${LastName || ''}`.trim();

    let saleId = null;
    let floatDebitedSuccessfully = false; // Track if the *specific carrier's* float was debited
    let carrierSpecificFloatLogicalName = null; // To store the logical name of the float that was debited

    try {
        // --- 1. Record the incoming M-Pesa transaction (money received) ---
        const existingTxDoc = await transactionsCollection.doc(transactionId).get();
        if (existingTxDoc.exists) {
            logger.warn(`⚠️ Duplicate C2B confirmation for TransID: ${transactionId}. Skipping processing.`);
            return res.json({ "ResultCode": 0, "ResultDesc": "Duplicate C2B confirmation received and ignored." });
        }

        await transactionsCollection.doc(transactionId).set({
            transactionID: transactionId,
            transactionTime: TransTime,
            amountReceived: amount,
            payerMsisdn: mpesaNumber,
            payerName: customerName,
            billRefNumber: topupNumber,
            mpesaRawCallback: callbackData,
            status: 'RECEIVED_PENDING_SALE',
            createdAt: now,
            lastUpdated: now,
        });
        logger.info(`✅ Recorded incoming transaction ${transactionId} in 'transactions' collection.`);

        // --- 2. Determine target carrier and its float logical name ---
        const targetCarrier = detectCarrier(topupNumber);
        if (targetCarrier === 'Unknown') {
            const errorMessage = `Unsupported carrier prefix for airtime top-up: ${topupNumber}`;
            logger.error(`❌ ${errorMessage}`, { TransID: transactionId, topupNumber: topupNumber, callback: callbackData });
            await errorsCollection.add({
                type: 'AIRTIME_SALE_ERROR',
                subType: 'UNKNOWN_CARRIER',
                error: errorMessage,
                transactionId: transactionId,
                callbackData: callbackData,
                createdAt: now,
            });
            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FULFILLMENT_FAILED',
                fulfillmentStatus: 'FAILED_UNKNOWN_CARRIER',
                errorMessage: errorMessage,
                lastUpdated: now,
            });
            return res.json({ "ResultCode": 0, "ResultDesc": "C2B confirmation received, but airtime not dispatched due to unsupported carrier." });
        }

        // Map carrier to its specific float logical name
        switch (targetCarrier) {
            case 'Safaricom':
                carrierSpecificFloatLogicalName = 'safaricomFloat'; // This maps to safaricomFloatDocRef
                break;
            case 'Airtel':
            case 'Telkom':
            case 'Equitel':
            case 'Faiba':
                carrierSpecificFloatLogicalName = 'africasTalkingFloat'; // This maps to africasTalkingFloatDocRef
                break;
            default:
                // This case should be caught by the earlier detectCarrier check, but good for robustness
                const unmappedError = `No float document mapped for detected carrier: ${targetCarrier}`;
                logger.error(`❌ ${unmappedError}`, { TransID: transactionId, topupNumber: topupNumber });
                await errorsCollection.add({
                    type: 'AIRTIME_SALE_ERROR',
                    subType: 'NO_FLOAT_MAPPING',
                    error: unmappedError,
                    transactionId: transactionId,
                    callbackData: callbackData,
                    createdAt: now,
                });
                await transactionsCollection.doc(transactionId).update({
                    status: 'RECEIVED_FULFILLMENT_FAILED',
                    fulfillmentStatus: 'FAILED_NO_FLOAT_MAPPING',
                    errorMessage: unmappedError,
                    lastUpdated: now,
                });
                return res.json({ "ResultCode": 0, "ResultDesc": "C2B confirmation received, but airtime not dispatched due to internal mapping error." });
        }

        // --- 3. Debit Carrier-Specific Float Balance & Record Airtime Sale attempt ---
        let floatUpdateResult;
        try {
            floatUpdateResult = await updateCarrierFloatBalance(carrierSpecificFloatLogicalName, -amount); // Debit
            floatDebitedSuccessfully = true;
        } catch (error) {
            floatUpdateResult = { success: false, reason: 'FLOAT_DEBIT_FAILED', message: error.message };
            logger.error(`❌ Failed to debit carrier-specific float for TransID ${transactionId} (${carrierSpecificFloatLogicalName}): ${error.message}`);
        }

        if (!floatUpdateResult.success) {
            const errorMessage = floatUpdateResult.message || `Carrier float debit failed for TransID ${transactionId}. Reason: ${floatUpdateResult.reason}`;
            await errorsCollection.add({
                type: 'AIRTIME_SALE_ERROR',
                subType: floatUpdateResult.reason,
                error: errorMessage,
                transactionId: transactionId,
                callbackData: callbackData,
                createdAt: now,
            });

            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FLOAT_ISSUE',
                fulfillmentStatus: 'FAILED_INSUFFICIENT_FLOAT',
                errorMessage: errorMessage,
                lastUpdated: now,
            });
            // Importantly, return "ResultCode": 0 here, because you've received the money.
            // The user will not get their airtime, but M-Pesa is done with its part.
            return res.json({ "ResultCode": 0, "ResultDesc": "C2B confirmation received, but airtime not dispatched due to insufficient float." });
        }

        // If float was successfully debited, proceed with recording the sale and dispatching airtime
        const saleRef = salesCollection.doc();
        saleId = saleRef.id;

        let airtimeDispatchStatus = 'FAILED';
        let airtimeDispatchResult = null;
        let saleErrorMessage = null;

        await saleRef.set({
            saleId: saleId,
            relatedTransactionId: transactionId,
            topupNumber: topupNumber,
            amount: amount,
            carrier: targetCarrier, // Use the detected carrier
            status: 'PENDING_DISPATCH',
            dispatchAttemptedAt: now,
            createdAt: now,
            lastUpdated: now,
        });
        logger.info(`✅ Initialized sale document ${saleId} in 'sales' collection for TransID ${transactionId}.`);

        // --- 4. Attempt to dispatch airtime ---
        if (targetCarrier === 'Safaricom') {
            airtimeDispatchResult = await sendSafaricomAirtime(topupNumber, amount);
        } else { // Airtel, Telkom, Equitel, Faiba via Africa's Talking
            airtimeDispatchResult = await sendAfricasTalkingAirtime(topupNumber, amount, targetCarrier);
        }

        const updateSaleFields = {
            lastUpdated: new Date(), // Use native Date object for Timestamp
            dispatchResult: airtimeDispatchResult.data || airtimeDispatchResult.error || airtimeDispatchResult, // Store raw API response/error
        };

        if (airtimeDispatchResult && airtimeDispatchResult.status === 'SUCCESS') {
            airtimeDispatchStatus = 'COMPLETED';
            logger.info(`✅ Airtime successfully sent for sale ${saleId} (TransID ${transactionId}).`, { airtimeResponse: airtimeDispatchResult.data });
            updateSaleFields.status = airtimeDispatchStatus;

            // Safaricom Specific Reconciliation: Only attempt if it was a Safaricom transaction
            // FIX 2: Move Safaricom float update inside the Safaricom branch
            if (targetCarrier === 'Safaricom' && airtimeDispatchResult.newSafaricomFloatBalance !== null) {
                try {
                    //directly update safaricom float with balance report
                    await safaricomFloatDocRef.update({
                        balance: airtimeDispatchResult.newSafaricomFloatBalance,
                        lastUpdated: new Date()
                    });
                    logger.info(`✅ Safaricom float balance directly updated from API response for TransID ${transactionId}. New balance: ${airtimeDispatchResult.newSafaricomFloatBalance}`);
                } catch (floatUpdateErr) {
                    logger.error(`❌ Failed to directly update Safaricom float from API response for TransID ${transactionId}:`, {
                        error: floatUpdateErr.message, reportedBalance: airtimeDispatchResult.newSafaricomFloatBalance
                    });
                    // FIX 3: Ensure `reportedBalance` is not undefined when adding to errors collection
                    const reportedBalanceForError = airtimeDispatchResult.newSafaricomFloatBalance !== null ? airtimeDispatchResult.newSafaricomFloatBalance : 'N/A';
                    await errorsCollection.add({
                        type: 'FLOAT_RECONCILIATION_WARNING',
                        subType: 'SAFARICOM_REPORTED_BALANCE_UPDATE_FAILED',
                        error: `Failed to update Safaricom float with reported balance: ${floatUpdateErr.message}`,
                        transactionId: transactionId,
                        saleId: saleId,
                        reportedBalance: reportedBalanceForError, // Pass a non-undefined value
                        createdAt: new Date(),
                    });
                }
            }
        } else {
            saleErrorMessage = airtimeDispatchResult ? airtimeDispatchResult.error : 'Airtime dispatch failed with no specific error message.';
            logger.error(`❌ Airtime dispatch failed for sale ${saleId} (TransID ${transactionId}):`, {
                error_message: saleErrorMessage,
                carrier: targetCarrier,
                topupNumber: topupNumber,
                amount: amount,
                airtimeResponse: airtimeDispatchResult,
                callbackData: callbackData,
            });
            await errorsCollection.add({
                type: 'AIRTIME_SALE_ERROR',
                subType: `AIRTIME_API_FAIL_${targetCarrier.toUpperCase()}`,
                error: saleErrorMessage,
                transactionId: transactionId,
                saleId: saleId,
                originalAmount: amount,
                airtimeResponse: airtimeDispatchResult,
                callbackData: callbackData,
                createdAt: now,
            });
            airtimeDispatchStatus = 'FAILED_DISPATCH_API';

            // REVERSAL LOGIC: If airtime dispatch failed *after* carrier-specific float was debited,
            // we need to reverse the float or flag for manual review.
            logger.warn(`⚠️ Airtime dispatch failed after float debit. Attempting to reverse float for TransID ${transactionId}, Sale ${saleId}.`);
            try {
                // Re-credit the specific carrier's float
                await updateCarrierFloatBalance(carrierSpecificFloatLogicalName, amount); // Credit back
                logger.info(`✅ Successfully reversed float debit for TransID ${transactionId}, Sale ${saleId}.`);
            } catch (reverseError) {
                logger.error(`❌ CRITICAL: Failed to reverse float debit for TransID ${transactionId}, Sale ${saleId}:`, {
                    error: reverseError.message,
                    stack: reverseError.stack
                });
                await errorsCollection.add({
                    type: 'FLOAT_RECONCILIATION_WARNING',
                    subType: 'FLOAT_REVERSAL_FAILED',
                    error: `Float debited but dispatch failed, and reversal failed for TransID ${transactionId}. Manual reconciliation REQUIRED.`,
                    transactionId: transactionId,
                    saleId: saleId,
                    amount: amount,
                    createdAt: now,
                });
            }
        }

        // --- 5. Update the Airtime Sale document with final status ---
        await saleRef.update({
            status: airtimeDispatchStatus,
            dispatchResult: airtimeDispatchResult.data || airtimeDispatchResult.error || airtimeDispatchResult, // Ensure data is not undefined
            errorMessage: saleErrorMessage,
            lastUpdated: new Date(), // Use native Date object
        });
        logger.info(`✅ Updated sale ${saleId} to status: ${airtimeDispatchStatus}.`);

        // --- 6. Update the 'transactions' document with fulfillment status ---
        await transactionsCollection.doc(transactionId).update({
            linkedSaleId: saleId,
            fulfillmentStatus: airtimeDispatchStatus,
            status: airtimeDispatchStatus === 'COMPLETED' ? 'RECEIVED_FULFILLED' : 'RECEIVED_FULFILLMENT_FAILED',
            lastUpdated: new Date(), // Use native Date object
        });
        logger.info(`✅ Updated transaction ${transactionId} with linked sale ID ${saleId} and fulfillment status.`);


    } catch (err) {
        // FIX 6: Complete the `catch` block for general exceptions
        const generalErrorMessage = `Critical processing exception for C2B TransID ${transactionId}: ${err.message}`;
        logger.error(`❌ ${generalErrorMessage}`, {
            error: err.message,
            stack: err.stack,
            TransID: transactionId,
            callbackData: callbackData
        });
        await errorsCollection.add({
            type: 'C2B_PROCESSING_EXCEPTION',
            error: generalErrorMessage,
            stack: err.stack,
            transactionCode: transactionId,
            callbackData: callbackData,
            createdAt: now,
            // FIX 3: Ensure 'reportedBalance' (if present) is not undefined here
            // It's not applicable for general exceptions, so remove if not relevant,
            // or ensure it's conditionally added with a valid value.
            // For now, it's safer to remove it if it's not always available.
        });

        // Attempt to update the transaction document with a failure status if it was initially created
        try {
            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_PROCESSING_ERROR',
                fulfillmentStatus: 'FAILED_SERVER_ERROR',
                errorMessage: generalErrorMessage,
                lastUpdated: new Date(), // Use native Date object
            });
        } catch (updateErr) {
            logger.error(`❌ Failed to update transaction ${transactionId} with processing error:`, { error: updateErr.message, stack: updateErr.stack });
        }
        // Also try to update the sale document if it was created (and float was debited)
        if (saleId) {
            try {
                await salesCollection.doc(saleId).update({
                    status: 'FAILED_SERVER_ERROR',
                    errorMessage: generalErrorMessage,
                    lastUpdated: new Date(), // Use native Date object
                });
            } catch (updateErr) {
                logger.error(`❌ Failed to update sale ${saleId} with processing error:`, { error: updateErr.message, stack: updateErr.stack });
            }
        }

        // CRITICAL: If float was debited but airtime dispatch failed due to an *exception* (not an API failure handled earlier)
        // this is a potential data inconsistency. Flag for manual review if reversal hasn't happened.
        if (floatDebitedSuccessfully) { // If we got to the point of debiting float
             logger.error(`❌ CRITICAL RECONCILIATION NEEDED: Float was debited for TransID ${transactionId} but an unhandled exception occurred and airtime dispatch status is unknown or failed. Manual review required!`);
             await errorsCollection.add({
                 type: 'FLOAT_RECONCILIATION_CRITICAL',
                 subType: 'UNHANDLED_EXCEPTION_AFTER_FLOAT_DEBIT',
                 error: `Float debited but an unhandled exception occurred during fulfillment for TransID ${transactionId}. Manual reconciliation REQUIRED.`,
                 transactionId: transactionId,
                 saleId: saleId, // May be null if sale document wasn't created
                 amount: amount,
                 carrier: targetCarrier, // May be null/undefined if not determined
                 createdAt: now,
                 originalException: err.message,
                 originalExceptionStack: err.stack
             });
        }

    } finally {
        // Ensure a response is always sent to M-Pesa
        res.json({ "ResultCode": 0, "ResultDesc": "C2B confirmation received, processing initiated (check logs for outcome)." });
    }
});


// Start the server
app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
});
