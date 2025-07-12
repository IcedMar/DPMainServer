require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const crypto = require('crypto');
const { Firestore, FieldValue, AggregateField } = require('@google-cloud/firestore'); // Import FieldValue and AggregateField
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

// NEW: Firestore reference for dealer config (updated path)
const safaricomDealerConfigRef = firestore.collection('mpesa_settings').doc('main_config');

// --- Africa's Talking Initialization ---
const AfricasTalking = require('africastalking');
const africastalking = AfricasTalking({
    apiKey: process.env.AT_API_KEY,
    username: process.env.AT_USERNAME
});

// --- Middleware ---
app.use(helmet());
app.use(bodyParser.json({ limit: '1mb' }));
app.use(cors()); // Enable CORS for all routes

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

// NEW: Cache variables for Dealer Service PIN
let cachedDealerServicePin = null;
let dealerPinExpiryTimestamp = 0;
const DEALER_PIN_CACHE_TTL = 10 * 60 * 1000; // Cache for 10 minutes (600,000 milliseconds)

//service pin
async function generateServicePin(rawPin) {
    logger.debug('[generateServicePin] rawPin length:', rawPin ? rawPin.length : 'null');
    try {
        const encodedPin = Buffer.from(rawPin).toString('base64'); // Correct for Node.js
        logger.debug('[generateServicePin] encodedPin length:', encodedPin.length);
        return encodedPin;
    } catch (error) {
        logger.error('[generateServicePin] error:', error);
        throw new Error(`Service PIN generation failed: ${error.message}`);
    }
}

// NEW: Function to get dealer service PIN from Firestore with caching
async function getDealerServicePin() {
    const now = Date.now();
    if (cachedDealerServicePin && now < dealerPinExpiryTimestamp) {
        logger.info('🔑 Using cached dealer service PIN from memory.');
        return cachedDealerServicePin;
    }

    logger.info('🔄 Fetching dealer service PIN from Firestore (mpesa_settings/main_config/servicePin)...');
    try {
        const doc = await safaricomDealerConfigRef.get(); // This now points to mpesa_settings/main_config

        if (!doc.exists) {
            const errorMsg = 'Dealer service PIN configuration document (mpesa_settings/main_config) not found in Firestore. Please create it with a "servicePin" field.';
            logger.error(`❌ ${errorMsg}`);
            throw new Error(errorMsg);
        }

        const pin = doc.data().servicePin; // THIS IS THE KEY CHANGE for the field name

        if (!pin) {
            const errorMsg = 'Dealer service PIN field ("servicePin") not found in Firestore document (mpesa_settings/main_config). Please add it.';
            logger.error(`❌ ${errorMsg}`);
            throw new Error(errorMsg);
        }

        // Cache the retrieved PIN and set expiry
        cachedDealerServicePin = pin;
        dealerPinExpiryTimestamp = now + DEALER_PIN_CACHE_TTL;
        logger.info('✅ Successfully fetched and cached dealer service PIN from Firestore.');
        return pin;

    } catch (error) {
        logger.error('❌ Failed to retrieve dealer service PIN from Firestore:', {
            message: error.message,
            stack: error.stack
        });
        throw new Error(`Failed to retrieve dealer service PIN: ${error.message}`);
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
    if (normalized.startsWith('0') && normalized.length === 10) {
        return normalized.slice(1); // Converts '0712345678' to '712345678'
    }
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

        if (!process.env.DEALER_SENDER_MSISDN || !process.env.MPESA_AIRTIME_URL) {
            const missingEnvError = 'Missing Safaricom Dealer API environment variables (DEALER_SENDER_MSISDN, MPESA_AIRTIME_URL). DEALER_SERVICE_PIN is now fetched from Firestore.';
            logger.error(missingEnvError);
            return { status: 'FAILED', message: missingEnvError };
        }

        const rawDealerPin = await getDealerServicePin(); // This will fetch from cache or Firestore
        const servicePin = await generateServicePin(rawDealerPin); // Then encode it

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
            t.set(floatDocRef, { balance: 0, lastUpdated: FieldValue.serverTimestamp() }); // Use FieldValue.serverTimestamp()
            currentFloat = 0; // Set currentFloat to 0 for this transaction's calculation
        }

        const newFloat = currentFloat + amount; // amount can be negative for debit
        if (amount < 0 && newFloat < 0) {
            const errorMessage = `Attempt to debit ${carrierLogicalName} float below zero. Current: ${currentFloat}, Attempted debit: ${-amount}`;
            logger.warn(`⚠️ ${errorMessage}`);
            throw new Error('Insufficient carrier-specific float balance for this transaction.');
        }

        t.update(floatDocRef, { balance: newFloat, lastUpdated: FieldValue.serverTimestamp() }); // Use FieldValue.serverTimestamp()
        logger.info(`✅ Updated ${carrierLogicalName} float balance. Old: ${currentFloat}, New: ${newFloat}, Change: ${amount}`);
        return { success: true, newBalance: newFloat };
    });
}


// --- C2B (Offline Paybill) Callbacks ---

// C2B Validation Endpoint
app.post('/c2b-validation', async (req, res) => {
    const callbackData = req.body;
    const now = new Date();
    const transactionIdentifier = callbackData.TransID || `C2B_VALIDATION_${Date.now()}`;

    logger.info('📞 Received C2B Validation Callback:', { TransID: transactionIdentifier, callback: callbackData });

    const { TransAmount } = callbackData;
    const amount = parseFloat(TransAmount);
    const MIN_AMOUNT = 5.00;

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
            "ResultCode": 1, // Changed from C2B00013 to 1 as per M-Pesa API spec for rejection
            "ResultDesc": `Invalid Amount`
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

    const topupNumber = BillRefNumber.replace(/\D/g, '');
    const amount = parseFloat(TransAmount); // This is the original amount paid by customer
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
            amountReceived: amount, // Original amount paid by customer
            payerMsisdn: mpesaNumber,
            payerName: customerName,
            billRefNumber: topupNumber,
            mpesaRawCallback: callbackData,
            status: 'RECEIVED_PENDING_SALE',
            createdAt: FieldValue.serverTimestamp(), // Use server timestamp
            lastUpdated: FieldValue.serverTimestamp(), // Use server timestamp
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
                createdAt: FieldValue.serverTimestamp(),
            });
            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FULFILLMENT_FAILED',
                fulfillmentStatus: 'FAILED_UNKNOWN_CARRIER',
                errorMessage: errorMessage,
                lastUpdated: FieldValue.serverTimestamp(),
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
            case 'AirtelMoney': // Ensure you map all your AT supported carriers here
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
                    createdAt: FieldValue.serverTimestamp(),
                });
                await transactionsCollection.doc(transactionId).update({
                    status: 'RECEIVED_FULFILLMENT_FAILED',
                    fulfillmentStatus: 'FAILED_NO_FLOAT_MAPPING',
                    errorMessage: unmappedError,
                    lastUpdated: FieldValue.serverTimestamp(),
                });
                return res.json({ "ResultCode": 0, "ResultDesc": "C2B confirmation received, but airtime not dispatched due to internal mapping error." });
        }

        // --- 3. Debit Carrier-Specific Float Balance & Record Airtime Sale attempt ---
        // The float is debited by the ORIGINAL amount received from the customer.
        // The bonus amount is "extra" and comes from the float, but the customer only paid the original.
        let floatUpdateResult;
        try {
            floatUpdateResult = await updateCarrierFloatBalance(carrierSpecificFloatLogicalName, -amount); // Debit original amount
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
                createdAt: FieldValue.serverTimestamp(),
            });

            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FLOAT_ISSUE',
                fulfillmentStatus: 'FAILED_INSUFFICIENT_FLOAT',
                errorMessage: errorMessage,
                lastUpdated: FieldValue.serverTimestamp(),
            });
            return res.json({ "ResultCode": 0, "ResultDesc": "C2B confirmation received, but airtime not dispatched due to insufficient float." });
        }

        // If float was successfully debited, proceed with recording the sale and dispatching airtime
        const saleRef = salesCollection.doc();
        saleId = saleRef.id;

        let airtimeDispatchStatus = 'FAILED';
        let airtimeDispatchResult = null;
        let saleErrorMessage = null;
        let airtimeProviderUsed = null; // To track which provider successfully sent or was attempted

        // --- FETCH BONUS SETTINGS AND CALCULATE FINAL AMOUNT TO DISPATCH ---
        const bonusDocRef = firestore.collection('airtime_bonuses').doc('current_settings');
        const bonusDocSnap = await bonusDocRef.get();
        const bonusSettings = bonusDocSnap.exists ? bonusDocSnap.data() : { safaricomPercentage: 0, africastalkingPercentage: 0 };

        let finalAmountToDispatch = amount; // Start with original amount
        let bonusApplied = 0;

        if (targetCarrier === 'Safaricom') {
            if (bonusSettings.safaricomPercentage > 0) {
                bonusApplied = amount * (bonusSettings.safaricomPercentage / 100);
                finalAmountToDispatch = amount + bonusApplied;
                logger.info(`Applying ${bonusSettings.safaricomPercentage}% Safaricom bonus. Original: ${amount}, Bonus: ${bonusApplied}, Final: ${finalAmountToDispatch}`);
            }
        } else { // Airtel, Telkom, Equitel, Faiba via Africa's Talking
            if (bonusSettings.africastalkingPercentage > 0) {
                bonusApplied = amount * (bonusSettings.africastalkingPercentage / 100);
                finalAmountToDispatch = amount + bonusApplied;
                logger.info(`Applying ${bonusSettings.africastalkingPercentage}% AfricasTalking bonus. Original: ${amount}, Bonus: ${bonusApplied}, Final: ${finalAmountToDispatch}`);
            }
        }
        // Round to 2 decimal places for financial accuracy
        finalAmountToDispatch = parseFloat(finalAmountToDispatch.toFixed(2));
        bonusApplied = parseFloat(bonusApplied.toFixed(2));


        await saleRef.set({
            saleId: saleId,
            relatedTransactionId: transactionId,
            topupNumber: topupNumber,
            originalAmountPaid: amount, // Store the original amount paid by customer
            amount: finalAmountToDispatch, // This is the amount actually dispatched (original + bonus)
            bonusApplied: bonusApplied, // Store the bonus amount
            carrier: targetCarrier, // Use the detected carrier
            status: 'PENDING_DISPATCH',
            dispatchAttemptedAt: FieldValue.serverTimestamp(), // Use server timestamp
            createdAt: FieldValue.serverTimestamp(), // Use server timestamp
            lastUpdated: FieldValue.serverTimestamp(), // Use server timestamp
        });
        logger.info(`✅ Initialized sale document ${saleId} in 'sales' collection for TransID ${transactionId} with bonus details.`);

        // --- Safaricom Primary Attempt ---
        logger.info(`Attempting Safaricom airtime via Primary (Dealer Portal) for TransID: ${transactionId}`);
        airtimeProviderUsed = 'SafaricomDealer';
        airtimeDispatchResult = await sendSafaricomAirtime(topupNumber, finalAmountToDispatch);

        if (airtimeDispatchResult && airtimeDispatchResult.status === 'SUCCESS') {
            airtimeDispatchStatus = 'COMPLETED';
            logger.info(`✅ Safaricom airtime successfully sent via Dealer Portal for sale ${saleId}.`);
        } else {
        logger.warn(`⚠️ Safaricom Dealer Portal failed for TransID ${transactionId}. Attempting fallback to Africastalking. Error: ${airtimeDispatchResult?.error || 'Unknown error'}`);

        // === NEW: Refund Safaricom float ===
        try {
            await updateCarrierFloatBalance('safaricomFloat', amount); // Refund the Safaricom float
            logger.info(`✅ Refunded Safaricom float for TransID ${transactionId}: +${amount}`);
        } catch (refundError) {
        logger.error(`❌ Failed to refund Safaricom float for TransID ${transactionId}: ${refundError.message}`);
        await errorsCollection.add({
            type: 'FLOAT_REFUND_ERROR',
            subType: 'SAFARICOM_FALLBACK_REFUND_FAILED',
            error: refundError.message,
            transactionId: transactionId,
            createdAt: FieldValue.serverTimestamp(),
        });
    }

    // === NEW: Debit Africastalking float ===
    let fallbackFloatDebitResult = { success: false };
    try {
        fallbackFloatDebitResult = await updateCarrierFloatBalance('africasTalkingFloat', -amount); // Debit Africastalking float
        logger.info(`✅ Debited Africastalking float for fallback: -${amount} (TransID ${transactionId})`);
    } catch (fallbackDebitError) {
    logger.error(`❌ Failed to debit Africastalking float for fallback (TransID ${transactionId}): ${fallbackDebitError.message}`);
    saleErrorMessage = `Fallback float debit failed: ${fallbackDebitError.message}`;
    await errorsCollection.add({
      type: 'FLOAT_DEBIT_ERROR',
      subType: 'AFRICASTALKING_FALLBACK_DEBIT_FAILED',
      error: fallbackDebitError.message,
      transactionId: transactionId,
      createdAt: FieldValue.serverTimestamp(),
    });
  }

  if (!fallbackFloatDebitResult.success) {
    airtimeDispatchStatus = 'FAILED';
    saleErrorMessage = saleErrorMessage || `Fallback float debit failed unexpectedly for TransID ${transactionId}.`;
  } else {
    // === NEW: Attempt fallback dispatch ===
    airtimeProviderUsed = 'AfricasTalkingFallback';
    airtimeDispatchResult = await sendAfricasTalkingAirtime(topupNumber, finalAmountToDispatch, targetCarrier);

    if (airtimeDispatchResult && airtimeDispatchResult.status === 'SUCCESS') {
      airtimeDispatchStatus = 'COMPLETED';
      logger.info(`✅ Safaricom fallback airtime successfully sent via Africastalking for sale ${saleId}.`);
    } else {
      saleErrorMessage = airtimeDispatchResult ? airtimeDispatchResult.error : 'Africastalking fallback failed with no specific error.';
      logger.error(`❌ Safaricom fallback via Africastalking failed for sale ${saleId}: ${saleErrorMessage}`);
    }
  }
}


        const updateSaleFields = {
            lastUpdated: FieldValue.serverTimestamp(), // Use server timestamp
            dispatchResult: airtimeDispatchResult.data || airtimeDispatchResult.error || airtimeDispatchResult, // Store raw API response/error
            airtimeProviderUsed: airtimeProviderUsed, // New field to track provider used
        };

        if (airtimeDispatchStatus === 'COMPLETED') { // Check the consolidated status
            updateSaleFields.status = airtimeDispatchStatus;

            // Safaricom Specific Reconciliation: Only attempt if Safaricom was the target carrier
            // and the primary Safaricom Dealer Portal was used and reported a new balance.
            // If AT was used as fallback, this part won't apply.
            if (targetCarrier === 'Safaricom' && airtimeDispatchResult.newSafaricomFloatBalance !== null && airtimeProviderUsed === 'SafaricomDealer') {
                try {
                    await safaricomFloatDocRef.update({
                        balance: airtimeDispatchResult.newSafaricomFloatBalance,
                        lastUpdated: FieldValue.serverTimestamp()
                    });
                    logger.info(`✅ Safaricom float balance directly updated from API response for TransID ${transactionId}. New balance: ${airtimeDispatchResult.newSafaricomFloatBalance}`);
                } catch (floatUpdateErr) {
                    logger.error(`❌ Failed to directly update Safaricom float from API response for TransID ${transactionId}:`, {
                        error: floatUpdateErr.message, reportedBalance: airtimeDispatchResult.newSafaricomFloatBalance
                    });
                    const reportedBalanceForError = airtimeDispatchResult.newSafaricomFloatBalance !== null ? airtimeDispatchResult.newSafaricomFloatBalance : 'N/A';
                    await errorsCollection.add({
                        type: 'FLOAT_RECONCILIATION_WARNING',
                        subType: 'SAFARICOM_REPORTED_BALANCE_UPDATE_FAILED',
                        error: `Failed to update Safaricom float with reported balance: ${floatUpdateErr.message}`,
                        transactionId: transactionId,
                        saleId: saleId,
                        reportedBalance: reportedBalanceForError,
                        createdAt: FieldValue.serverTimestamp(),
                    });
                }
            }
            // For Africas Talking (both primary for Airtel/Telkom and fallback for Safaricom),
            // your `updateCarrierFloatBalance` already debits the float based on the sale.
            // No need for a separate `africasTalkingFloatDocRef.update` here unless AT provides a balance in its API response
            // that you specifically want to use for reconciliation, similar to Safaricom's.
            // Currently, your `sendAfricasTalkingAirtime` doesn't extract a `newAfricasTalkingFloatBalance`.

        } else {
            // Airtime dispatch ultimately failed (either primary or fallback)
            saleErrorMessage = saleErrorMessage || 'Airtime dispatch failed with no specific error message.'; // Ensure it's not null
            logger.error(`❌ Airtime dispatch failed for sale ${saleId} (TransID ${transactionId}):`, {
                error_message: saleErrorMessage,
                carrier: targetCarrier,
                topupNumber: topupNumber,
                originalAmountPaid: amount,
                finalAmountDispatched: finalAmountToDispatch,
                airtimeResponse: airtimeDispatchResult,
                callbackData: callbackData,
            });
            await errorsCollection.add({
                type: 'AIRTIME_SALE_ERROR',
                subType: 'AIRTIME_DISPATCH_FAILED', // This subType remains generic for ultimate failure
                error: saleErrorMessage,
                transactionId: transactionId,
                saleId: saleId,
                callbackData: callbackData,
                airtimeApiResponse: airtimeDispatchResult,
                providerAttempted: airtimeProviderUsed, // Log which provider was ultimately responsible for failure
                createdAt: FieldValue.serverTimestamp(),
            });
            updateSaleFields.status = 'FAILED_DISPATCH_API';
            updateSaleFields.errorMessage = saleErrorMessage;
        }

        await saleRef.update(updateSaleFields);
        logger.info(`✅ Updated sale document ${saleId} with dispatch result.`);

        // --- 5. Update main transaction status based on airtime dispatch ---
        await transactionsCollection.doc(transactionId).update({
            status: airtimeDispatchStatus === 'COMPLETED' ? 'COMPLETED_AND_FULFILLED' : 'RECEIVED_FULFILLMENT_FAILED',
            fulfillmentStatus: airtimeDispatchStatus,
            fulfillmentDetails: airtimeDispatchResult,
            lastUpdated: FieldValue.serverTimestamp(),
            airtimeProviderUsed: airtimeProviderUsed, // Update transaction with provider used
        });

        logger.info(`Final status for TransID ${transactionId}: ${airtimeDispatchStatus}`);
        res.json({ "ResultCode": 0, "ResultDesc": "C2B Confirmation and Airtime Dispatch Processed." });

    } catch (error) {
        logger.error(`❌ CRITICAL ERROR in C2B Confirmation for TransID ${transactionId}:`, {
            message: error.message,
            stack: error.stack,
            callbackData: callbackData,
            floatDebitedSuccessfully: floatDebitedSuccessfully, // Important for debugging
            carrierSpecificFloatLogicalName: carrierSpecificFloatLogicalName, // Important for debugging
        });

        // Attempt to update the transaction status to reflect the critical error
        if (transactionId) {
            try {
                await transactionsCollection.doc(transactionId).update({
                    status: 'CRITICAL_PROCESSING_ERROR',
                    errorMessage: `Critical server error during C2B processing: ${error.message}`,
                    lastUpdated: FieldValue.serverTimestamp(),
                });
            } catch (updateError) {
                logger.error(`❌ Failed to update transaction ${transactionId} after critical error:`, updateError.message);
            }
        }

        res.json({ "ResultCode": 0, "ResultDesc": "Internal server error during processing." });
    }
});

// --- NEW AIRTIME BONUS API ENDPOINTS ---
const CURRENT_BONUS_DOC_PATH = 'airtime_bonuses/current_settings'; // Document path for current settings
const BONUS_HISTORY_COLLECTION = 'bonus_history'; // Collection for history logs

// GET current bonus percentages
app.get('/api/airtime-bonuses/current', async (req, res) => {
    try {
        const docRef = firestore.collection('airtime_bonuses').doc('current_settings');
        const docSnap = await docRef.get();

        if (docSnap.exists) {
            res.json(docSnap.data());
        } else {
            // If document doesn't exist, initialize it with default values
            logger.info('Initializing airtime_bonuses/current_settings with default values.');
            await docRef.set({ safaricomPercentage: 0, africastalkingPercentage: 0, lastUpdated: FieldValue.serverTimestamp() });
            res.json({ safaricomPercentage: 0, africastalkingPercentage: 0 });
        }
    } catch (error) {
        logger.error('Error fetching current airtime bonuses:', { message: error.message, stack: error.stack });
        res.status(500).json({ error: 'Failed to fetch current airtime bonuses.' });
    }
});

// POST to update bonus percentages and log history
app.post('/api/airtime-bonuses/update', async (req, res) => {
    const { safaricomPercentage, africastalkingPercentage, actor } = req.body; // 'actor' could be the authenticated user's ID/email

    if (typeof safaricomPercentage !== 'number' || typeof africastalkingPercentage !== 'number' || safaricomPercentage < 0 || africastalkingPercentage < 0) {
        logger.warn('Invalid bonus percentages received for update.', { safaricomPercentage, africastalkingPercentage });
        return res.status(400).json({ error: 'Invalid bonus percentages. Must be non-negative numbers.' });
    }

    try {
        const currentSettingsDocRef = firestore.collection('airtime_bonuses').doc('current_settings');
        const currentSettingsSnap = await currentSettingsDocRef.get();
        const oldSettings = currentSettingsSnap.exists ? currentSettingsSnap.data() : { safaricomPercentage: 0, africastalkingPercentage: 0 };

        const batch = firestore.batch();

        // Update the current settings document
        batch.set(currentSettingsDocRef, {
            safaricomPercentage: safaricomPercentage,
            africastalkingPercentage: africastalkingPercentage,
            lastUpdated: FieldValue.serverTimestamp(), // Use server timestamp
        }, { merge: true }); // Use merge to avoid overwriting other fields if they exist

        // Add history entries only if values have changed
        if (safaricomPercentage !== oldSettings.safaricomPercentage) {
            batch.set(firestore.collection(BONUS_HISTORY_COLLECTION).doc(), {
                company: 'Safaricom',
                oldPercentage: oldSettings.safaricomPercentage || 0,
                newPercentage: safaricomPercentage,
                timestamp: FieldValue.serverTimestamp(),
                actor: actor || 'system', // Default to 'system' if actor is not provided
            });
            logger.info(`Safaricom bonus changed from ${oldSettings.safaricomPercentage} to ${safaricomPercentage} by ${actor || 'system'}.`);
        }
        if (africastalkingPercentage !== oldSettings.africastalkingPercentage) {
            batch.set(firestore.collection(BONUS_HISTORY_COLLECTION).doc(), {
                company: 'Africastalking',
                oldPercentage: oldSettings.africastalkingPercentage || 0,
                newPercentage: africastalkingPercentage,
                timestamp: FieldValue.serverTimestamp(),
                actor: actor || 'system', // Default to 'system' if actor is not provided
            });
            logger.info(`AfricasTalking bonus changed from ${oldSettings.africastalkingPercentage} to ${africastalkingPercentage} by ${actor || 'system'}.`);
        }

        await batch.commit();
        res.json({ success: true, message: 'Bonus percentages updated successfully.' });

    } catch (error) {
        logger.error('Error updating airtime bonuses:', { message: error.message, stack: error.stack });
        res.status(500).json({ error: 'Failed to update airtime bonuses.' });
    }
});

// GET bonus history
app.get('/api/airtime-bonuses/history', async (req, res) => {
    try {
        const historyQuery = firestore.collection(BONUS_HISTORY_COLLECTION)
                                       .orderBy('timestamp', 'desc')
                                       .limit(50); // Limit to last 50 entries for performance

        const snapshot = await historyQuery.get();
        const history = snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                id: doc.id,
                company: data.company,
                oldPercentage: data.oldPercentage,
                newPercentage: data.newPercentage,
                timestamp: data.timestamp ? data.timestamp.toDate().toISOString() : null, // Convert Timestamp to ISO string for frontend
                actor: data.actor,
            };
        });
        res.json(history);
    } catch (error) {
        logger.error('Error fetching airtime bonus history:', { message: error.message, stack: error.stack });
        res.status(500).json({ error: 'Failed to fetch airtime bonus history.' });
    }
});

app.listen(PORT, () => logger.info(`✅ Server running on port ${PORT}`));
