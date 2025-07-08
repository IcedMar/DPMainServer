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
const helmet = require('helmet'); // Security middleware
const rateLimit = require('express-rate-limit'); // Rate limiting middleware
const winston = require('winston'); // For structured logging
require('winston-daily-rotate-file'); // For log file rotation

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
// Configure transports for production vs. development
const transports = [
    new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        ),
        level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    }),
];

// Add file logging with rotation for production
if (process.env.NODE_ENV === 'production') {
    transports.push(
        new winston.transports.DailyRotateFile({
            filename: 'logs/application-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '20m', // Rotate when file size reaches 20MB
            maxFiles: '14d', // Keep logs for 14 days
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
            level: 'error', // Only log errors to this file
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
        })
    );
}

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info', // Default to info level
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }), // Log stack traces for errors
        winston.format.splat(), // Enable string interpolation
        winston.format.json() // JSON format for structured logging
    ),
    defaultMeta: { service: 'daimapay-c2b-server' },
    transports: transports,
});

// --- Express App Setup ---
const app = express();
const PORT = process.env.PORT || 3000;

// --- Firestore Initialization ---
const firestore = new Firestore({
    projectId: process.env.GCP_PROJECT_ID,
    keyFilename: process.env.GCP_KEY_FILE, // Make sure this path is correct and accessible
});

// Separate collections as per requirement
const transactionsCollection = firestore.collection('transactions'); // For money received
const salesCollection = firestore.collection('sales');           // For airtime dispatched
const errorsCollection = firestore.collection('errors');         // For logging errors
// New: Collection for managing system-wide settings, including float
const systemSettingsCollection = firestore.collection('systemSettings');
const AIRTIME_FLOAT_DOC_ID = 'airtimeFloat'; // Fixed ID for the float document

// --- Middleware ---
app.use(helmet()); // Apply security headers

app.use(bodyParser.json({ limit: '1mb' })); // Limit request body size

// Rate Limiting for C2B callbacks to prevent abuse
const c2bLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 60, // Limit each IP to 60 requests per 5 minutes
    message: 'Too many requests from this IP for C2B callbacks, please try again later.',
    handler: (req, res, next, options) => {
        logger.warn(`Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
        res.status(options.statusCode).json({
            "ResultCode": 1, // Indicate failure to M-Pesa
            "ResultDesc": options.message
        });
    }
});
app.use('/c2b-confirmation', c2bLimiter);
app.use('/c2b-validation', c2bLimiter);


let cachedAirtimeToken = null;
let tokenExpiryTimestamp = 0;

// Carrier detection helper
function detectCarrier(phoneNumber) {
    const normalized = phoneNumber.replace(/^(\+254|254)/, '0').trim();
    // Ensure the number is 9 digits after '0'
    if (normalized.length !== 10 || !normalized.startsWith('0')) {
        logger.debug(`Invalid phone number format for carrier detection: ${phoneNumber}`);
        return 'Unknown';
    }
    const prefix3 = normalized.substring(1, 4); // after '0'

    // Prefixes based on current Kenyan mobile network ranges (as of mid-2024, subject to change)
    const safaricom = new Set([
        '110', '111', '112', '113', '114', '115', '116', '117', '118', '119', // 011x
        '700', '701', '702', '703', '704', '705', '706', '707', '708', '709', // 070x
        '710', '711', '712', '713', '714', '715', '716', '717', '718', '719', // 071x
        '720', '721', '722', '723', '724', '725', '726', '727', '728', '729', // 072x
        '740', '741', '742', '743', '744', '745', '746', '748', '749',       // 074x (excluding 747 - Faiba)
        '757', '758', '759',                                               // 075x (specific Safaricom, rest Airtel)
        '768', '769',                                                      // 076x (some Safaricom, 764-767 Equitel)
        '790', '791', '792', '793', '794', '795', '796', '797', '798', '799'  // 079x
    ]);
    const airtel = new Set([
        '100', '101', '102', '103', '104', '105', '106', '107', '108', '109', // 010x
        '730', '731', '732', '733', '734', '735', '736', '737', '738', '739', // 073x
        '750', '751', '752', '753', '754', '755', '756',                   // 075x
        '780', '781', '782', '783', '784', '785', '786', '787', '788', '789'  // 078x
    ]);
    const telkom = new Set([
        '770', '771', '772', '773', '774', '775', '776', '777', '778', '779' // 077x
    ]);
    const equitel = new Set([
        '764', '765', '766', '767',                                       // 076x
    ]);
    const faiba = new Set([
        '747', // 0747
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
        tokenExpiryTimestamp = now + 3599 * 1000; // Token expires in 1 hour (3600 seconds)
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
    // Ensures the number starts with 0 and is 10 digits long.
    let normalized = String(num).replace(/^(\+254|254)/, '0').trim();
    if (normalized.startsWith('0') && normalized.length === 10) {
        return normalized;
    }
    // If it's 7xx or 1xx, prepend 0
    if (normalized.length === 9 && !normalized.startsWith('0')) {
        return `0${normalized}`;
    }
    logger.warn(`Phone number could not be normalized to 07XXXXXXXX format: ${num}`);
    return num; // Return original if cannot normalize, carrier detection will likely fail.
}

// ✅ Send Safaricom dealer airtime
async function sendSafaricomAirtime(receiverNumber, amount) {
    try {
        const token = await getCachedAirtimeToken();
        const normalizedReceiver = normalizeReceiverPhoneNumber(receiverNumber);
        const adjustedAmount = Math.round(amount * 100); // Safaricom Airtime API expects amount in cents

        if (!process.env.DEALER_SENDER_MSISDN || !process.env.DEALER_SERVICE_PIN || !process.env.MPESA_AIRTIME_URL) {
            logger.error('Missing Safaricom Dealer API environment variables.');
            return { status: 'FAILED', message: 'Missing Safaricom Dealer API credentials.' };
        }

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

        logger.info('✅ Safaricom dealer airtime API response:', { receiver: normalizedReceiver, amount: amount, response_data: response.data });
        return {
            status: 'SUCCESS',
            message: 'Safaricom airtime sent',
            data: response.data,
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
    try {
        if (!process.env.AT_API_KEY || !process.env.AT_USERNAME) {
            logger.error('Missing Africa\'s Talking API environment variables.');
            return { status: 'FAILED', message: 'Missing Africa\'s Talking credentials.' };
        }
        const result = await africastalking.AIRTIME.send({
            recipients: [{ phoneNumber: normalizeReceiverPhoneNumber(phoneNumber), amount: `KES ${amount}` }],
        });
        logger.info(`✅ Africa's Talking airtime sent to ${carrier}:`, { recipient: phoneNumber, amount: amount, at_response: result });

        // AT response structure varies, typically check result.responses[0].status
        if (result && result.responses && result.responses.length > 0 && result.responses[0].status === 'Success') {
            return {
                status: 'SUCCESS',
                message: 'Africa\'s Talking airtime sent',
                data: result,
            };
        } else {
            logger.error(`❌ Africa's Talking airtime send indicates non-success status for ${carrier}:`, {
                recipient: phoneNumber,
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
            recipient: phoneNumber,
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


// --- C2B (Offline Paybill) Callbacks ---

// C2B Validation Endpoint (Optional but Recommended)
app.post('/c2b-validation', async (req, res) => {
    const callbackData = req.body;
    const now = new Date().toISOString();
    const transactionIdentifier = callbackData.TransID || `C2B_VALIDATION_${Date.now()}`;

    logger.info('📞 Received C2B Validation Callback:', { TransID: transactionIdentifier, callback: callbackData });

    const { BillRefNumber, TransAmount } = callbackData;
    const amount = parseFloat(TransAmount);
    const MIN_AMOUNT = 10.00; // Minimum amount for airtime purchase

    // --- Validation Checks ---

    // 1. Basic Phone Number (BillRefNumber) Validation
    if (!BillRefNumber || BillRefNumber.length < 9 || BillRefNumber.length > 15 || isNaN(BillRefNumber)) {
        logger.warn(`⚠️ C2B Validation rejected [TransID: ${transactionIdentifier}]: Invalid BillRefNumber format (${BillRefNumber}).`);
        await errorsCollection.add({
            type: 'C2B_VALIDATION_REJECT',
            subType: 'INVALID_BILLREF_FORMAT',
            error: `Invalid or malformed Account Number: ${BillRefNumber}`,
            callbackData: callbackData,
            createdAt: now,
        });
        return res.json({
            "ResultCode": 1, // Reject
            "ResultDesc": "Invalid Account Number format provided."
        });
    }

    // 2. Carrier Detection
    const carrier = detectCarrier(BillRefNumber);
    if (carrier === 'Unknown') {
        logger.warn(`⚠️ C2B Validation rejected [TransID: ${transactionIdentifier}]: Unsupported carrier for BillRefNumber (${BillRefNumber}).`);
        await errorsCollection.add({
            type: 'C2B_VALIDATION_REJECT',
            subType: 'UNSUPPORTED_CARRIER',
            error: `Unsupported carrier for provided Account Number: ${BillRefNumber}`,
            callbackData: callbackData,
            createdAt: now,
        });
        return res.json({
            "ResultCode": 1, // Reject
            "ResultDesc": "Unsupported carrier for provided Account Number."
        });
    }

    // 3. Amount Validation (KES 10 and above)
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

    // 4. Float Balance Check (Crucial for preventing over-selling)
    try {
        const floatDoc = await systemSettingsCollection.doc(AIRTIME_FLOAT_DOC_ID).get();
        if (!floatDoc.exists) {
            logger.error(`❌ Float balance document '${AIRTIME_FLOAT_DOC_ID}' not found in 'systemSettings' collection! Rejecting transaction.`);
            await errorsCollection.add({
                type: 'C2B_VALIDATION_ERROR',
                subType: 'FLOAT_DOC_MISSING',
                error: `Airtime float balance document missing in Firestore.`,
                callbackData: callbackData,
                createdAt: now,
            });
            return res.json({
                "ResultCode": 1,
                "ResultDesc": "Service temporarily unavailable. Please try again later."
            });
        }

        const currentFloatBalance = parseFloat(floatDoc.data().currentBalance);
        if (isNaN(currentFloatBalance)) {
            logger.error(`❌ Float balance in document '${AIRTIME_FLOAT_DOC_ID}' is not a valid number! Rejecting transaction.`);
            await errorsCollection.add({
                type: 'C2B_VALIDATION_ERROR',
                subType: 'FLOAT_BALANCE_INVALID',
                error: `Airtime float balance is invalid.`,
                callbackData: callbackData,
                createdAt: now,
            });
            return res.json({
                "ResultCode": 1,
                "ResultDesc": "Service temporarily unavailable. Please try again later."
            });
        }

        if (currentFloatBalance < amount) {
            logger.warn(`⚠️ C2B Validation rejected [TransID: ${transactionIdentifier}]: Insufficient float balance. Current: ${currentFloatBalance}, Needed: ${amount}`);
            await errorsCollection.add({
                type: 'C2B_VALIDATION_REJECT',
                subType: 'INSUFFICIENT_FLOAT',
                error: `Insufficient airtime float balance. Current: ${currentFloatBalance}, Requested: ${amount}`,
                callbackData: callbackData,
                createdAt: now,
            });
            return res.json({
                "ResultCode": 1, // Reject
                "ResultDesc": "Sorry, unable to process your request due to insufficient airtime float. Please try a smaller amount or check back later."
            });
        }
        logger.info(`✅ Float check passed for TransID ${transactionIdentifier}. Current balance: ${currentFloatBalance}, Request amount: ${amount}.`);

    } catch (error) {
        logger.error(`❌ Error during float balance check for TransID ${transactionIdentifier}:`, {
            message: error.message,
            stack: error.stack,
            callbackData: callbackData
        });
        await errorsCollection.add({
            type: 'C2B_VALIDATION_ERROR',
            subType: 'FLOAT_CHECK_EXCEPTION',
            error: `Failed to check airtime float balance: ${error.message}`,
            callbackData: callbackData,
            createdAt: now,
        });
        return res.json({
            "ResultCode": 1, // Reject due to internal error
            "ResultDesc": "An internal error occurred while validating your request. Please try again later."
        });
    }

    // If all validation passes, accept the transaction
    logger.info('✅ C2B Validation successful:', { TransID: transactionIdentifier, BillRefNumber: BillRefNumber, Amount: TransAmount });
    res.json({
        "ResultCode": 0, // Accept
        "ResultDesc": "Validation successful."
    });
});

// C2B Confirmation Endpoint (Mandatory)
app.post('/c2b-confirmation', async (req, res) => {
    const callbackData = req.body;
    const now = new Date().toISOString();
    const transactionId = callbackData.TransID; // M-Pesa Transaction ID (unique identifier for the incoming payment)

    logger.info('📞 Received C2B Confirmation Callback:', { TransID: transactionId, callback: callbackData });

    // Extract relevant data from callbackData
    const {
        TransTime,
        TransAmount,
        BillRefNumber,      // This is the Account Number entered by the customer (top-up number)
        MSISDN,             // Customer's phone number
        FirstName,
        MiddleName,
        LastName,
    } = callbackData;

    const topupNumber = BillRefNumber; // Assuming BillRefNumber is the number to top up
    const amount = parseFloat(TransAmount);
    const mpesaNumber = MSISDN;
    const customerName = `${FirstName || ''} ${MiddleName || ''} ${LastName || ''}`.trim();

    let saleId = null; // To store the ID of the sales document if created
    let floatDeducted = false; // Flag to track if float was successfully debited

    // Use a try-catch-finally block to ensure Firestore updates and M-Pesa response
    try {
        // --- 1. Record the incoming M-Pesa transaction (money received) ---
        // Check for duplicate M-Pesa TransID to ensure idempotency
        const existingTxDoc = await transactionsCollection.doc(transactionId).get();
        if (existingTxDoc.exists) {
            logger.warn(`⚠️ Duplicate C2B confirmation for TransID: ${transactionId}. Skipping processing.`);
            // Acknowledge M-Pesa even if it's a duplicate
            return res.json({ "ResultCode": 0, "ResultDesc": "Duplicate C2B confirmation received and ignored." });
        }

        // Record the incoming payment in the transactions collection
        await transactionsCollection.doc(transactionId).set({
            transactionID: transactionId, // M-Pesa's unique transaction ID for money received
            transactionTime: TransTime, // M-Pesa's transaction timestamp
            amountReceived: amount,
            payerMsisdn: mpesaNumber,
            payerName: customerName,
            billRefNumber: topupNumber, // The account number provided by customer
            mpesaRawCallback: callbackData, // Store the full callback for audit
            status: 'RECEIVED_PENDING_SALE', // Initial status for money received
            createdAt: now,
            lastUpdated: now,
        });
        logger.info(`✅ Recorded incoming transaction ${transactionId} in 'transactions' collection.`);


        // --- 2. Debit Float Balance & Record Airtime Sale attempt ---
        // Use a Firestore Transaction to safely update the float balance
        const floatUpdateResult = await firestore.runTransaction(async t => {
            const floatDocRef = systemSettingsCollection.doc(AIRTIME_FLOAT_DOC_ID);
            const floatDocSnapshot = await t.get(floatDocRef);

            if (!floatDocSnapshot.exists) {
                const errorMessage = `Float balance document '${AIRTIME_FLOAT_DOC_ID}' not found during transaction!`;
                logger.error(`❌ ${errorMessage}`);
                throw new Error(errorMessage); // This will cause the transaction to fail and retry
            }

            const currentFloat = parseFloat(floatDocSnapshot.data().currentBalance);
            if (isNaN(currentFloat)) {
                const errorMessage = `Float balance in document '${AIRTIME_FLOAT_DOC_ID}' is invalid!`;
                logger.error(`❌ ${errorMessage}`);
                throw new Error(errorMessage);
            }

            if (currentFloat < amount) {
                const errorMessage = `Insufficient float balance during confirmation for TransID ${transactionId}. Current: ${currentFloat}, Needed: ${amount}`;
                logger.warn(`⚠️ ${errorMessage}`);
                return { success: false, reason: 'INSUFFICIENT_FLOAT', message: errorMessage };
            }

            // If sufficient, debit the float
            const newFloat = currentFloat - amount;
            t.update(floatDocRef, { currentBalance: newFloat, lastUpdated: new Date().toISOString() });
            floatDeducted = true; // Set flag as float was debited

            logger.info(`✅ Debited float balance for TransID ${transactionId}. Old: ${currentFloat}, New: ${newFloat}`);
            return { success: true, newFloat: newFloat };
        });

        if (!floatUpdateResult.success) {
            // Float check failed during confirmation (e.g., race condition, or float went low between validation and confirmation)
            const errorMessage = floatUpdateResult.message || `Float debit failed for TransID ${transactionId}. Reason: ${floatUpdateResult.reason}`;
            logger.error(`❌ Float debit failed for TransID ${transactionId}. Reason: ${floatUpdateResult.reason}`);
            await errorsCollection.add({
                type: 'AIRTIME_SALE_ERROR',
                subType: floatUpdateResult.reason,
                error: errorMessage,
                transactionId: transactionId,
                callbackData: callbackData,
                createdAt: now,
            });

            // Update transaction record to reflect float issue
            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FLOAT_ISSUE',
                fulfillmentStatus: 'FAILED_INSUFFICIENT_FLOAT',
                errorMessage: errorMessage,
                lastUpdated: now,
            });

            // Since float debit failed, we don't proceed with airtime dispatch.
            return res.json({ "ResultCode": 0, "ResultDesc": "C2B confirmation received, but airtime not dispatched due to float issue." });
        }

        // If float was successfully debited, proceed with recording the sale and dispatching airtime
        const saleRef = salesCollection.doc(); // Let Firestore generate a unique ID
        saleId = saleRef.id; // Store saleId for potential future updates in catch block

        let airtimeDispatchStatus = 'FAILED';
        let airtimeDispatchResult = null;
        let saleErrorMessage = null;

        // Initialize sale document
        await saleRef.set({
            saleId: saleId,
            relatedTransactionId: transactionId, 
            topupNumber: topupNumber,
            amount: amount,
            carrier: detectCarrier(topupNumber), // Detect carrier here for sales record
            status: 'PENDING_DISPATCH', // Initial status for airtime sale
            dispatchAttemptedAt: now,
            createdAt: now,
            lastUpdated: now,
        });
        logger.info(`✅ Initialized sale document ${saleId} in 'sales' collection for TransID ${transactionId}.`);

        // --- 3. Attempt to dispatch airtime ---
        const carrier = detectCarrier(topupNumber); 
        if (carrier === 'Unknown') {
            saleErrorMessage = `Unsupported carrier prefix for airtime top-up: ${topupNumber}`;
            logger.error(`❌ ${saleErrorMessage}`, { TransID: transactionId, saleId: saleId, topupNumber: topupNumber, callback: callbackData });
            await errorsCollection.add({
                type: 'AIRTIME_SALE_ERROR',
                subType: 'UNKNOWN_CARRIER',
                error: saleErrorMessage,
                transactionId: transactionId,
                saleId: saleId,
                callbackData: callbackData,
                createdAt: now,
            });
            airtimeDispatchStatus = 'FAILED_UNKNOWN_CARRIER';
        } else {
            logger.info(`📡 Detected Carrier for sale ${saleId} (TransID ${transactionId}): ${carrier}`);
            if (carrier === 'Safaricom') {
                airtimeDispatchResult = await sendSafaricomAirtime(topupNumber, amount);
            } else { 
                airtimeDispatchResult = await sendAfricasTalkingAirtime(topupNumber, amount, carrier);
            }

            if (airtimeDispatchResult && airtimeDispatchResult.status === 'SUCCESS') {
                airtimeDispatchStatus = 'COMPLETED';
                logger.info(`✅ Airtime successfully sent for sale ${saleId} (TransID ${transactionId}).`, { airtimeResponse: airtimeDispatchResult.data });
            } else {
                saleErrorMessage = airtimeDispatchResult ? airtimeDispatchResult.error : 'Airtime dispatch failed with no specific error message.';
                logger.error(`❌ Airtime dispatch failed for sale ${saleId} (TransID ${transactionId}):`, {
                    error_message: saleErrorMessage,
                    carrier: carrier,
                    topupNumber: topupNumber,
                    amount: amount,
                    airtimeResponse: airtimeDispatchResult,
                    callbackData: callbackData,
                });
                await errorsCollection.add({
                    type: 'AIRTIME_SALE_ERROR',
                    subType: `AIRTIME_API_FAIL_${carrier.toUpperCase()}`,
                    error: saleErrorMessage,
                    transactionId: transactionId,
                    saleId: saleId,
                    originalAmount: amount,
                    airtimeResponse: airtimeDispatchResult,
                    callbackData: callbackData,
                    createdAt: now,
                });
                airtimeDispatchStatus = 'FAILED_DISPATCH_API';
                // REVERSAL LOGIC: If airtime dispatch failed *after* float was debited,
                logger.warn(`⚠️ Airtime dispatch failed after float debit. Manual reconciliation may be required for TransID ${transactionId}, Sale ${saleId}.`);
            }
        }

        // --- 4. Update the Airtime Sale document with final status ---
        await saleRef.update({
            status: airtimeDispatchStatus,
            dispatchResult: airtimeDispatchResult, 
            errorMessage: saleErrorMessage,
            lastUpdated: new Date().toISOString(),
        });
        logger.info(`✅ Updated sale ${saleId} to status: ${airtimeDispatchStatus}.`);

        // --- 5. Update the 'transactions' document with fulfillment status ---
        await transactionsCollection.doc(transactionId).update({
            linkedSaleId: saleId,
            fulfillmentStatus: airtimeDispatchStatus, 
            status: 'RECEIVED_FULFILLED', 
            lastUpdated: new Date().toISOString(),
        });
        logger.info(`✅ Updated transaction ${transactionId} with linked sale ID ${saleId} and fulfillment status.`);


    } catch (err) {
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
        });

        try {
            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_PROCESSING_ERROR',
                fulfillmentStatus: 'FAILED_SERVER_ERROR',
                errorMessage: generalErrorMessage,
                lastUpdated: new Date().toISOString(),
            });
        } catch (updateErr) {
            logger.error(`❌ Failed to update transaction ${transactionId} with processing error:`, { error: updateErr.message, stack: updateErr.stack });
        }
        if (saleId) {
            try {
                await salesCollection.doc(saleId).update({
                    status: 'FAILED_SERVER_ERROR',
                    errorMessage: generalErrorMessage,
                    lastUpdated: new Date().toISOString(),
                });
            } catch (updateErr) {
                logger.error(`❌ Failed to update sale ${saleId} with processing error:`, { error: updateErr.message, stack: updateErr.stack });
            }
        }

        // If float was debited but airtime failed due to an exception, this is a REVERSAL SCENARIO
        if (floatDeducted) {
             logger.warn(`⚠️ CRITICAL: Float was debited for TransID ${transactionId} but airtime dispatch failed due to an exception. Manual float reversal or reconciliation may be required.`);
             await errorsCollection.add({
                type: 'FLOAT_RECONCILIATION_WARNING',
                subType: 'FLOAT_DEBITED_BUT_DISPATCH_FAILED',
                error: `Float debited but airtime dispatch failed unexpectedly for TransID ${transactionId}.`,
                transactionId: transactionId,
                saleId: saleId,
                amount: amount,
                createdAt: now,
             });
        }

    } finally {
        res.json({ "ResultCode": 0, "ResultDesc": "C2B confirmation received by DaimaPay server." });
    }
});


// --- Health check endpoint ---
app.get('/', (req, res) => {
    logger.info('Health check endpoint hit.');
    res.send('DaimaPay C2B backend is live ✅');
});

// --- Fallback for unhandled routes ---
app.use((req, res, next) => {
    logger.warn(`404 Not Found: ${req.method} ${req.originalUrl}`);
    res.status(404).json({ message: 'Endpoint Not Found' });
});

// --- Centralized Error Handling Middleware (Express 4-argument error handler) ---
app.use((err, req, res, next) => {
    logger.error('Express Error Handler caught an error:', {
        method: req.method,
        url: req.originalUrl,
        error: err.message,
        stack: err.stack,
        body: req.body // Be careful with sensitive data in logs
    });

    if (res.headersSent) {
        return next(err); // If headers already sent, defer to default Express error handler
    }

    const statusCode = err.statusCode || 500;
    const message = process.env.NODE_ENV === 'production' ? 'An unexpected error occurred.' : err.message;

    res.status(statusCode).json({
        message: message,
        ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }), // Only send stack in dev
    });
});

// Start the server
app.listen(PORT, () => {
    logger.info(`🚀 C2B Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode.`);
    logger.info('Make sure NODE_ENV is set to "production" in your deployment environment.');
});