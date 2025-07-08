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

// --- Google Cloud Secret Manager (Optional - Uncomment and configure if needed) ---
/*
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const secretManagerClient = new SecretManagerServiceClient();

async function getSecret(name) {
    const [version] = await secretManagerClient.accessSecretVersion({
        name: `projects/${process.env.GCP_PROJECT_ID}/secrets/${name}/versions/latest`,
    });
    return version.payload.data.toString('utf8');
}

// Example usage to load secrets before app starts
async function loadSecrets() {
    try {
        process.env.AT_API_KEY = await getSecret('AT_API_KEY');
        process.env.AT_USERNAME = await getSecret('AT_USERNAME');
        // ... load other secrets
        logger.info('Secrets loaded successfully from Secret Manager.');
    } catch (error) {
        logger.error('Failed to load secrets from Secret Manager:', error.message);
        process.exit(1); // Exit if secrets can't be loaded
    }
}
// You'd call loadSecrets() at the very start of your application
// before `africastalking` or `Firestore` are initialized if their credentials are in Secret Manager.
// For this script, we'll stick to .env for now to keep it runnable without complex GCP setup.
*/


// --- Firestore Initialization ---
const firestore = new Firestore({
    projectId: process.env.GCP_PROJECT_ID,
    keyFilename: process.env.GCP_KEY_FILE, // Make sure this path is correct and accessible
});

const txCollection = firestore.collection('transactions');
const errorsCollection = firestore.collection('errors');

// --- Middleware ---
app.use(helmet()); // Apply security headers

const corsOptions = {
    origin: 'https://daima-pay-portal.onrender.com', // Ensure this is your actual frontend URL
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
};
app.use(cors(corsOptions));
app.options('/*splat', cors(corsOptions)); // Handle pre-flight requests

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
    const transactionIdentifier = callbackData.TransID || 'N/A'; // Use TransID if available

    logger.info('📞 Received C2B Validation Callback:', { TransID: transactionIdentifier, callback: callbackData });

    const { BillRefNumber, TransAmount } = callbackData;

    // IMPORTANT: Implement your business validation logic here
    // For example, check if BillRefNumber (intended topup number) is valid or if it corresponds
    // to an existing account in your system, or if TransAmount is correct.

    // Basic Validation: Check if BillRefNumber is a valid phone number format and carrier.
    if (!BillRefNumber || BillRefNumber.length < 9 || BillRefNumber.length > 15 || isNaN(BillRefNumber)) {
        logger.warn(`⚠️ C2B Validation rejected [TransID: ${transactionIdentifier}]: Invalid BillRefNumber format (${BillRefNumber}).`);
        await errorsCollection.add({
            type: 'C2B_VALIDATION_REJECT',
            subType: 'INVALID_BILLREF_FORMAT',
            error: `Invalid or malformed BillRefNumber: ${BillRefNumber}`,
            callbackData: callbackData,
            createdAt: now,
        });
        return res.json({
            "ResultCode": 1, // 0 for Accept, 1 for Reject
            "ResultDesc": "Invalid Account Number format provided."
        });
    }

    const carrier = detectCarrier(BillRefNumber);
    if (carrier === 'Unknown') {
        logger.warn(`⚠️ C2B Validation rejected [TransID: ${transactionIdentifier}]: Unsupported carrier for BillRefNumber (${BillRefNumber}).`);
        await errorsCollection.add({
            type: 'C2B_VALIDATION_REJECT',
            subType: 'UNSUPPORTED_CARRIER',
            error: `Unsupported carrier for BillRefNumber: ${BillRefNumber}`,
            callbackData: callbackData,
            createdAt: now,
        });
        return res.json({
            "ResultCode": 1,
            "ResultDesc": "Unsupported carrier for provided Account Number."
        });
    }

    // Amount validation
    if (TransAmount <= 0) {
        logger.warn(`⚠️ C2B Validation rejected [TransID: ${transactionIdentifier}]: Invalid amount (${TransAmount}).`);
        await errorsCollection.add({
            type: 'C2B_VALIDATION_REJECT',
            subType: 'INVALID_AMOUNT',
            error: `Transaction amount must be greater than zero: ${TransAmount}`,
            callbackData: callbackData,
            createdAt: now,
        });
        return res.json({
            "ResultCode": 1,
            "ResultDesc": "Transaction amount must be greater than zero."
        });
    }
    // Add more validation logic as needed (e.g., min/max amount, service availability)

    // If all validation passes, accept the transaction
    logger.info('✅ C2B Validation successful:', { TransID: transactionIdentifier, BillRefNumber: BillRefNumber, Amount: TransAmount });
    res.json({
        "ResultCode": 0, // 0 for Accept, 1 for Reject
        "ResultDesc": "Validation successful."
    });
});

// C2B Confirmation Endpoint (Mandatory)
app.post('/c2b-confirmation', async (req, res) => {
    const callbackData = req.body;
    const now = new Date().toISOString();
    const transactionId = callbackData.TransID; // M-Pesa Transaction ID

    logger.info('📞 Received C2B Confirmation Callback:', { TransID: transactionId, callback: callbackData });

    // Extract relevant data from callbackData
    const {
        TransactionType,
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
            logger.warn(`⚠️ Duplicate C2B confirmation for TransID: ${transactionId}. Skipping processing.`);
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
            logger.error(`❌ ${errorMessage}`, { TransID: transactionId, topupNumber: topupNumber, callback: callbackData });
            await errorsCollection.add({
                type: 'C2B_AIRTIME_ERROR',
                subType: 'UNKNOWN_CARRIER',
                error: errorMessage,
                callbackData: callbackData,
                createdAt: now,
            });
            finalTxStatus = 'FAILED_UNKNOWN_CARRIER';
        } else {
            logger.info(`📡 Detected Carrier for C2B TransID ${transactionId}: ${carrier}`);
            if (carrier === 'Safaricom') {
                airtimeResult = await sendSafaricomAirtime(topupNumber, amount);
            } else { // Airtel, Telkom, Equitel, Faiba via Africa's Talking
                airtimeResult = await sendAfricasTalkingAirtime(topupNumber, amount, carrier);
            }

            if (airtimeResult && airtimeResult.status === 'SUCCESS') {
                finalTxStatus = 'COMPLETED';
                logger.info(`✅ Airtime successfully sent for C2B TransID: ${transactionId}`, { airtimeResponse: airtimeResult.data });
            } else {
                errorMessage = airtimeResult ? airtimeResult.error : 'Airtime send failed with no specific error message.';
                logger.error(`❌ Airtime send failed for C2B TransID ${transactionId}:`, {
                    error_message: errorMessage,
                    carrier: carrier,
                    topupNumber: topupNumber,
                    amount: amount,
                    airtimeResponse: airtimeResult,
                    callbackData: callbackData,
                });
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
        errorMessage = `Processing exception for C2B TransID ${transactionId}: ${err.message}`;
        logger.error(`❌ ${errorMessage}`, {
            error: err.message,
            stack: err.stack,
            TransID: transactionId,
            callbackData: callbackData
        });
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
            airtimeResult: airtimeResult, // Store full airtime API response if available
            errorMessage: errorMessage,
            lastUpdated: now,
            // Add float balance updates here if needed
        }).catch(updateErr => {
            logger.error(`❌ Failed to update transaction ${transactionId} in Firestore during finally block:`, {
                error: updateErr.message,
                stack: updateErr.stack,
                transactionCode: transactionId,
                callbackData: callbackData,
            });
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
    logger.info(`CORS origin allowed: ${corsOptions.origin}`);
});