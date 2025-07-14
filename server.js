const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const admin = require('firebase-admin');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');
const axios = require('axios');
const winston = require('winston');
const winstonFirebase = require('winston-firebase');
const Bottleneck = require('bottleneck'); 

// Load environment variables from .env file
require('dotenv').config();

// Initialize Firebase Admin SDK
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);

initializeApp({
    credential: cert(serviceAccount)
});

const firestore = getFirestore();
const auth = getAuth();

// Initialize Winston Logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'airtime-topup-service' },
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            ),
        }),
        // Add Firebase transport if needed for cloud logging
        // new winstonFirebase(firebaseConfig),
    ],
});

// Uncaught Exceptions & Unhandled Rejections
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', { message: error.message, stack: error.stack });
    process.exit(1); // Exit with a failure code
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', { promise, reason: reason.message, stack: reason.stack });
    // Do not exit, allow the process to continue unless it's a critical error
});

// Africa's Talking SDK Initialization
const AfricasTalking = require('africastalking');
const africastalking = AfricasTalking({
    apiKey: process.env.AT_API_KEY,
    username: process.env.AT_USERNAME
});

// Express App Initialization
const app = express();
const PORT = process.env.PORT || 3000;

// Security Middlewares
app.use(helmet());
app.use(cors());
app.use(express.json()); // For parsing application/json

// Rate Limiting for public facing endpoints (adjust as needed)
const rateLimit = require('express-rate-limit');
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    message: 'Too many requests from this IP, please try again after 15 minutes',
});
app.use(apiLimiter);

// Firestore Collection References
const transactionsCollection = firestore.collection('transactions');
const salesCollection = firestore.collection('sales');
const errorsCollection = firestore.collection('errors');
const safaricomFloatDocRef = firestore.collection('floats').doc('safaricomFloat');
const africasTalkingFloatDocRef = firestore.collection('floats').doc('africasTalkingFloat');
const bonusHistoryCollection = firestore.collection('airtime_bonus_history');
const mpesaSettingsDocRef = firestore.collection('mpesa_settings').doc('credentials'); // For Daraja consumer key/secret
const reconciledTransactionsCollection = firestore.collection('reconciled_transactions');
const failedReconciliationsCollection = firestore.collection('failed_reconciliations');
const reversalTimeoutsCollection = firestore.collection('daraja_reversal_timeouts');

// Global variable for Safaricom Dealer API Token and its expiry
let safaricomDealerAccessToken = null;
let safaricomDealerTokenExpiry = 0;

// Rate limiter for Safaricom Dealer API to avoid exceeding limits
const safaricomApiLimiter = new Bottleneck({
    minTime: 500, // At most 2 requests per second
    maxConcurrent: 1, // Process requests one at a time
});

async function getDarajaAccessToken() {
    try {
        const doc = await mpesaSettingsDocRef.get();
        if (!doc.exists) {
            logger.error('Daraja API credentials not found in Firestore.');
            throw new Error('Daraja API credentials not configured.');
        }
        const { consumerKey, consumerSecret } = doc.data();

        if (!consumerKey || !consumerSecret) {
            logger.error('Missing M-Pesa Consumer Key or Secret in Firestore settings.');
            throw new Error('M-Pesa API credentials incomplete.');
        }

        const authString = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');
        const url = process.env.MPESA_AUTH_URL;

        if (!url) {
            logger.error('MPESA_AUTH_URL is not set in environment variables.');
            throw new Error('M-Pesa authentication URL not configured.');
        }

        const response = await axios.get(url, {
            headers: {
                'Authorization': `Basic ${authString}`
            }
        });
        logger.info('✅ Successfully fetched Daraja access token.');
        return response.data.access_token;
    } catch (error) {
        logger.error('❌ Failed to get Daraja access token:', {
            message: error.message,
            statusCode: error.response ? error.response.status : 'N/A',
            errorData: error.response ? error.response.data : 'N/A',
            stack: error.stack
        });
        return null;
    }
}

// Function to fetch Safaricom Dealer API token
async function getSafaricomDealerAccessToken() {
    const now = Date.now();
    // Check if token exists and is not expired
    if (safaricomDealerAccessToken && safaricomDealerTokenExpiry > now) {
        logger.info('✅ Using cached Safaricom Dealer API token.');
        return safaricomDealerAccessToken;
    }

    try {
        const doc = await mpesaSettingsDocRef.get();
        if (!doc.exists) {
            logger.error('Safaricom Dealer credentials not found in Firestore.');
            throw new Error('Safaricom Dealer credentials not configured.');
        }
        const { safaricomDealerUsername, safaricomDealerPassword } = doc.data();

        if (!safaricomDealerUsername || !safaricomDealerPassword) {
            logger.error('Missing Safaricom Dealer Username or Password in Firestore settings.');
            throw new Error('Safaricom Dealer credentials incomplete.');
        }

        const loginUrl = process.env.SAFARICOM_DEALER_LOGIN_URL;
        if (!loginUrl) {
            logger.error('SAFARICOM_DEALER_LOGIN_URL is not set in environment variables.');
            throw new Error('Safaricom Dealer login URL not configured.');
        }

        const response = await axios.post(loginUrl, {
            username: safaricomDealerUsername,
            password: safaricomDealerPassword
        });

        if (response.data && response.data.token && response.data.expiresIn) {
            safaricomDealerAccessToken = response.data.token;
            // Set expiry time a bit before actual expiry to be safe (e.g., 5 minutes before)
            safaricomDealerTokenExpiry = now + (response.data.expiresIn * 1000) - (5 * 60 * 1000);
            logger.info('✅ Successfully fetched new Safaricom Dealer API token.');
            return safaricomDealerAccessToken;
        } else {
            throw new Error('Invalid response from Safaricom Dealer login API.');
        }

    } catch (error) {
        logger.error('❌ Failed to get Safaricom Dealer API token:', {
            message: error.message,
            statusCode: error.response ? error.response.status : 'N/A',
            errorData: error.response ? error.response.data : 'N/A',
            stack: error.stack
        });
        return null;
    }
}

// Function to generate Safaricom Dealer PIN (cached)
let cachedServicePin = null;
let pinLastFetched = 0;
const PIN_CACHE_DURATION = 1 * 60 * 60 * 1000; // Cache for 1 hour

async function getCachedServicePin() {
    const now = Date.now();
    if (cachedServicePin && (now - pinLastFetched) < PIN_CACHE_DURATION) {
        logger.info('✅ Using cached Safaricom Service PIN.');
        return cachedServicePin;
    }

    try {
        const doc = await mpesaSettingsDocRef.get();
        if (!doc.exists || !doc.data().safaricomServicePin) {
            logger.error('Safaricom Service PIN not found in Firestore settings.');
            throw new Error('Safaricom Service PIN not configured.');
        }
        cachedServicePin = doc.data().safaricomServicePin;
        pinLastFetched = now;
        logger.info('✅ Fetched Safaricom Service PIN from Firestore and cached.');
        return cachedServicePin;
    } catch (error) {
        logger.error('❌ Failed to retrieve Safaricom Service PIN:', {
            message: error.message,
            stack: error.stack
        });
        return null;
    }
}

// Function to detect carrier based on phone number prefix
function detectCarrier(phoneNumber) {
    const cleanedNumber = phoneNumber.replace(/\D/g, ''); // Remove non-digits
    const prefix = cleanedNumber.startsWith('254') ? cleanedNumber.substring(3, 5) : cleanedNumber.substring(0, 2);

    // Safaricom prefixes
    const safaricomPrefixes = ['70', '71', '72', '74', '75', '76', '79', '10'];
    if (safaricomPrefixes.includes(prefix) || cleanedNumber.startsWith('07') || cleanedNumber.startsWith('01')) {
        return 'Safaricom';
    }

    // Airtel prefixes
    const airtelPrefixes = ['73', '78'];
    if (airtelPrefixes.includes(prefix)) {
        return 'Airtel';
    }

    // Telkom prefixes
    const telkomPrefixes = ['77'];
    if (telkomPrefixes.includes(prefix)) {
        return 'Telkom';
    }

    // Equitel prefixes
    const equitelPrefixes = ['764', '765']; // Assuming '764' and '765' for Equitel
    if (cleanedNumber.startsWith('254764') || cleanedNumber.startsWith('254765')) {
        return 'Equitel';
    }

    // Faiba prefixes
    const faibaPrefixes = ['747', '748'];
    if (cleanedNumber.startsWith('254747') || cleanedNumber.startsWith('254748')) {
        return 'Faiba';
    }

    return 'Unknown';
}


// Function to send Safaricom Airtime via Dealer Portal
async function sendSafaricomAirtime(phoneNumber, amount) {
    let normalizedPhone = phoneNumber;
    if (phoneNumber.startsWith('0')) {
        normalizedPhone = '254' + phoneNumber.slice(1);
    } else if (phoneNumber.startsWith('+254')) {
        normalizedPhone = phoneNumber.slice(1);
    } else if (!phoneNumber.startsWith('254')) {
        logger.error('[sendSafaricomAirtime] Invalid phone format:', { phoneNumber: phoneNumber });
        return {
            status: 'FAILED',
            message: 'Invalid phone number format for Safaricom Dealer',
            details: {
                error: 'Phone must start with +254, 254, or 0'
            }
        };
    }

    return safaricomApiLimiter.schedule(async () => {
        try {
            const token = await getSafaricomDealerAccessToken();
            const servicePin = await getCachedServicePin();
            const url = process.env.SAFARICOM_DEALER_AIRTIME_URL;

            if (!token || !servicePin || !url) {
                logger.error('Missing Safaricom Dealer API credentials or URL.');
                return { status: 'FAILED', message: 'Missing Safaricom Dealer credentials or URL.' };
            }

            const payload = {
                pin: servicePin,
                amount: parseFloat(amount).toFixed(2), // Ensure amount is float with 2 decimal places
                msisdn: normalizedPhone
            };

            const headers = {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            };

            const response = await axios.post(url, payload, { headers });

            // Safaricom Dealer API response structure might vary, adjust this based on actual API docs
            const dealerResponse = response.data;
            if (dealerResponse.status === 'success' || dealerResponse.code === '200' || dealerResponse.message === 'Request processed successfully') {
                logger.info(`✅ Safaricom airtime successfully sent to ${normalizedPhone}:`, {
                    amount: amount,
                    dealer_response: dealerResponse
                });
                return {
                    status: 'SUCCESS',
                    message: 'Safaricom airtime sent',
                    data: dealerResponse,
                    // Assuming the dealer API returns the new float balance directly in a field like 'newBalance'
                    newSafaricomFloatBalance: dealerResponse.currentBalance || null
                };
            } else {
                const errorMessage = dealerResponse.message || dealerResponse.error || 'Unknown Safaricom Dealer API error';
                logger.error(`❌ Safaricom Dealer airtime send failed for ${normalizedPhone}:`, {
                    amount: amount,
                    dealer_response: dealerResponse
                });
                return {
                    status: 'FAILED',
                    message: 'Safaricom Dealer airtime send failed.',
                    error: errorMessage,
                    data: dealerResponse, // Return full response for debugging
                };
            }
        } catch (error) {
            const errorData = error.response ? error.response.data : error.message;
            logger.error(`❌ Safaricom Dealer airtime send failed (exception caught) for ${phoneNumber}:`, {
                recipient: phoneNumber,
                amount: amount,
                message: error.message,
                stack: error.stack,
                errorData: errorData
            });
            return {
                status: 'FAILED',
                message: `Safaricom Dealer airtime send failed (exception): ${error.message}`,
                error: errorData,
            };
        }
    });
}

// Function to send Africa's Talking Airtime
async function sendAfricasTalkingAirtime(phoneNumber, amount, carrier) {
    let normalizedPhone = phoneNumber;

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

        const response = result?.responses?.[0];
        const status = response?.status;
        const errorMessage = response?.errorMessage;

        if (status === 'Sent' && errorMessage === 'None') {
            logger.info(`✅ Africa's Talking airtime successfully initiated to ${carrier}:`, {
                recipient: normalizedPhone,
                amount: amount,
                at_response: result
            });
            return {
                status: 'INITIATED', // Changed to 'INITIATED' to signify not yet final completion
                message: 'Africa\'s Talking airtime initiated, awaiting final callback',
                data: result,
                at_requestId: response.requestId, // EXPOSE THE REQUEST_ID
            };
        } else {
            logger.error(`❌ Africa's Talking airtime send indicates non-success for ${carrier}:`, {
                recipient: normalizedPhone,
                amount: amount,
                at_response: result
            });
            return {
                status: 'FAILED',
                message: 'Africa\'s Talking airtime send failed or not successful at initial stage.',
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

// Daraja Reversal Function
async function initiateDarajaReversal(transactionId, amount, receiverMsisdn) {
    logger.info(`🔄 Attempting Daraja reversal for TransID: ${transactionId}, Amount: ${amount}`);
    try {
        const accessToken = await getDarajaAccessToken();

        if (!accessToken) {
            throw new Error("Failed to get Daraja access token for reversal.");
        }

        const url = process.env.MPESA_REVERSAL_URL;
        const shortCode = process.env.MPESA_SHORTCODE;
        const initiator = process.env.MPESA_INITIATOR_NAME;
        const securityCredential = process.env.MPESA_SECURITY_CREDENTIAL;

        if (!url || !shortCode || !initiator || !securityCredential) {
            throw new Error("Missing Daraja reversal environment variables.");
        }

        const payload = {
            Initiator: initiator,
            SecurityCredential: securityCredential,
            CommandID: "TransactionReversal",
            TransactionID: transactionId,
            Amount: amount,
            ReceiverPartyA: shortCode,
            ReceiverPartyB: receiverMsisdn,
            QueueTimeoutURL: process.env.MPESA_REVERSAL_QUEUE_TIMEOUT_URL,
            ResultURL: process.env.MPESA_REVERSAL_RESULT_URL,
            Remarks: `Airtime dispatch failed for ${transactionId}`,
            Occasion: "Failed Airtime Topup"
        };

        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        };

        const response = await axios.post(url, payload, { headers });

        logger.info(`✅ Daraja Reversal API response for TransID ${transactionId}:`, response.data);

        if (response.data && response.data.ResponseCode === '0') {
            return {
                success: true,
                message: "Reversal request accepted by Daraja.",
                data: response.data,
                conversationId: response.data.ConversationID || null,
            };
        } else {
            const errorMessage = response.data ?
                `Daraja reversal request failed: ${response.data.ResponseDescription || 'Unknown error'}` :
                'Daraja reversal request failed with no response data.';
            logger.error(`❌ Daraja reversal request not accepted for TransID ${transactionId}: ${errorMessage}`);
            return {
                success: false,
                message: errorMessage,
                data: response.data,
            };
        }

    } catch (error) {
        const errorData = error.response ? error.response.data : error.message;
        logger.error(`❌ Exception during Daraja reversal for TransID ${transactionId}:`, {
            error: errorData,
            stack: error.stack
        });
        return {
            success: false,
            message: `Exception in reversal process: ${errorData.errorMessage || error.message}`,
            error: errorData
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
            currentFloat = parseFloat(floatDocSnapshot.data().balance);
            if (isNaN(currentFloat)) {
                const errorMessage = `Float balance in document '${carrierLogicalName}' is invalid!`;
                logger.error(`❌ ${errorMessage}`);
                throw new Error(errorMessage);
            }
        } else {
            logger.warn(`Float document '${carrierLogicalName}' not found. Initializing with balance 0.`);
            t.set(floatDocRef, { balance: 0, lastUpdated: FieldValue.serverTimestamp() });
            currentFloat = 0;
        }

        const newFloat = currentFloat + amount;
        if (amount < 0 && newFloat < 0) {
            const errorMessage = `Attempt to debit ${carrierLogicalName} float below zero. Current: ${currentFloat}, Attempted debit: ${-amount}`;
            logger.warn(`⚠️ ${errorMessage}`);
            throw new Error('Insufficient carrier-specific float balance for this transaction.');
        }

        t.update(floatDocRef, { balance: newFloat, lastUpdated: FieldValue.serverTimestamp() });
        logger.info(`✅ Updated ${carrierLogicalName} float balance. Old: ${currentFloat}, New: ${newFloat}, Change: ${amount}`);
        return { success: true, newBalance: newFloat };
    });
}

// C2B (Offline Paybill) Callbacks

// C2B Validation Endpoint
app.post('/c2b-validation', async (req, res) => {
    const callbackData = req.body;
    const transactionIdentifier = callbackData.TransID || `C2B_VALIDATION_${Date.now()}`;

    logger.info('📞 Received C2B Validation Callback:', { TransID: transactionIdentifier, callback: callbackData });

    const { TransAmount } = callbackData;
    const amount = parseFloat(TransAmount);
    const MIN_AMOUNT = 5.00;

    if (isNaN(amount) || amount < MIN_AMOUNT) {
        logger.warn(`⚠️ C2B Validation rejected [TransID: ${transactionIdentifier}]: Invalid amount (${TransAmount}). Must be KES ${MIN_AMOUNT} or more.`);
        await errorsCollection.add({
            type: 'C2B_VALIDATION_REJECT',
            subType: 'INVALID_AMOUNT_TOO_LOW',
            error: `Transaction amount must be KES ${MIN_AMOUNT} or more: ${TransAmount}`,
            callbackData: callbackData,
            createdAt: FieldValue.serverTimestamp(),
        });
        return res.json({
            "ResultCode": 1,
            "ResultDesc": `Invalid Amount`
        });
    }

    logger.info('✅ C2B Validation successful (amount check only):', { TransID: transactionIdentifier, Amount: TransAmount });
    res.json({
        "ResultCode": 0,
        "ResultDesc": "Validation successful."
    });
});

// C2B Confirmation Endpoint (Mandatory)
app.post('/c2b-confirmation', async (req, res) => {
    const callbackData = req.body;
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
    const amount = parseFloat(TransAmount);
    const mpesaNumber = MSISDN;
    const customerName = `${FirstName || ''} ${MiddleName || ''} ${LastName || ''}`.trim();

    let saleId = null;
    let airtimeDispatchStatus = 'FAILED';
    let airtimeDispatchResult = null;
    let saleErrorMessage = null;
    let airtimeProviderUsed = null;

    try {
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
            createdAt: FieldValue.serverTimestamp(),
            lastUpdated: FieldValue.serverTimestamp(),
        });
        logger.info(`✅ Recorded incoming transaction ${transactionId} in 'transactions' collection.`);

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

        const bonusDocRef = firestore.collection('airtime_bonuses').doc('current_settings');
        const bonusDocSnap = await bonusDocRef.get();
        const bonusSettings = bonusDocSnap.exists ? bonusDocSnap.data() : { safaricomPercentage: 0, africastalkingPercentage: 0 };

        let finalAmountToDispatch = amount;
        let bonusApplied = 0;

        if (targetCarrier === 'Safaricom') {
            if (bonusSettings.safaricomPercentage > 0) {
                bonusApplied = amount * (bonusSettings.safaricomPercentage / 100);
                finalAmountToDispatch = amount + bonusApplied;
                logger.info(`Applying ${bonusSettings.safaricomPercentage}% Safaricom bonus. Original: ${amount}, Bonus: ${bonusApplied}, Final: ${finalAmountToDispatch}`);
            }
        } else {
            if (bonusSettings.africastalkingPercentage > 0) {
                bonusApplied = amount * (bonusSettings.africastalkingPercentage / 100);
                finalAmountToDispatch = amount + bonusApplied;
                logger.info(`Applying ${bonusSettings.africastalkingPercentage}% AfricasTalking bonus. Original: ${amount}, Bonus: ${bonusApplied}, Final: ${finalAmountToDispatch}`);
            }
        }
        finalAmountToDispatch = parseFloat(finalAmountToDispatch.toFixed(2));
        bonusApplied = parseFloat(bonusApplied.toFixed(2));

        const saleRef = salesCollection.doc();
        saleId = saleRef.id;
        await saleRef.set({
            saleId: saleId,
            relatedTransactionId: transactionId,
            topupNumber: topupNumber,
            originalAmountPaid: amount,
            amount: finalAmountToDispatch,
            bonusApplied: bonusApplied,
            carrier: targetCarrier,
            status: 'PENDING_DISPATCH',
            dispatchAttemptedAt: FieldValue.serverTimestamp(),
            createdAt: FieldValue.serverTimestamp(),
            lastUpdated: FieldValue.serverTimestamp(),
            payerMsisdn: mpesaNumber, // Store for potential reversal
        });
        logger.info(`✅ Initialized sale document ${saleId} in 'sales' collection for TransID ${transactionId} with bonus details.`);

        if (targetCarrier === 'Safaricom') {
            try {
                await updateCarrierFloatBalance('safaricomFloat', -finalAmountToDispatch);
                airtimeProviderUsed = 'SafaricomDealer';
                airtimeDispatchResult = await sendSafaricomAirtime(topupNumber, finalAmountToDispatch);

                if (airtimeDispatchResult && airtimeDispatchResult.status === 'SUCCESS') {
                    airtimeDispatchStatus = 'COMPLETED';
                    logger.info(`✅ Safaricom airtime successfully sent via Dealer Portal for sale ${saleId}.`);
                } else {
                    saleErrorMessage = airtimeDispatchResult?.error || 'Safaricom Dealer Portal failed with unknown error.';
                    logger.warn(`⚠️ Safaricom Dealer Portal failed for TransID ${transactionId}. Attempting fallback to Africastalking. Error: ${saleErrorMessage}`);

                    await updateCarrierFloatBalance('safaricomFloat', finalAmountToDispatch);
                    logger.info(`✅ Refunded Safaricom float for TransID ${transactionId}: +${finalAmountToDispatch}`);

                    await updateCarrierFloatBalance('africasTalkingFloat', -finalAmountToDispatch);
                    airtimeProviderUsed = 'AfricasTalkingFallback';
                    airtimeDispatchResult = await sendAfricasTalkingAirtime(topupNumber, finalAmountToDispatch, targetCarrier);

                    if (airtimeDispatchResult && airtimeDispatchResult.status === 'INITIATED') {
                        airtimeDispatchStatus = 'PENDING_AT_CONFIRMATION'; // NEW: Intermediate status
                        updateSaleFields.at_requestId = airtimeDispatchResult.at_requestId; // NEW: Store AT requestId
                        logger.info(`✅ Safaricom fallback airtime initiated via AfricasTalking for sale ${saleId}. AT Request ID: ${airtimeDispatchResult.at_requestId}`);
                        const commissionAmount = parseFloat((amount * 0.04).toFixed(2));
                        await updateCarrierFloatBalance('africasTalkingFloat', commissionAmount);
                        logger.info(`✅ Credited Africa's Talking float with ${commissionAmount} (4% commission) for TransID ${transactionId}.`);
                    } else {
                        saleErrorMessage = airtimeDispatchResult ? airtimeDispatchResult.error : 'Africastalking fallback failed with no specific error.';
                        logger.error(`❌ Safaricom fallback via Africastalking failed for sale ${saleId}: ${saleErrorMessage}`);
                        airtimeDispatchStatus = 'FAILED'; // Fallback also failed
                    }
                }
            } catch (dispatchError) {
                saleErrorMessage = `Safaricom primary dispatch process failed (or float debit failed): ${dispatchError.message}`;
                logger.error(`❌ Safaricom primary dispatch process failed for TransID ${transactionId}: ${dispatchError.message}`);
                airtimeDispatchStatus = 'FAILED';
            }

        } else if (['Airtel', 'Telkom', 'Equitel', 'Faiba'].includes(targetCarrier)) {
            try {
                await updateCarrierFloatBalance('africasTalkingFloat', -finalAmountToDispatch);
                airtimeProviderUsed = 'AfricasTalkingDirect';
                airtimeDispatchResult = await sendAfricasTalkingAirtime(topupNumber, finalAmountToDispatch, targetCarrier);

                if (airtimeDispatchResult && airtimeDispatchResult.status === 'INITIATED') {
                    airtimeDispatchStatus = 'PENDING_AT_CONFIRMATION'; // NEW: Intermediate status
                    updateSaleFields.at_requestId = airtimeDispatchResult.at_requestId; // NEW: Store AT requestId
                    logger.info(`✅ AfricasTalking airtime initiated directly for sale ${saleId}. AT Request ID: ${airtimeDispatchResult.at_requestId}`);
                    const commissionAmount = parseFloat((amount * 0.04).toFixed(2));
                    await updateCarrierFloatBalance('africasTalkingFloat', commissionAmount);
                    logger.info(`✅ Credited Africa's Talking float with ${commissionAmount} (4% commission) for TransID ${transactionId}.`);
                } else {
                    saleErrorMessage = airtimeDispatchResult ? airtimeDispatchResult.error : 'Africastalking direct dispatch failed with no specific error.';
                    logger.error(`❌ AfricasTalking direct dispatch failed for sale ${saleId}: ${saleErrorMessage}`);
                    airtimeDispatchStatus = 'FAILED'; // AT direct dispatch failed
                }
            } catch (dispatchError) {
                saleErrorMessage = `AfricasTalking direct dispatch process failed (or float debit failed): ${dispatchError.message}`;
                logger.error(`❌ AfricasTalking direct dispatch process failed for TransID ${transactionId}: ${dispatchError.message}`);
                airtimeDispatchStatus = 'FAILED';
            }
        } else {
            saleErrorMessage = `No valid dispatch path for carrier: ${targetCarrier}`;
            logger.error(`❌ ${saleErrorMessage} for TransID ${transactionId}`);
            await errorsCollection.add({
                type: 'AIRTIME_SALE_ERROR',
                subType: 'NO_DISPATCH_PATH',
                error: saleErrorMessage,
                transactionId: transactionId,
                callbackData: callbackData,
                createdAt: FieldValue.serverTimestamp(),
            });
            airtimeDispatchStatus = 'FAILED';
        }

        const updateSaleFields = {
            lastUpdated: FieldValue.serverTimestamp(),
            dispatchResult: airtimeDispatchResult?.data || airtimeDispatchResult?.error || airtimeDispatchResult,
            airtimeProviderUsed: airtimeProviderUsed,
        };

        if (airtimeDispatchStatus === 'COMPLETED') {
            updateSaleFields.status = airtimeDispatchStatus;
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
        } else if (airtimeDispatchStatus === 'PENDING_AT_CONFIRMATION') {
            updateSaleFields.status = airtimeDispatchStatus; // Keep PENDING status
            updateSaleFields.at_requestId = airtimeDispatchResult.at_requestId; // Ensure AT Request ID is saved
        }
        else {
            saleErrorMessage = saleErrorMessage || 'Airtime dispatch failed with no specific error message.';
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
                subType: 'AIRTIME_DISPATCH_FAILED',
                error: saleErrorMessage,
                transactionId: transactionId,
                saleId: saleId,
                callbackData: callbackData,
                airtimeApiResponse: airtimeDispatchResult,
                providerAttempted: airtimeProviderUsed,
                createdAt: FieldValue.serverTimestamp(),
            });
            updateSaleFields.status = 'FAILED_DISPATCH_API';
            updateSaleFields.errorMessage = saleErrorMessage;
        }

        await saleRef.update(updateSaleFields);
        logger.info(`✅ Updated sale document ${saleId} with dispatch result.`);

        if (airtimeDispatchStatus === 'FAILED_DISPATCH_API') { // Only reverse if ultimately failed
            logger.warn(`🛑 Airtime dispatch ultimately failed for TransID ${transactionId}. Initiating Daraja reversal.`);

            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FULFILLMENT_FAILED',
                fulfillmentStatus: 'FAILED_DISPATCH_API',
                fulfillmentDetails: airtimeDispatchResult,
                errorMessage: saleErrorMessage,
                lastUpdated: FieldValue.serverTimestamp(),
                airtimeProviderUsed: airtimeProviderUsed,
                reversalAttempted: true,
            });

            const reversalResult = await initiateDarajaReversal(transactionId, amount, mpesaNumber);

            if (reversalResult.success) {
                logger.info(`✅ Daraja reversal initiated successfully for TransID ${transactionId}.`);
                await reconciledTransactionsCollection.doc(transactionId).set({
                    transactionId: transactionId,
                    amount: amount,
                    mpesaNumber: mpesaNumber,
                    reversalInitiatedAt: FieldValue.serverTimestamp(),
                    reversalRequestDetails: reversalResult.data,
                    originalCallbackData: callbackData,
                    status: 'REVERSAL_INITIATED',
                    createdAt: FieldValue.serverTimestamp(),
                });
                await transactionsCollection.doc(transactionId).update({
                    status: 'REVERSAL_PENDING_CONFIRMATION',
                    lastUpdated: FieldValue.serverTimestamp(),
                    reversalDetails: reversalResult.data,
                });
            } else {
                logger.error(`❌ Daraja reversal failed to initiate for TransID ${transactionId}: ${reversalResult.message}`);
                await failedReconciliationsCollection.doc(transactionId).set({
                    transactionId: transactionId,
                    amount: amount,
                    mpesaNumber: mpesaNumber,
                    reversalAttemptedAt: FieldValue.serverTimestamp(),
                    reversalFailureDetails: reversalResult.error,
                    originalCallbackData: callbackData,
                    reason: reversalResult.message,
                    createdAt: FieldValue.serverTimestamp(),
                }, { merge: true });
                await transactionsCollection.doc(transactionId).update({
                    status: 'REVERSAL_INITIATION_FAILED',
                    lastUpdated: FieldValue.serverTimestamp(),
                    reversalDetails: reversalResult.error,
                    errorMessage: `Reversal initiation failed: ${reversalResult.message}`
                });
            }
        } else if (airtimeDispatchStatus === 'COMPLETED' || airtimeDispatchStatus === 'PENDING_AT_CONFIRMATION') {
            await transactionsCollection.doc(transactionId).update({
                status: 'COMPLETED_AND_FULFILLED', // For Safaricom success directly or AT pending
                fulfillmentStatus: airtimeDispatchStatus,
                fulfillmentDetails: airtimeDispatchResult,
                lastUpdated: FieldValue.serverTimestamp(),
                airtimeProviderUsed: airtimeProviderUsed,
            });
        }

        logger.info(`Final status for TransID ${transactionId}: ${airtimeDispatchStatus === 'COMPLETED' || airtimeDispatchStatus === 'PENDING_AT_CONFIRMATION' ? 'COMPLETED_AND_FULFILLED (or pending AT confirmation)' : 'REVERSAL_ATTEMPTED_OR_FAILED'}`);
        res.json({ "ResultCode": 0, "ResultDesc": "C2B Confirmation and Airtime Dispatch Processed. Reversal initiated if failed." });

    } catch (error) {
        logger.error(`❌ CRITICAL ERROR in C2B Confirmation for TransID ${transactionId}:`, {
            message: error.message,
            stack: error.stack,
            callbackData: callbackData,
        });

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
        res.json({ "ResultCode": 0, "ResultDesc": "Internal server error during processing. Please check logs." });
    }
});

// Africa's Talking Airtime Status Webhook Endpoint
app.post('/africastalking-airtime-status', async (req, res) => {
    const callbackData = req.body;
    logger.info('📞 Received Africa\'s Talking Airtime Status Callback:', callbackData);

    const { status: atStatus, requestId: atRequestId, errorMessage, transactionId: atInternalTransactionId } = callbackData;

    if (!atRequestId) {
        logger.warn('⚠️ AT Airtime Status Callback: Missing requestId in payload.', { callbackData });
        return res.json({ status: 'error', message: 'Missing requestId' });
    }

    try {
        const salesSnapshot = await salesCollection
            .where('at_requestId', '==', atRequestId)
            .limit(1)
            .get();

        if (salesSnapshot.empty) {
            logger.warn(`⚠️ AT Airtime Status Callback: No matching sale found for requestId: ${atRequestId}.`, { callbackData });
            return res.json({ status: 'ignored', message: 'No matching sale found' });
        }

        const saleDocRef = salesSnapshot.docs[0].ref;
        const saleDocData = salesSnapshot.docs[0].data();
        const saleId = salesSnapshot.docs[0].id;
        const relatedTransactionId = saleDocData.relatedTransactionId;

        let newSaleStatus;
        let newTransactionStatus;
        let updateFields = {
            lastUpdated: FieldValue.serverTimestamp(),
            at_final_callback_data: callbackData,
            at_internal_transaction_id: atInternalTransactionId,
            errorMessage: errorMessage,
        };

        if (atStatus === 'Success') {
            newSaleStatus = 'COMPLETED';
            newTransactionStatus = 'COMPLETED_AND_FULFILLED';
            logger.info(`✅ AT Airtime for sale ${saleId} (AT Request ID: ${atRequestId}) confirmed SUCCESS.`);
            updateFields.status = newSaleStatus;
        } else if (atStatus === 'Failed' || atStatus === 'Rejected') {
            newSaleStatus = 'FAILED_DISPATCH_AT_CONFIRMATION';
            newTransactionStatus = 'RECEIVED_FULFILLMENT_FAILED';
            logger.error(`❌ AT Airtime for sale ${saleId} (AT Request ID: ${atRequestId}) FAILED: ${errorMessage || 'Unknown reason'}`);
            updateFields.status = newSaleStatus;
            updateFields.errorMessage = errorMessage || 'Africa\'s Talking reported failure.';

            if (relatedTransactionId && saleDocData.originalAmountPaid) {
                logger.warn(`🛑 AT dispatch failed for sale ${saleId}. Initiating Daraja reversal for TransID ${relatedTransactionId}.`);
                const reversalResult = await initiateDarajaReversal(relatedTransactionId, saleDocData.originalAmountPaid, saleDocData.payerMsisdn || null);
                if (reversalResult.success) {
                    logger.info(`✅ Daraja reversal initiated successfully for TransID ${relatedTransactionId} from AT callback.`);
                    await transactionsCollection.doc(relatedTransactionId).update({
                        status: 'REVERSAL_PENDING_CONFIRMATION_FROM_AT_FAILURE',
                        lastUpdated: FieldValue.serverTimestamp(),
                        reversalDetails: reversalResult.data,
                    });
                } else {
                    logger.error(`❌ Daraja reversal initiation failed from AT callback for TransID ${relatedTransactionId}: ${reversalResult.message}`);
                    await failedReconciliationsCollection.doc(relatedTransactionId).set({
                        transactionId: relatedTransactionId,
                        reversalAttemptedAt: FieldValue.serverTimestamp(),
                        reversalFailureDetails: reversalResult.error,
                        reason: `AT callback failure -> Reversal initiation failed: ${reversalResult.message}`,
                        createdAt: FieldValue.serverTimestamp(),
                    }, { merge: true });
                }
            } else {
                logger.warn(`⚠️ Could not initiate Daraja reversal for failed AT sale ${saleId}. Missing relatedTransactionId or originalAmountPaid.`, {
                    relatedTransactionId,
                    originalAmountPaid: saleDocData.originalAmountPaid
                });
            }
        } else {
            newSaleStatus = `AT_STATUS_${atStatus.toUpperCase()}`;
            newTransactionStatus = `PENDING_FULFILLMENT_AT_STATUS_${atStatus.toUpperCase()}`;
            logger.warn(`AT Airtime for sale ${saleId} (AT Request ID: ${atRequestId}) received UNEXPECTED status: ${atStatus}.`);
            updateFields.status = newSaleStatus;
        }

        await saleDocRef.update(updateFields);

        if (relatedTransactionId) {
            await transactionsCollection.doc(relatedTransactionId).update({
                status: newTransactionStatus,
                fulfillmentStatus: newSaleStatus,
                lastUpdated: FieldValue.serverTimestamp(),
            });
        }

        res.json({ status: 'success', message: 'Africa\'s Talking Airtime Status Callback processed.' });

    } catch (error) {
        logger.error(`❌ CRITICAL ERROR processing Africa's Talking Airtime Status Callback for requestId ${atRequestId || 'N/A'}:`, {
            message: error.message,
            stack: error.stack,
            callbackData: callbackData,
        });
        res.json({ status: 'error', message: 'Internal server error during callback processing.' });
    }
});


// Daraja Reversal Result Endpoint
app.post('/daraja-reversal-result', async (req, res) => {
    const reversalResult = req.body;
    logger.info('📞 Received Daraja Reversal Result Callback:', reversalResult);

    const { TransactionID, ResultCode, ResultDesc } = reversalResult;

    const transactionRef = transactionsCollection.doc(TransactionID);
    const transactionDoc = await transactionRef.get();

    if (!transactionDoc.exists) {
        logger.warn(`⚠️ Reversal result received for unknown TransID: ${TransactionID}`);
        return res.json({ "ResultCode": 0, "ResultDesc": "Acknowledged" });
    }

    if (ResultCode === '0') {
        logger.info(`✅ Reversal for TransID ${TransactionID} COMPLETED successfully.`);
        await transactionRef.update({
            status: 'REVERSED_SUCCESSFULLY',
            reversalConfirmationDetails: reversalResult,
            lastUpdated: FieldValue.serverTimestamp(),
        });
        await reconciledTransactionsCollection.doc(TransactionID).update({
            status: 'REVERSAL_CONFIRMED',
            reversalConfirmationDetails: reversalResult,
            lastUpdated: FieldValue.serverTimestamp(),
        });
    } else {
        logger.error(`❌ Reversal for TransID ${TransactionID} FAILED: ${ResultDesc}`);
        await transactionRef.update({
            status: 'REVERSAL_FAILED_CONFIRMATION',
            reversalConfirmationDetails: reversalResult,
            errorMessage: `Reversal failed: ${ResultDesc}`,
            lastUpdated: FieldValue.serverTimestamp(),
        });
        await failedReconciliationsCollection.doc(TransactionID).set({
            transactionId: TransactionID,
            reversalConfirmationDetails: reversalResult,
            reason: ResultDesc,
            createdAt: FieldValue.serverTimestamp(),
        }, { merge: true });
    }

    res.json({ "ResultCode": 0, "ResultDesc": "Reversal result processed." });
});

// Daraja Reversal Queue Timeout Endpoint
app.post('/daraja-reversal-timeout', async (req, res) => {
    const timeoutData = req.body;
    const { OriginatorConversationID, ConversationID, ResultCode, ResultDesc } = timeoutData;

    logger.warn('⚠️ Received Daraja Reversal Queue Timeout Callback:', {
        OriginatorConversationID: OriginatorConversationID,
        ConversationID: ConversationID,
        ResultCode: ResultCode,
        ResultDesc: ResultDesc,
        fullCallback: timeoutData
    });

    try {
        let transactionIdToUpdate = OriginatorConversationID;

        const originalTransactionRef = transactionsCollection.doc(transactionIdToUpdate);
        const originalTransactionDoc = await originalTransactionRef.get();

        if (originalTransactionDoc.exists) {
            logger.info(`Updating transaction ${transactionIdToUpdate} with reversal timeout status.`);
            await originalTransactionRef.update({
                status: 'REVERSAL_TIMED_OUT',
                reversalTimeoutDetails: timeoutData,
                lastUpdated: FieldValue.serverTimestamp(),
            });
        } else {
            logger.warn(`⚠️ Reversal Timeout received for unknown or unlinked TransID/OriginatorConversationID: ${transactionIdToUpdate}`);
        }

        await reversalTimeoutsCollection.add({
            transactionId: transactionIdToUpdate,
            originatorConversationId: OriginatorConversationID,
            conversationId: ConversationID,
            resultCode: ResultCode,
            resultDesc: ResultDesc,
            fullCallbackData: timeoutData,
            createdAt: FieldValue.serverTimestamp(),
        });

        logger.info(`✅ Daraja Reversal Queue Timeout processed for ${transactionIdToUpdate}.`);
        res.json({ "ResultCode": 0, "ResultDesc": "Daraja Reversal Queue Timeout Received and Processed." });

    } catch (error) {
        logger.error(`❌ CRITICAL ERROR processing Daraja Reversal Queue Timeout for ${OriginatorConversationID || 'N/A'}:`, {
            message: error.message,
            stack: error.stack,
            timeoutData: timeoutData
        });
        res.json({ "ResultCode": 0, "ResultDesc": "Internal server error during Queue Timeout processing." });
    }
});

// NEW AIRTIME BONUS API ENDPOINTS
const CURRENT_BONUS_DOC_PATH = 'airtime_bonuses/current_settings';

// GET current bonus percentages
app.get('/api/airtime-bonuses/current', async (req, res) => {
    try {
        const docRef = firestore.collection('airtime_bonuses').doc('current_settings');
        const docSnap = await docRef.get();

        if (docSnap.exists) {
            res.json(docSnap.data());
        } else {
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
    const { safaricomPercentage, africastalkingPercentage, actor } = req.body;

    if (typeof safaricomPercentage !== 'number' || typeof africastalkingPercentage !== 'number' || safaricomPercentage < 0 || africastalkingPercentage < 0) {
        logger.warn('Invalid bonus percentages received for update.', { safaricomPercentage, africastalkingPercentage });
        return res.status(400).json({ error: 'Invalid bonus percentages. Must be non-negative numbers.' });
    }

    try {
        const currentSettingsDocRef = firestore.collection('airtime_bonuses').doc('current_settings');
        const currentSettingsSnap = await currentSettingsDocRef.get();
        const oldSettings = currentSettingsSnap.exists ? currentSettingsSnap.data() : { safaricomPercentage: 0, africastalkingPercentage: 0 };

        const batch = firestore.batch();

        batch.set(currentSettingsDocRef, {
            safaricomPercentage: safaricomPercentage,
            africastalkingPercentage: africastalkingPercentage,
            lastUpdated: FieldValue.serverTimestamp(),
        }, { merge: true });

        if (safaricomPercentage !== oldSettings.safaricomPercentage) {
            batch.set(bonusHistoryCollection.doc(), {
                company: 'Safaricom',
                oldPercentage: oldSettings.safaricomPercentage || 0,
                newPercentage: safaricomPercentage,
                timestamp: FieldValue.serverTimestamp(),
                actor: actor || 'system',
            });
            logger.info(`Safaricom bonus changed from ${oldSettings.safaricomPercentage} to ${safaricomPercentage} by ${actor || 'system'}.`);
        }
        if (africastalkingPercentage !== oldSettings.africastalkingPercentage) {
            batch.set(bonusHistoryCollection.doc(), {
                company: 'AfricasTalking',
                oldPercentage: oldSettings.africastalkingPercentage || 0,
                newPercentage: africastalkingPercentage,
                timestamp: FieldValue.serverTimestamp(),
                actor: actor || 'system',
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

// Start the server
app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
    console.log(`Server running on port ${PORT}`);
});