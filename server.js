require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs')
const { Firestore, FieldValue } = require('@google-cloud/firestore'); // Import FieldValue
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const nodemailer = require('nodemailer');
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
const reconciledTransactionsCollection = firestore.collection('reconciled_transactions');
const failedReconciliationsCollection = firestore.collection('failed_reconciliations');
const reversalTimeoutsCollection = firestore.collection('reversal_timeouts'); // NEW: Initialize this collection
const bonusHistoryCollection = firestore.collection('bonus_history'); // NEW: Initialize this collection
const stkTransactionsCollection = firestore.collection('stk_Transactions');
const safaricomDealerConfigRef = firestore.collection('mpesa_settings').doc('main_config');

// --- Africa's Talking Initialization ---
const AfricasTalking = require('africastalking');
const africastalking = AfricasTalking({
    apiKey: process.env.AT_API_KEY,
    username: process.env.AT_USERNAME
});

// M-Pesa API Credentials from .env
const CONSUMER_KEY = process.env.CONSUMER_KEY;
const CONSUMER_SECRET = process.env.CONSUMER_SECRET;
const SHORTCODE = process.env.BUSINESS_SHORT_CODE; // Your Paybill/Till number
const PASSKEY = process.env.PASSKEY;
const STK_CALLBACK_URL = process.env.CALLBACK_URL; // Your public URL for /stk-callback
const ANALYTICS_SERVER_URL = process.env.ANALYTICS_SERVER_URL; // Your analytics server URL

// --- Middleware ---
app.use(helmet());
app.use(bodyParser.json({ limit: '1mb' }));
// Allow specific origins (recommended for production)
const allowedOrigins = [
    'https://www.daimapay.com',
    'https://daimapay-51406.web.app',
    'https://daimapay.web.app',
    'https://daimapay-wallet.web.app'
];
app.use(cors({
    origin: function (origin, callback) {
        // allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE', 
    credentials: true, 
    optionsSuccessStatus: 204 
}));

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


let cachedDarajaAccessToken = null;
let tokenExpiryTime = 0; // Timestamp when the current token expires

async function getDarajaAccessToken() {
    // Check if token is still valid
    if (cachedDarajaAccessToken && Date.now() < tokenExpiryTime) {
        logger.debug('🔑 Using cached Daraja access token.');
        return cachedDarajaAccessToken;
    }

    logger.info('🔑 Generating new Daraja access token...');
    try {
        const consumerKey = process.env.DARAJA_CONSUMER_KEY;
        const consumerSecret = process.env.DARAJA_CONSUMER_SECRET;
        const oauthUrl = process.env.DARAJA_OAUTH_URL;

        if (!consumerKey || !consumerSecret || !oauthUrl) {
            throw new Error("Missing Daraja API credentials or OAuth URL in environment variables.");
        }

        // Base64 encode consumer key and secret
        const authString = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');

        const response = await axios.get(oauthUrl, {
            headers: {
                Authorization: `Basic ${authString}`,
            },
        });

        const { access_token, expires_in } = response.data;

        if (access_token && expires_in) {
            cachedDarajaAccessToken = access_token;
            // Set expiry time a bit before the actual expiry to avoid using an expired token
            // Daraja tokens are usually valid for 3600 seconds (1 hour)
            tokenExpiryTime = Date.now() + (expires_in * 1000) - (60 * 1000); // 1 minute buffer
            logger.info(`✅ New Daraja access token generated. Expires in ${expires_in} seconds.`);
            return cachedDarajaAccessToken;
        } else {
            logger.error('❌ Daraja OAuth response did not contain access_token or expires_in:', response.data);
            throw new Error('Invalid Daraja OAuth response.');
        }
    } catch (error) {
        const errorDetails = error.response ? JSON.stringify(error.response.data) : error.message;
        logger.error(`❌ Failed to get Daraja access token: ${errorDetails}`);
        throw new Error(`Failed to obtain Daraja access token: ${errorDetails}`);
    }
}

//--BEGINING OF EMAIL FUNCTION --
// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, 
    pass: process.env.EMAIL_PASS, 
  }
});

app.post('/api/send-login-email', async (req, res) => {
  const { userEmail, userRole, timestamp } = req.body;

  if (!userEmail || !userRole || !timestamp) {
    return res.status(400).json({ error: 'All fields required' });
  }
    const mailOptions = {
    from: `"Login Alert" <no-reply@daimapay.com>`,
    to: 'team.daimapay@gmail.com',
    subject: `New Login Detected`,
    text: `User ${userEmail} logged in as ${userRole} at ${timestamp}`,
    html: `<p><strong>Email:</strong> ${userEmail}</p><p><strong>Role:</strong> ${userRole}</p><p><strong>Time:</strong> ${timestamp}</p>`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({ success: true, message: 'Email sent successfully' });
  } catch (err) {
    console.error('Email Error:', err);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

app.post('/api/notify-float-balance', async (req, res) => {
  const { to, floatBalance, threshold, telco } = req.body;

  // Input validation
  if (!to || !floatBalance || !telco) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  // Configure nodemailer transporter
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER, // Your Gmail address
      pass: process.env.EMAIL_PASS, // App password or real password (use app password for Gmail)
    },
  });

  // Email content
  const mailOptions = {
    from: `"DaimaPay Alerts" <${process.env.EMAIL_USER}>`,
    to,
    subject: `Float Balance Alert: ${telco}`,
    html: `
      <h2>Float Balance Notification</h2>
      <p><strong>Telco:</strong> ${telco}</p>
      <p><strong>Current Float Balance:</strong> Ksh ${Number(floatBalance).toLocaleString()}</p>
      ${threshold ? `<p><strong>Threshold:</strong> Ksh ${Number(threshold).toLocaleString()}</p>` : ''}
      <p>Please take necessary action if the balance is below the threshold.</p>
      <hr>
      <small>This is an automated message from DaimaPay.</small>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'Email sent successfully.' });
  } catch (err) {
    console.error('Email send error:', err);
    res.status(500).json({ error: 'Failed to send email notification.' });
  }
});
//-- END OF EMAIL --

//-- BEGINING OF ANALYTICS
const formatDate = (date) => date.toISOString().split('T')[0];
const getFloatCollectionId = (telco) => {
  if (telco === 'Safaricom') return 'Saf_float';
  if (['Airtel', 'Telkom', 'Africastalking'].includes(telco)) return 'AT_Float';
  return null;
};

const getIndividualFloatBalance = async (floatType) => {
  try {
    const doc = await firestore.collection(floatType).doc('current').get();
    return doc.exists ? doc.data().balance || 0 : 0;
  } catch (err) {
    console.error(`Error fetching ${floatType} float:`, err);
    return 0;
  }
};

// --- Time helpers ---
const getStartOfDayEAT = (date) => {
  const d = new Date(date);
  d.setUTCHours(0, 0, 0, 0);
  d.setUTCHours(d.getUTCHours() - 3);
  return Firestore.Timestamp.fromDate(d);
};
const getEndOfDayEAT = (date) => {
  const d = new Date(date);
  d.setUTCHours(23, 59, 59, 999);
  d.setUTCHours(d.getUTCHours() - 3);
  return Firestore.Timestamp.fromDate(d);
};
const getStartOfMonthEAT = (date) => {
  const d = new Date(date.getFullYear(), date.getMonth(), 1);
  d.setUTCHours(0, 0, 0, 0);
  d.setUTCHours(d.getUTCHours() - 3);
  return Firestore.Timestamp.fromDate(d);
};

// --- Classic sum fallback ---
async function sumSales(collectionRef) {
  const snap = await collectionRef.get();
  return snap.docs.reduce((sum, doc) => sum + (doc.data().amount || 0), 0);
}

// --- Main Sales Data Function ---
const getSalesOverviewData = async () => {
  const telcos = ['Safaricom', 'Airtel', 'Telkom'];
  const sales = {};
  const topPurchasers = {};
    
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);

  const startToday = getStartOfDayEAT(today);
  const endToday = getEndOfDayEAT(today);
  const startYesterday = getStartOfDayEAT(yesterday);
  const endYesterday = getEndOfDayEAT(yesterday);
  const startMonth = getStartOfMonthEAT(today);

  for (const telco of telcos) {
    // Today
    const todayRef = firestore.collection('sales')
      .where('status', 'in', ['COMPLETED', 'SUCCESS'])
      .where('carrier', '==', telco)
      .where('createdAt', '>=', startToday)
      .where('createdAt', '<=', endToday);
    const todayTotal = await sumSales(todayRef);
      
    // Yesterday
    const yestRef = firestore.collection('sales')
      .where('status', 'in', ['COMPLETED', 'SUCCESS'])
      .where('carrier', '==', telco)
      .where('createdAt', '>=', startYesterday)
      .where('createdAt', '<=', endYesterday);
    const yestTotal = await sumSales(yestRef);

    // This month
    const monthRef = firestore.collection('sales')
      .where('status', 'in', ['COMPLETED', 'SUCCESS'])
      .where('carrier', '==', telco)
      .where('createdAt', '>=', startMonth);
    const monthTotal = await sumSales(monthRef);

    const trend = yestTotal === 0
      ? (todayTotal > 0 ? 'up' : 'neutral')
      : (todayTotal >= yestTotal ? 'up' : 'down');

    sales[telco] = { today: todayTotal, month: monthTotal, trend };
      // Top purchasers
    const allRef = firestore.collection('sales')
      .where('carrier', '==', telco)
      .where('status', 'in', ['COMPLETED', 'SUCCESS']);
    const allSnap = await allRef.get();
    const buyers = {};
    allSnap.forEach(doc => {
      const { topupNumber, amount } = doc.data();
      if (topupNumber) buyers[topupNumber] = (buyers[topupNumber] || 0) + (amount || 0);
    });
    const top = Object.entries(buyers)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([name, Amount]) => ({ name, Amount }));
    topPurchasers[telco] = top;
  }

  return { sales, topPurchasers };
};

// --- Endpoints ---
app.get('/api/analytics/sales-overview', async (req, res) => {
  try {
    const { sales } = await getSalesOverviewData();
    res.json(sales);
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: 'Failed to load sales overview.' });
  }
});
app.post('/api/process-airtime-purchase', async (req, res) => {
  const { amount, status, telco, transactionId } = req.body;

  if (!amount || !status || !telco || !transactionId) {
    return res.status(400).json({ error: 'Missing fields.' });
  }

  if (!['COMPLETED', 'SUCCESS'].includes(status.toUpperCase())) {
    return res.json({ ok: true, note: 'No float deduction needed.' });
  }

  const floatCollectionId = getFloatCollectionId(telco);
  if (!floatCollectionId) {
    return res.status(400).json({ error: 'Unknown telco.' });
  }

  const floatRef = firestore.collection(floatCollectionId).doc('current');
    try {
    await firestore.runTransaction(async (tx) => {
      const doc = await tx.get(floatRef);
      if (!doc.exists) throw new Error('Float doc missing.');
      const current = doc.data().balance || 0;
      const newBal = current - amount;
      if (newBal < 0) throw new Error('Insufficient float.');
      tx.update(floatRef, { balance: newBal });
    });
    res.json({ ok: true, note: 'Float deducted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/analytics/dashboard', async (req, res) => {
  try {
    const { sales, topPurchasers } = await getSalesOverviewData();
    const saf = await getIndividualFloatBalance('Saf_float');
    const at = await getIndividualFloatBalance('AT_Float');

    const floatLogsSnap = await firestore.collection('floatLogs')
      .orderBy('timestamp', 'desc')
      .limit(50)
      .get();

    const floatLogs = floatLogsSnap.docs.map(doc => ({
      date: formatDate(doc.data().timestamp?.toDate?.() || new Date()),
      type: doc.data().type,
      Amount: doc.data().Amount,
      description: doc.data().description,
    }));

    res.json({
      sales,
      safFloatBalance: saf,
      atFloatBalance: at,
      floatBalance: saf + at,
      floatLogs,
      topPurchasers
    });
} catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load dashboard.' });
  }
});
   
//--END OF ANALYTICS --

// Function to get Daraja access token
async function getAccessToken() {
    const auth = Buffer.from(`${CONSUMER_KEY}:${CONSUMER_SECRET}`).toString('base64');
    try {
        const response = await axios.get('https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
            headers: {
                'Authorization': `Basic ${auth}`
            }
        });
        return response.data.access_token;
    } catch (error) {
        logger.error('Error getting access token:', error.message);
        throw new Error('Failed to get M-Pesa access token.');
    }
}

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

// Function to generate password for STK Push
function generatePassword(shortcode, passkey, timestamp) {
    const str = shortcode + passkey + timestamp;
    return Buffer.from(str).toString('base64');
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

        const rawDealerPin = await getDealerServicePin(); 
        const servicePin = await generateServicePin(rawDealerPin); 

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

        // --- CORRECTED: Check Safaricom API response status for actual success ---
        const isSuccess = response.data && response.data.responseStatus === '200';

        if (response.data && response.data.responseDesc) {
            const desc = response.data.responseDesc;
            const idMatch = desc.match(/^(R\d{6}\.\d{4}\.\d{6})/); // Regex for the transaction ID
            if (idMatch && idMatch[1]) {
                safaricomInternalTransId = idMatch[1];
            }
            const balanceMatch = desc.match(/New balance is Ksh\. (\d+(?:\.\d{2})?)/); // Regex for the balance
            if (balanceMatch && balanceMatch[1]) {
                newSafaricomFloatBalance = parseFloat(balanceMatch[1]);
            }
        }

        // Always log the full response from Safaricom for debugging purposes
        logger.info('✅ Safaricom dealer airtime API response:', { receiver: normalizedReceiver, amount: amount, response_data: response.data });

        if (isSuccess) {
            return {
                status: 'SUCCESS',
                message: 'Safaricom airtime sent',
                data: response.data,
                safaricomInternalTransId: safaricomInternalTransId,
                newSafaricomFloatBalance: newSafaricomFloatBalance,
            };
        } else {
            // If the status code indicates failure, return FAILED
            const errorMessage = `Safaricom Dealer API reported failure (Status: ${response.data.responseStatus || 'N/A'}): ${response.data.responseDesc || 'Unknown reason'}`;
            logger.warn(`⚠️ Safaricom dealer airtime send reported non-success:`, {
                receiver: receiverNumber,
                amount: amount,
                response_data: response.data,
                errorMessage: errorMessage
            });
            return {
                status: 'FAILED',
                message: errorMessage,
                error: response.data, // Provide the full response for debugging
            };
        }
    } catch (error) {
        logger.error('❌ Safaricom dealer airtime send failed (exception caught):', {
            receiver: receiverNumber,
            amount: amount,
            message: error.message,
            response_data: error.response ? error.response.data : 'N/A',
            stack: error.stack
        });
        return {
            status: 'FAILED',
            message: 'Safaricom airtime send failed due to network/API error',
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

function generateSecurityCredential(password) {
    const certificatePath = '/etc/secrets/ProductionCertificate.cer';

    try {
        console.log('🔹 Reading the public key certificate...');
        const publicKey = fs.readFileSync(certificatePath, 'utf8');

        console.log('✅ Certificate loaded successfully.');
        console.log('🔹 Encrypting the password...');
        const encryptedBuffer = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_PADDING,
            },
            Buffer.from(password, 'utf8')
        );

        return encryptedBuffer.toString('base64');
    } catch (error) {
        console.error('❌ Error generating security credential:', error.message);
        return null;
    }
}

// Helper function to notify the offline server (add this somewhere in your server.js)
async function notifyOfflineServerForFulfillment(transactionDetails) {
    try {
        const offlineServerUrl = process.env.OFFLINE_SERVER_FULFILLMENT_URL;
        if (!offlineServerUrl) {
            logger.error('OFFLINE_SERVER_FULFILLMENT_URL is not set in environment variables. Cannot notify offline server.');
            return { success: false, message: 'Offline server URL not configured.' };
        }

        // Send a POST request to your offline server
        const response = await axios.post(offlineServerUrl, transactionDetails);

        logger.info(`✅ Notified offline server for fulfillment of ${transactionDetails.checkoutRequestID}. Offline server response:`, response.data);
        return { success: true, responseData: response.data };

    } catch (error) {
        logger.error(`❌ Failed to notify offline server for fulfillment of ${transactionDetails.checkoutRequestID}:`, {
            message: error.message,
            statusCode: error.response ? error.response.status : 'N/A',
            responseData: error.response ? error.response.data : 'N/A',
            stack: error.stack
        });

         // Log this critical error to Firestore's errorsCollection
        await errorsCollection.add({
            type: 'OFFLINE_SERVER_NOTIFICATION_FAILED',
            checkoutRequestID: transactionDetails.checkoutRequestID,
            error: error.message,
            offlineServerResponse: error.response ? error.response.data : null,
            payloadSent: transactionDetails,
            createdAt: FieldValue.serverTimestamp(),
        });

        return { success: false, message: 'Failed to notify offline server.' };
    }
}

// --- NEW: Daraja Reversal Function ---
async function initiateDarajaReversal(transactionId, amount, receiverMsisdn) { 
    logger.info(`🔄 Attempting Daraja reversal for TransID: ${transactionId}, Amount: ${amount}`);
    try {
        const accessToken = await getDarajaAccessToken(); // Function to get Daraja access token

        if (!accessToken) {
            throw new Error("Failed to get Daraja access token for reversal.");
        }

        const url = process.env.MPESA_REVERSAL_URL; 
        const shortCode = process.env.MPESA_SHORTCODE; 
        const initiator = process.env.MPESA_INITIATOR_NAME; 
        const password=process.env.MPESA_SECURITY_PASSWORD;
        const securityCredential = generateSecurityCredential(password);  
        

        if (!url || !shortCode || !initiator || !securityCredential) {
            throw new Error("Missing Daraja reversal environment variables.");
        }

        const payload = {
            Initiator: initiator,
            SecurityCredential: securityCredential, // Use your actual security credential
            CommandID: "TransactionReversal",
            TransactionID: transactionId, // The M-Pesa TransID to be reversed
            Amount: amount, // The amount to reverse
            ReceiverParty: shortCode, // Your Short Code
            RecieverIdentifierType: "11",
            QueueTimeOutURL: process.env.MPESA_REVERSAL_QUEUE_TIMEOUT_URL, // URL for timeout callbacks
            ResultURL: process.env.MPESA_REVERSAL_RESULT_URL, // URL for result callbacks
            Remarks: `Airtime dispatch failed for ${transactionId}`,
            Occasion: "Failed Airtime Topup"
        };

        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        };

        const response = await axios.post(url, payload, { headers });

        logger.info(`✅ Daraja Reversal API response for TransID ${transactionId}:`, response.data);

        // Daraja reversal API typically returns a `ResponseCode` and `ResponseDescription`
        // A ResponseCode of '0' usually indicates that the request was accepted for processing.
        // The actual success/failure of the reversal happens asynchronously via the ResultURL.
        // For now, we'll consider '0' as "reversal initiated successfully".
        if (response.data && response.data.ResponseCode === '0') {
            return {
                success: true,
                message: "Reversal request accepted by Daraja.",
                data: response.data,
                // You might store the ConversationID for tracking if provided
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

// ---STK Functions ---

// --- RATE LIMITING ---
const stkPushLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 20, // Limit each IP to 20 requests per window
    message: 'Too many STK Push requests from this IP, please try again after a minute.',
    statusCode: 429,
    headers: true,
});

const stkCallbackRateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100, // M-Pesa can send multiple retries
    message: 'Too many STK Callback requests, please try again later.',
    statusCode: 429,
    headers: true,
});

// 1. STK Push Initiation Endpoint
app.post('/stk-push', stkPushLimiter, async (req, res) => {
    const { amount, phoneNumber, recipient, customerName, serviceType, reference } = req.body; // Added customerName, serviceType, reference for completeness

    if (!amount || !phoneNumber || !recipient) {
        logger.warn('Missing required parameters for STK Push:', { amount, phoneNumber, recipient });
        return res.status(400).json({ success: false, message: 'Missing required parameters: amount, phoneNumber, recipient.' });
    }

    const timestamp = generateTimestamp();
    const password = generatePassword(SHORTCODE, PASSKEY, timestamp);

    logger.info(`Initiating STK Push for recipient: ${recipient}, amount: ${amount}, customer: ${phoneNumber}`);

    // --- Input Validation (moved here for early exit) ---
    const MIN_AMOUNT = 5;
    const MAX_AMOUNT = 5000;
    const amountFloat = parseFloat(amount);

     if (isNaN(amountFloat) || amountFloat < MIN_AMOUNT || amountFloat > MAX_AMOUNT) {
        logger.warn(`🛑 Invalid amount ${amount} for STK Push. Amount must be between ${MIN_AMOUNT} and ${MAX_AMOUNT}.`);
        return res.status(400).json({ success: false, message: `Invalid amount. Must be between ${MIN_AMOUNT} and ${MAX_AMOUNT}.` });
    }

    const cleanedRecipient = recipient.replace(/\D/g, ''); // Ensure only digits
    const cleanedCustomerPhone = phoneNumber.replace(/\D/g, ''); // Ensure only digits

    if (!cleanedRecipient || !cleanedCustomerPhone || cleanedRecipient.length < 9 || cleanedCustomerPhone.length < 9) {
        logger.warn(`🛑 Invalid recipient (${recipient}) or customer phone (${phoneNumber}) for STK Push.`);
        return res.status(400).json({ success: false, message: "Invalid recipient or customer phone number format." });
    }

    const detectedCarrier = detectCarrier(cleanedRecipient); // Detect carrier at initiation
    if (detectedCarrier === 'Unknown') {
        logger.warn(`🛑 Unknown carrier for recipient ${cleanedRecipient}.`);
        return res.status(400).json({ success: false, message: "Recipient's carrier is not supported." });
    }

    // Declare CheckoutRequestID here, it will be set after Daraja response
    let CheckoutRequestID = null;

    try {
        const accessToken = await getAccessToken();

        const stkPushPayload = {
            BusinessShortCode: SHORTCODE,
            Password: password,
            Timestamp: timestamp,
            TransactionType: 'CustomerPayBillOnline', // Or 'CustomerBuyGoodsOnline' if applicable
            Amount: amountFloat, // Use the parsed float amount
            PartyA: cleanedCustomerPhone, // Customer's phone number
            PartyB: SHORTCODE, // Your Paybill/Till number
            PhoneNumber: cleanedCustomerPhone, // Customer's phone number
            CallBackURL: STK_CALLBACK_URL,
            AccountReference: cleanedRecipient, // Use recipient number as account reference
            TransactionDesc: `Airtime for ${cleanedRecipient}`
        };

        const stkPushResponse = await axios.post(
            'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            stkPushPayload,
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                     'Content-Type': 'application/json' // Explicitly set Content-Type
                }
            }
        );

        logger.info('STK Push Request Sent to Daraja:', stkPushResponse.data);

        const {
            ResponseCode,
            ResponseDescription,
            CustomerMessage,
            CheckoutRequestID: darajaCheckoutRequestID, // Rename to avoid conflict with outer scope
            MerchantRequestID
        } = stkPushResponse.data;

        // Assign Daraja's CheckoutRequestID to the outer scope variable
        CheckoutRequestID = darajaCheckoutRequestID;

        // ONLY create the stk_transaction document if M-Pesa successfully accepted the push request
        if (ResponseCode === '0') {
            await stkTransactionsCollection.doc(CheckoutRequestID).set({
                checkoutRequestID: CheckoutRequestID,
                merchantRequestID: MerchantRequestID, // Populate directly here
                phoneNumber: cleanedCustomerPhone, // The number that received the STK Push
                amount: amountFloat, // Use amountFloat for consistency
                recipient: cleanedRecipient, // Crucial: Store the intended recipient here
                carrier: detectedCarrier, // Assuming you detect carrier during initial request
                initialRequestAt: FieldValue.serverTimestamp(),
                stkPushStatus: 'PUSH_INITIATED', // Initial status
                stkPushPayload: stkPushPayload, // Store the payload sent to Daraja
                darajaResponse: stkPushResponse.data, // Store full Daraja response here
                customerName: customerName || null,
                serviceType: serviceType || 'airtime',
                reference: reference || null,
                lastUpdated: FieldValue.serverTimestamp(), // Add lastUpdated here too
            });
            logger.info(`✅ STK Transaction document ${CheckoutRequestID} created with STK Push initiation response.`);

            return res.status(200).json({ success: true, message: CustomerMessage, checkoutRequestID: CheckoutRequestID });

        } else {
            // M-Pesa did not accept the push request (e.g., invalid number, insufficient balance in your shortcode)
            logger.error('❌ STK Push Request Failed by Daraja:', stkPushResponse.data);
            // Log this failure in errors collection
            await errorsCollection.add({
                type: 'STK_PUSH_INITIATION_FAILED_BY_DARJA',
                error: ResponseDescription,
                requestPayload: stkPushPayload,
                mpesaResponse: stkPushResponse.data,
                createdAt: FieldValue.serverTimestamp(),
                checkoutRequestID: CheckoutRequestID, // Log this ID even if no record was created for it
            });

            // No stk_transaction document created if Daraja rejected the request
            return res.status(500).json({ success: false, message: ResponseDescription || 'STK Push request failed.' });
        }

    } catch (error) {
        logger.error('❌ Critical error during STK Push initiation:', {
            message: error.message,
            stack: error.stack,
            requestBody: req.body,
            responseError: error.response ? error.response.data : 'No response data'
        });

        const errorMessage = error.response ? (error.response.data.errorMessage || error.response.data.MpesaError || error.response.data) : error.message;

        await errorsCollection.add({
            type: 'STK_PUSH_CRITICAL_INITIATION_ERROR',
            error: errorMessage,
            requestBody: req.body,
            stack: error.stack,
            createdAt: FieldValue.serverTimestamp(),
            checkoutRequestID: CheckoutRequestID || 'N/A', // Log the ID if available
        });

        res.status(500).json({ success: false, message: 'Failed to initiate STK Push.', error: errorMessage });
    }
}); 

// Modified STK Callback Endpoint
app.post('/stk-callback', async (req, res) => {
    const callback = req.body;
    logger.info('📞 Received STK Callback:', JSON.stringify(callback, null, 2)); // Log full callback for debugging

    // Safaricom sends an empty object on initial push confirmation before payment
    if (!callback || !callback.Body || !callback.Body.stkCallback) {
        logger.warn('Received an empty or malformed STK callback. Ignoring.');
        // Always respond with ResultCode 0 to M-Pesa to acknowledge receipt and prevent retries.
        return res.json({ ResultCode: 0, ResultDesc: 'Callback processed (ignored empty/malformed).' });
    }

    const { MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc, CallbackMetadata } = callback.Body.stkCallback;

    // Extracting relevant data from the callback
    const amount = CallbackMetadata?.Item.find(item => item.Name === 'Amount')?.Value;
    const mpesaReceiptNumber = CallbackMetadata?.Item.find(item => item.Name === 'MpesaReceiptNumber')?.Value;
    const transactionDate = CallbackMetadata?.Item.find(item => item.Name === 'TransactionDate')?.Value;
    const customerPhoneNumber = CallbackMetadata?.Item.find(item => item.Name === 'PhoneNumber')?.Value; // PartyA's phone

    // --- Retrieve the STK transaction record ---
    // This is the *only* collection the STK server should read/update now.
    const stkTransactionDocRef = stkTransactionsCollection.doc(CheckoutRequestID);
    const stkTransactionDoc = await stkTransactionDocRef.get();

    if (!stkTransactionDoc.exists) {
        logger.error(`❌ No matching STK transaction record for CheckoutRequestID (${CheckoutRequestID}) found in 'stk_transactions' collection.`);
        // Respond with success to M-Pesa to prevent retries of this unknown callback,
        // but log for manual investigation.
        return res.json({ ResultCode: 0, ResultDesc: 'No matching STK transaction record found.' });
    }
        
    const stkTransactionData = stkTransactionDoc.data();
    // Get original recipient and carrier from the initial STK Push record
    const originalRecipient = stkTransactionData.recipient;
    const originalCarrier = stkTransactionData.carrier;
    const originalAmountRequested = stkTransactionData.amount; // The amount initially requested for the push

    // Prepare common update data for stk_transactions
    const commonStkUpdateData = {
        mpesaResultCode: ResultCode,
        mpesaResultDesc: ResultDesc,
        mpesaCallbackMetadata: CallbackMetadata, // Store full metadata
        customerPhoneNumber: customerPhoneNumber, // From M-Pesa callback (PartyA)
        lastUpdated: FieldValue.serverTimestamp(),
    };

    // Check M-Pesa ResultCode for success
    if (ResultCode === 0) {
        logger.info(`✅ M-Pesa payment successful for ${CheckoutRequestID}. Updating 'stk_transactions' and notifying offline server.`);

        const successfulStkUpdateData = {
            ...commonStkUpdateData,
            mpesaPaymentStatus: 'SUCCESSFUL',
             mpesaReceiptNumber: mpesaReceiptNumber,
            mpesaTransactionDate: transactionDate,
            amountConfirmed: amount, // Amount from M-Pesa callback
            stkPushStatus: 'MPESA_PAYMENT_SUCCESS', // Final STK transaction status on STK server
        };

        try {
            await stkTransactionDocRef.update(successfulStkUpdateData);
            logger.info(`✅ STK transaction document ${CheckoutRequestID} updated with MPESA_PAYMENT_SUCCESS status.`);


            // Always respond to M-Pesa with ResultCode 0 to acknowledge receipt of the callback.
            return res.json({ ResultCode: 0, ResultDesc: 'Callback received and processing for external fulfillment initiated.' });

        } catch (updateError) {
            logger.error(`❌ Error updating 'stk_transactions' or notifying offline server for ${CheckoutRequestID}:`, { message: updateError.message, stack: updateError.stack });
            await errorsCollection.add({
                type: 'STK_CALLBACK_UPDATE_OR_NOTIFICATION_ERROR',
                checkoutRequestID: CheckoutRequestID,
                error: updateError.message,
                stack: updateError.stack,
                callbackData: callback,
                createdAt: FieldValue.serverTimestamp(),
            });
            // Still respond success to M-Pesa to prevent retries (you'll handle the error internally)
            return res.json({ ResultCode: 0, ResultDesc: 'Callback processed with internal error during update/notification.' });
        }

    } else {
        // M-Pesa payment failed or was cancelled by user
        logger.warn(`⚠️ M-Pesa payment failed or cancelled for ${CheckoutRequestID}. ResultCode: ${ResultCode}, ResultDesc: ${ResultDesc}`);
        const failedStkUpdateData = {
            ...commonStkUpdateData,
            mpesaPaymentStatus: 'FAILED_OR_CANCELLED',
            stkPushStatus: 'MPESA_PAYMENT_FAILED', // Final STK transaction status on STK server
        };

        try {
            // Update only the stk_transactions document for failed/cancelled payments
            await stkTransactionDocRef.update(failedStkUpdateData);
            logger.info(`✅ STK transaction document updated for failed/cancelled payment for ${CheckoutRequestID}.`);
        } catch (error) {
            logger.error(`❌ Error updating 'stk_transactions' for failed/cancelled STK payment ${CheckoutRequestID}:`, { message: error.message, stack: error.stack });
            await errorsCollection.add({
                type: 'STK_CALLBACK_FAILED_PAYMENT_UPDATE_ERROR',
                checkoutRequestID: CheckoutRequestID,
                error: error.message,
                stack: error.stack,
                callbackData: callback,
                createdAt: FieldValue.serverTimestamp(),
            });
        }
        // Always respond with ResultCode 0 to M-Pesa even for failed payments, to acknowledge receipt of the callback.
        return res.json({ ResultCode: 0, ResultDesc: 'Payment failed/cancelled. Callback processed.' });
    }
});

// --- C2B (Offline Paybill) Callbacks ---
/**
 * Processes the airtime fulfillment for a given transaction.
 * This function is designed to be called by both C2B confirmation and STK Push callback.
 *
 * @param {object} params - The parameters for fulfillment.
 * @param {string} params.transactionId - The unique M-Pesa transaction ID (TransID or CheckoutRequestID).
 * @param {number} params.originalAmountPaid - The original amount paid by the customer.
 * @param {string} params.payerMsisdn - The phone number of the customer who paid.
 * @param {string} params.payerName - The name of the customer (optional, can be null for STK Push).
 * @param {string} params.topupNumber - The recipient phone number for airtime.
 * @param {string} params.sourceCallbackData - The raw callback data from M-Pesa (C2B or STK Push).
 * @param {string} params.requestType - 'C2B' or 'STK_PUSH' to differentiate logging/storage.
 * @param {string|null} [params.relatedSaleId=null] - Optional: saleId if already created (e.g., from STK Push initial request).
 * @returns {Promise<object>} - An object indicating success/failure and final status.
 */
async function processAirtimeFulfillment({
    transactionId,
    originalAmountPaid,
    payerMsisdn,
    payerName,
    topupNumber,
    sourceCallbackData,
    requestType,
    relatedSaleId = null
}) {
    const now = FieldValue.serverTimestamp(); // Use server timestamp for consistency
    logger.info(`Starting airtime fulfillment for ${requestType} transaction: ${transactionId}`);

    let airtimeDispatchStatus = 'FAILED';
    let airtimeDispatchResult = null;
    let saleErrorMessage = null;
    let airtimeProviderUsed = null;
    let finalSaleId = relatedSaleId; // Use existing saleId if provided

    try {
        // --- Input Validation (amount range - moved from C2B, now applies to both) ---
        // Note: For STK Push, amount validation happens before dispatch.
        // For C2B, it's here because the initial recording happens before this logic.
        const MIN_AMOUNT = 5;
        const MAX_AMOUNT = 5000;
        const amountInt = Math.round(parseFloat(originalAmountPaid));

        if (amountInt < MIN_AMOUNT || amountInt > MAX_AMOUNT) {
            const errorMessage = `Transaction amount ${amountInt} is outside allowed range (${MIN_AMOUNT} - ${MAX_AMOUNT}).`;
            logger.warn(`🛑 ${errorMessage} Initiating reversal for ${transactionId}.`);
            await errorsCollection.add({
                type: 'AIRTIME_FULFILLMENT_ERROR',
                subType: 'INVALID_AMOUNT_RANGE',
                error: errorMessage,
                transactionId: transactionId,
                originalAmount: originalAmountPaid,
                payerMsisdn: payerMsisdn,
                topupNumber: topupNumber,
                requestType: requestType,
                createdAt: now,
            });

            // Update transaction status before attempting reversal
            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FULFILLMENT_FAILED',
                fulfillmentStatus: 'FAILED_INVALID_AMOUNT',
                errorMessage: errorMessage,
                lastUpdated: now,
            });

            const reversalResult = await initiateDarajaReversal(transactionId, originalAmountPaid, payerMsisdn);
            if (reversalResult.success) {
                logger.info(`✅ Reversal initiated for invalid amount ${amountInt} on transaction ${transactionId}`);
                await reconciledTransactionsCollection.doc(transactionId).set({
                    transactionId: transactionId,
                    amount: originalAmountPaid,
                    mpesaNumber: payerMsisdn,
                    reversalInitiatedAt: now,
                    reversalRequestDetails: reversalResult.data,
                    originalCallbackData: sourceCallbackData,
                    status: 'REVERSAL_INITIATED',
                    createdAt: now,
                }, { merge: true });
                await transactionsCollection.doc(transactionId).update({
                    status: 'REVERSAL_PENDING_CONFIRMATION',
                    lastUpdated: now,
                    reversalDetails: reversalResult.data,
                    errorMessage: reversalResult.message,
                    reversalAttempted: true,
                });
                return { success: true, status: 'REVERSAL_INITIATED_INVALID_AMOUNT' }; // Return success as reversal was initiated
            } else {
                logger.error(`❌ Reversal failed for invalid amount ${amountInt} for ${transactionId}: ${reversalResult.message}`);
                await failedReconciliationsCollection.doc(transactionId).set({
                    transactionId: transactionId,
                    amount: originalAmountPaid,
                    mpesaNumber: payerMsisdn,
                    reversalAttemptedAt: now,
                    reversalFailureDetails: reversalResult.error,
                    originalCallbackData: sourceCallbackData,
                    reason: `Reversal initiation failed for invalid amount: ${reversalResult.message}`,
                    createdAt: now,
                }, { merge: true });
                await transactionsCollection.doc(transactionId).update({
                    status: 'REVERSAL_INITIATION_FAILED',
                    lastUpdated: now,
                    reversalDetails: reversalResult.error,
                    errorMessage: `Reversal initiation failed for invalid amount: ${reversalResult.message}`,
                    reversalAttempted: true,
                });
                return { success: false, status: 'REVERSAL_FAILED_INVALID_AMOUNT', error: reversalResult.message };
            }
        }


        // --- Determine target carrier ---
        const targetCarrier = detectCarrier(topupNumber);
        if (targetCarrier === 'Unknown') {
            const errorMessage = `Unsupported carrier prefix for airtime top-up: ${topupNumber}`;
            logger.error(`❌ ${errorMessage}`, { TransID: transactionId, topupNumber: topupNumber });
            await errorsCollection.add({
                type: 'AIRTIME_FULFILLMENT_ERROR',
                subType: 'UNKNOWN_CARRIER',
                error: errorMessage,
                transactionId: transactionId,
                requestType: requestType,
                createdAt: now,
            });
            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FULFILLMENT_FAILED',
                fulfillmentStatus: 'FAILED_UNKNOWN_CARRIER',
                errorMessage: errorMessage,
                lastUpdated: now,
            });
            return { success: false, status: 'FAILED_UNKNOWN_CARRIER', error: errorMessage };
        }

        // --- FETCH BONUS SETTINGS AND CALCULATE FINAL AMOUNT TO DISPATCH ---
        const bonusDocRef = firestore.collection('airtime_bonuses').doc('current_settings');
        const bonusDocSnap = await bonusDocRef.get();

        let safaricomBonus = 0;
        let atBonus = 0;

        if (bonusDocSnap.exists) {
            safaricomBonus = bonusDocSnap.data()?.safaricomPercentage ?? 0;
            atBonus = bonusDocSnap.data()?.africastalkingPercentage ?? 0;
        } else {
            logger.warn('Bonus settings document does not exist. Skipping bonus application.');
        }

        let finalAmountToDispatch = originalAmountPaid;
        let bonusApplied = 0;

        // Custom rounding: 0.1–0.4 => 0, 0.5–0.9 => 1
        const customRound = (value) => {
            const decimalPart = value % 1;
            const integerPart = Math.floor(value);
            return decimalPart >= 0.5 ? integerPart + 1 : integerPart;
        };

        // Apply bonus with optional rounding
        const applyBonus = (amount, percentage, label, round = false) => {
            const rawBonus = amount * (percentage / 100);
            const bonus = round ? customRound(rawBonus) : rawBonus;
            const total = amount + bonus;
            logger.info(
                `Applying ${percentage}% ${label} bonus. Original: ${amount}, Bonus: ${bonus} (${round ? 'rounded' : 'raw'}), Final: ${total}`
            );
            return { total, bonus, rawBonus };
        };

        // Normalize carrier name to lowercase
        const carrierNormalized = targetCarrier.toLowerCase();

        if (carrierNormalized === 'safaricom' && safaricomBonus > 0) {
            const result = applyBonus(originalAmountPaid, safaricomBonus, 'Safaricom', false); // No rounding
            finalAmountToDispatch = result.total;
            bonusApplied = result.rawBonus;
        } else if (['airtel', 'telkom', 'equitel', 'faiba'].includes(carrierNormalized) && atBonus > 0) {
            const result = applyBonus(originalAmountPaid, atBonus, 'AfricasTalking', true); // Use custom rounding
            finalAmountToDispatch = result.total;
            bonusApplied = result.bonus;
        }

        logger.info(`Final amount to dispatch for ${transactionId}: ${finalAmountToDispatch}`);

        // --- Initialize or Update sale document ---
        const saleData = {
            relatedTransactionId: transactionId,
            topupNumber: topupNumber,
            originalAmountPaid: originalAmountPaid,
            amount: finalAmountToDispatch, // This is the amount actually dispatched (original + bonus)
            bonusApplied: bonusApplied, // Store the bonus amount
            carrier: targetCarrier, // Use the detected carrier
            status: 'PENDING_DISPATCH',
            dispatchAttemptedAt: now,
            lastUpdated: now,
            requestType: requestType, // C2B or STK_PUSH
            // createdAt will be set if this is a new document, or remain if it's an update
        };

        if (finalSaleId) {
            // If relatedSaleId exists (from STK Push initial request), update it
            const saleDoc = await salesCollection.doc(finalSaleId).get();
            if (saleDoc.exists) {
                await salesCollection.doc(finalSaleId).update(saleData);
                logger.info(`✅ Updated existing sale document ${finalSaleId} for TransID ${transactionId} with fulfillment details.`);
            } else {
                // If ID was provided but document doesn't exist (e.g., deleted), create new one
                const newSaleRef = salesCollection.doc();
                finalSaleId = newSaleRef.id;
                await newSaleRef.set({ saleId: finalSaleId, createdAt: now, ...saleData });
                logger.warn(`⚠️ Sale document ${relatedSaleId} not found. Created new sale document ${finalSaleId} for TransID ${transactionId}.`);
            }
        } else {
            // Create a new sale document (typical for C2B)
            const newSaleRef = salesCollection.doc();
            finalSaleId = newSaleRef.id;
            await newSaleRef.set({ saleId: finalSaleId, createdAt: now, ...saleData });
            logger.info(`✅ Initialized new sale document ${finalSaleId} in 'sales' collection for TransID ${transactionId}.`);
        }

        // --- Conditional Airtime Dispatch Logic based on Carrier ---
        if (targetCarrier === 'Safaricom') {
            try {
                await updateCarrierFloatBalance('safaricomFloat', -finalAmountToDispatch);
                airtimeProviderUsed = 'SafaricomDealer';
                airtimeDispatchResult = await sendSafaricomAirtime(topupNumber, finalAmountToDispatch);

                if (airtimeDispatchResult && airtimeDispatchResult.status === 'SUCCESS') {
                    airtimeDispatchStatus = 'COMPLETED';
                    logger.info(`✅ Safaricom airtime successfully sent via Dealer Portal for sale ${finalSaleId}.`);
                } else {
                    saleErrorMessage = airtimeDispatchResult?.error || 'Safaricom Dealer Portal failed with unknown error.';
                    logger.warn(`⚠️ Safaricom Dealer Portal failed for TransID ${transactionId}. Attempting fallback to Africastalking. Error: ${saleErrorMessage}`);

                    // Refund Safaricom float, as primary attempt failed
                    await updateCarrierFloatBalance('safaricomFloat', finalAmountToDispatch);
                    logger.info(`✅ Refunded Safaricom float for TransID ${transactionId}: +${finalAmountToDispatch}`);

                    // Attempt fallback via Africa's Talking (debit AT float)
                    await updateCarrierFloatBalance('africasTalkingFloat', -finalAmountToDispatch);
                    airtimeProviderUsed = 'AfricasTalkingFallback';
                    airtimeDispatchResult = await sendAfricasTalkingAirtime(topupNumber, finalAmountToDispatch, targetCarrier);

                    if (airtimeDispatchResult && airtimeDispatchResult.status === 'SUCCESS') {
                        airtimeDispatchStatus = 'COMPLETED';
                        logger.info(`✅ Safaricom fallback airtime successfully sent via AfricasTalking for sale ${finalSaleId}.`);
                        // NEW: Adjust Africa's Talking float for 4% commission
                        const commissionAmount = parseFloat((originalAmountPaid * 0.04).toFixed(2));
                        await updateCarrierFloatBalance('africasTalkingFloat', commissionAmount);
                        logger.info(`✅ Credited Africa's Talking float with ${commissionAmount} (4% commission) for TransID ${transactionId}.`);
                    } else {
                        saleErrorMessage = airtimeDispatchResult ? airtimeDispatchResult.error : 'AfricasTalking fallback failed with no specific error.';
                        logger.error(`❌ Safaricom fallback via AfricasTalking failed for sale ${finalSaleId}: ${saleErrorMessage}`);
                    }
                }
            } catch (dispatchError) {
                saleErrorMessage = `Safaricom primary dispatch process failed (or float debit failed): ${dispatchError.message}`;
                logger.error(`❌ Safaricom primary dispatch process failed for TransID ${transactionId}: ${dispatchError.message}`);
            }

        } else if (['Airtel', 'Telkom', 'Equitel', 'Faiba'].includes(targetCarrier)) {
            // Directly dispatch via Africa's Talking
            try {
                await updateCarrierFloatBalance('africasTalkingFloat', -finalAmountToDispatch);
                airtimeProviderUsed = 'AfricasTalkingDirect';
                airtimeDispatchResult = await sendAfricasTalkingAirtime(topupNumber, finalAmountToDispatch, targetCarrier);

                if (airtimeDispatchResult && airtimeDispatchResult.status === 'SUCCESS') {
                    airtimeDispatchStatus = 'COMPLETED';
                    logger.info(`✅ AfricasTalking airtime successfully sent directly for sale ${finalSaleId}.`);
                    // NEW: Adjust Africa's Talking float for 4% commission
                    const commissionAmount = parseFloat((originalAmountPaid * 0.04).toFixed(2));
                    await updateCarrierFloatBalance('africasTalkingFloat', commissionAmount);
                    logger.info(`✅ Credited Africa's Talking float with ${commissionAmount} (4% commission) for TransID ${transactionId}.`);
                } else {
                    saleErrorMessage = airtimeDispatchResult ? airtimeDispatchResult.Safaricom : 'AfricasTalking direct dispatch failed with no specific error.';
                    logger.error(`❌ AfricasTalking direct dispatch failed for sale ${finalSaleId}: ${saleErrorMessage}`);
                }
            } catch (dispatchError) {
                saleErrorMessage = `AfricasTalking direct dispatch process failed (or float debit failed): ${dispatchError.message}`;
                logger.error(`❌ AfricasTalking direct dispatch process failed for TransID ${transactionId}: ${dispatchError.message}`);
            }
        } else {
            // This case should ideally be caught by the initial detectCarrier check, but good for robustness
            saleErrorMessage = `No valid dispatch path for carrier: ${targetCarrier}`;
            logger.error(`❌ ${saleErrorMessage} for TransID ${transactionId}`);
            await errorsCollection.add({
                type: 'AIRTIME_FULFILLMENT_ERROR',
                subType: 'NO_DISPATCH_PATH',
                error: saleErrorMessage,
                transactionId: transactionId,
                requestType: requestType,
                createdAt: now,
            });
        }

        const updateSaleFields = {
            lastUpdated: now,
            dispatchResult: airtimeDispatchResult?.data || airtimeDispatchResult?.error || airtimeDispatchResult,
            airtimeProviderUsed: airtimeProviderUsed,
        };

        // If airtime dispatch was COMPLETELY successful
        if (airtimeDispatchStatus === 'COMPLETED') {
            updateSaleFields.status = airtimeDispatchStatus;

            // Only update Safaricom float balance from API response if Safaricom Dealer was used and successful
            if (targetCarrier === 'Safaricom' && airtimeDispatchResult && airtimeDispatchResult.newSafaricomFloatBalance !== undefined && airtimeProviderUsed === 'SafaricomDealer') {
                try {
                    await safaricomFloatDocRef.update({
                        balance: airtimeDispatchResult.newSafaricomFloatBalance,
                        lastUpdated: now
                    });
                    logger.info(`✅ Safaricom float balance directly updated from API response for TransID ${transactionId}. New balance: ${airtimeDispatchResult.newSafaricomFloatBalance}`);
                } catch (floatUpdateErr) {
                    logger.error(`❌ Failed to directly update Safaricom float from API response for TransID ${transactionId}:`, {
                        error: floatUpdateErr.message, reportedBalance: airtimeDispatchResult.newSafaricomFloatBalance
                    });
                    const reportedBalanceForError = airtimeDispatchResult.newSafaricomFloatBalance !== undefined ? airtimeDispatchResult.newSafaricomFloatBalance : 'N/A';
                    await errorsCollection.add({
                        type: 'FLOAT_RECONCILIATION_WARNING',
                        subType: 'SAFARICOM_REPORTED_BALANCE_UPDATE_FAILED',
                        error: `Failed to update Safaricom float with reported balance: ${floatUpdateErr.message}`,
                        transactionId: transactionId,
                        saleId: finalSaleId,
                        reportedBalance: reportedBalanceForError,
                        createdAt: now,
                    });
                }
            }
            await salesCollection.doc(finalSaleId).update(updateSaleFields);
            logger.info(`✅ Updated sale document ${finalSaleId} with dispatch result (COMPLETED).`);

            // Also update the main transaction status to fulfilled
            await transactionsCollection.doc(transactionId).update({
                status: 'COMPLETED_AND_FULFILLED',
                fulfillmentStatus: airtimeDispatchStatus,
                fulfillmentDetails: airtimeDispatchResult,
                lastUpdated: now,
                airtimeProviderUsed: airtimeProviderUsed,
            });
            logger.info(`✅ Transaction ${transactionId} marked as COMPLETED_AND_FULFILLED.`);
            return { success: true, status: 'COMPLETED_AND_FULFILLED' };

        } else {
            // Airtime dispatch ultimately failed (either primary or fallback)
            saleErrorMessage = saleErrorMessage || 'Airtime dispatch failed with no specific error message.';
            logger.error(`❌ Airtime dispatch ultimately failed for sale ${finalSaleId} (TransID ${transactionId}):`, {
                error_message: saleErrorMessage,
                carrier: targetCarrier,
                topupNumber: topupNumber,
                originalAmountPaid: originalAmountPaid,
                finalAmountDispatched: finalAmountToDispatch,
                airtimeResponse: airtimeDispatchResult,
                sourceCallbackData: sourceCallbackData,
            });
            await errorsCollection.add({
                type: 'AIRTIME_FULFILLMENT_ERROR',
                subType: 'AIRTIME_DISPATCH_FAILED',
                error: saleErrorMessage,
                transactionId: transactionId,
                saleId: finalSaleId,
                sourceCallbackData: sourceCallbackData,
                airtimeApiResponse: airtimeDispatchResult,
                providerAttempted: airtimeProviderUsed,
                requestType: requestType,
                createdAt: now,
            });

            updateSaleFields.status = 'FAILED_DISPATCH_API';
            updateSaleFields.errorMessage = saleErrorMessage;
            await salesCollection.doc(finalSaleId).update(updateSaleFields);
            logger.info(`✅ Updated sale document ${finalSaleId} with dispatch result (FAILED).`);

            // --- Initiate Reversal if airtime dispatch failed ---
            logger.warn(`🛑 Airtime dispatch ultimately failed for TransID ${transactionId}. Initiating Daraja reversal.`);

            // Update main transaction status to reflect immediate failure
            await transactionsCollection.doc(transactionId).update({
                status: 'RECEIVED_FULFILLMENT_FAILED',
                fulfillmentStatus: 'FAILED_DISPATCH_API',
                fulfillmentDetails: airtimeDispatchResult,
                errorMessage: saleErrorMessage,
                lastUpdated: now,
                airtimeProviderUsed: airtimeProviderUsed,
                reversalAttempted: true,
            });

            const reversalResult = await initiateDarajaReversal(transactionId, originalAmountPaid, payerMsisdn);

            if (reversalResult.success) {
                logger.info(`✅ Daraja reversal initiated successfully for TransID ${transactionId}.`);
                await reconciledTransactionsCollection.doc(transactionId).set({
                    transactionId: transactionId,
                    amount: originalAmountPaid,
                    mpesaNumber: payerMsisdn,
                    reversalInitiatedAt: now,
                    reversalRequestDetails: reversalResult.data,
                    originalCallbackData: sourceCallbackData,
                    status: 'REVERSAL_INITIATED',
                    createdAt: now,
                }, { merge: true });
                await transactionsCollection.doc(transactionId).update({
                    status: 'REVERSAL_PENDING_CONFIRMATION',
                    lastUpdated: now,
                    reversalDetails: reversalResult.data,
                    errorMessage: reversalResult.message,
                });
                return { success: true, status: 'REVERSAL_INITIATED' };
            } else {
                logger.error(`❌ Daraja reversal failed to initiate for TransID ${transactionId}: ${reversalResult.message}`);
                await failedReconciliationsCollection.doc(transactionId).set({
                    transactionId: transactionId,
                    amount: originalAmountPaid,
                    mpesaNumber: payerMsisdn,
                    reversalAttemptedAt: now,
                    reversalFailureDetails: reversalResult.error,
                    originalCallbackData: sourceCallbackData,
                    reason: reversalResult.message,
                    createdAt: now,
                }, { merge: true });
                await transactionsCollection.doc(transactionId).update({
                    status: 'REVERSAL_INITIATION_FAILED',
                    lastUpdated: now,
                    reversalDetails: reversalResult.error,
                    errorMessage: `Reversal initiation failed: ${reversalResult.message}`
                });
                return { success: false, status: 'REVERSAL_INITIATION_FAILED', error: reversalResult.message };
            }
        }
    } catch (error) {
        logger.error(`❌ CRITICAL ERROR during Airtime Fulfillment for TransID ${transactionId}:`, {
            message: error.message,
            stack: error.stack,
            sourceCallbackData: sourceCallbackData,
            requestType: requestType,
        });

        // Ensure main transaction record reflects critical error
        if (transactionId) {
            try {
                await transactionsCollection.doc(transactionId).update({
                    status: 'CRITICAL_FULFILLMENT_ERROR',
                    errorMessage: `Critical server error during airtime fulfillment: ${error.message}`,
                    lastUpdated: now,
                });
            } catch (updateError) {
                logger.error(`❌ Failed to update transaction ${transactionId} after critical fulfillment error:`, updateError.message);
            }
        }

        // Add to errors collection as a fallback
        await errorsCollection.add({
            type: 'CRITICAL_FULFILLMENT_ERROR',
            error: error.message,
            stack: error.stack,
            transactionId: transactionId,
            requestType: requestType,
            sourceCallbackData: sourceCallbackData,
            createdAt: now,
        });

        return { success: false, status: 'CRITICAL_ERROR', error: error.message };
    }
}


// C2B Validation Endpoint
// ... existing code ...

// C2B Validation Endpoint
app.post('/c2b-validation', async (req, res) => {
    const callbackData = req.body;
    const now = new Date();
    const transactionIdentifier = callbackData.TransID || `C2B_VALIDATION_${Date.now()}`;
    const { TransAmount, BillRefNumber } = callbackData;
    const amount = parseFloat(TransAmount);

    try {
        // ✅ Validate phone format or account number
        const phoneRegex = /^(\+254|254|0)(1\d|7\d)\d{7}$/;
        const isPhone = phoneRegex.test(BillRefNumber);
        let isAccountNumber = false;
        if (!isPhone) {
            // Check if BillRefNumber matches a registered user's account number
            const userSnap = await firestore.collection('users')
                .where('accountNumber', '==', BillRefNumber)
                .limit(1)
                .get();
            isAccountNumber = !userSnap.empty;
        }
        if (!isPhone && !isAccountNumber) {
            throw {
                code: 'C2B00012',
                desc: `Invalid BillRefNumber format: ${BillRefNumber}`,
                subType: 'INVALID_BILL_REF'
            };
        }

        // ✅ Detect carrier (only if phone)
        let carrier = 'Unknown';
        if (isPhone) {
            carrier = detectCarrier(BillRefNumber);
            if (carrier === 'Unknown') {
                throw {
                    code: 'C2B00011',
                    desc: `Could not detect carrier from BillRefNumber: ${BillRefNumber}`,
                    subType: 'CARRIER_UNKNOWN'
                };
            }
        }

        // ✅ Fetch settings from Firestore in parallel
        const [carrierDoc, systemDoc] = await Promise.all([
            isPhone ? firestore.collection('carrier_settings').doc(carrier.toLowerCase()).get() : Promise.resolve({ exists: true, data: () => ({ active: true }) }),
            firestore.collection('system_settings').doc('global').get(),
        ]);

        // ✅ Check system status
        const systemStatus = systemDoc.exists ? systemDoc.data().status : 'offline';
        if (systemStatus !== 'online') {
            throw {
                code: 'C2B00016',
                desc: `System is currently offline.`,
                subType: 'SYSTEM_OFFLINE'
            };
        }

        // ✅ Check if carrier is active (only if phone)
        const carrierActive = isPhone ? (carrierDoc.exists ? carrierDoc.data().active : false) : true;
        if (isPhone && !carrierActive) {
            throw {
                code: 'C2B00011',
                desc: `${carrier} is currently inactive`,
                subType: 'CARRIER_INACTIVE'
            };
        }

        // ✅ Passed all checks
        console.info('✅ C2B Validation successful:', {
            TransID: transactionIdentifier,
            Amount: TransAmount,
            Carrier: carrier,
            Phone: BillRefNumber,
        });

        return res.json({
            ResultCode: '0',
            ResultDesc: 'Accepted',
        });

    } catch (err) {
        console.warn(`❌ Validation failed [${transactionIdentifier}]: ${err.desc}`, { error: err });

        await firestore.collection('errors').add({
            type: 'C2B_VALIDATION_REJECT',
            subType: err.subType || 'UNKNOWN_ERROR',
            error: err.desc || JSON.stringify(err),
            callbackData,
            createdAt: FieldValue.serverTimestamp(),
        });

        return res.json({
            ResultCode: err.code || 'C2B00016',
            ResultDesc: 'Rejected',
        });
    }
});


// C2B Confirmation Endpoint (Mandatory)
app.post('/c2b-confirmation', async (req, res) => {
    const callbackData = req.body;
    const transactionId = callbackData.TransID;
    const now = FieldValue.serverTimestamp(); // Use server timestamp

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

    const amount = parseFloat(TransAmount); // This is the original amount paid by customer
    const mpesaNumber = MSISDN;
    const customerName = `${FirstName || ''} ${MiddleName || ''} ${LastName || ''}`.trim();

    try {
        // --- 1. Record the incoming M-Pesa transaction (money received) ---
        const existingTxDoc = await transactionsCollection.doc(transactionId).get();
        if (existingTxDoc.exists) {
            logger.warn(`⚠️ Duplicate C2B confirmation for TransID: ${transactionId}. Skipping processing.`);
            return res.json({ "ResultCode": 0, "ResultDesc": "Duplicate C2B confirmation received and ignored." });
        }

        // Check if BillRefNumber is a phone number or account number
        const phoneRegex = /^(\+254|254|0)(1\d|7\d)\d{7}$/;
        const isPhone = phoneRegex.test(BillRefNumber);
        let topupNumber = BillRefNumber;
        let walletUpdateResult = null;
        let bonusApplied = 0;
        let bonusPercentage = 0;
        if (!isPhone) {
            // It's an account number: update walletBalance in users collection
            const userSnap = await firestore.collection('users')
                .where('accountNumber', '==', BillRefNumber)
                .limit(1)
                .get();
            if (!userSnap.empty) {
                const userDoc = userSnap.docs[0];
                const userRef = userDoc.ref;
                // Fetch bonus percentage (global or per-user)
                // Example: global bonus
                const bonusDoc = await firestore.collection('wallet_bonuses').doc('current_settings').get();
                if (bonusDoc.exists) {
                    bonusPercentage = bonusDoc.data().percentage || 0;
                }
                // Example: per-user override
                if (userDoc.data().walletBonusPercentage !== undefined) {
                    bonusPercentage = userDoc.data().walletBonusPercentage;
                }
                bonusApplied = amount * (bonusPercentage / 100);
                const totalToAdd = amount + bonusApplied;
                await userRef.update({
                    walletBalance: FieldValue.increment(totalToAdd),
                    lastWalletUpdate: now
                });
                walletUpdateResult = {
                    userId: userDoc.id,
                    accountNumber: BillRefNumber,
                    incrementedBy: totalToAdd,
                    bonusApplied,
                    bonusPercentage
                };
                logger.info(`✅ Updated walletBalance for user ${userDoc.id} (accountNumber: ${BillRefNumber}) by Ksh ${totalToAdd} (bonus: ${bonusApplied})`);
            } else {
                logger.warn(`⚠️ No user found with accountNumber: ${BillRefNumber} for wallet update.`);
            }
        } else {
            // If phone, remove non-digits for topupNumber
            topupNumber = BillRefNumber.replace(/\D/g, '');
        }

        await transactionsCollection.doc(transactionId).set({
            transactionID: transactionId,
            type: 'C2B_PAYMENT', // Explicitly mark type
            transactionTime: TransTime,
            amountReceived: amount, // Original amount paid by customer
            payerMsisdn: mpesaNumber,
            payerName: customerName,
            billRefNumber: BillRefNumber,
            mpesaRawCallback: callbackData,
            status: 'RECEIVED_PENDING_FULFILLMENT', // Set status to pending fulfillment
            fulfillmentStatus: 'PENDING', // Initial fulfillment status
            createdAt: now,
            lastUpdated: now,
            walletUpdateResult: walletUpdateResult || null,
            walletBonusApplied: bonusApplied,
            walletBonusPercentage: bonusPercentage
        });
        logger.info(`✅ Recorded incoming transaction ${transactionId} in 'transactions' collection.`);

        // --- 2. Trigger the unified airtime fulfillment process only if phone number ---
        if (isPhone) {
            const fulfillmentResult = await processAirtimeFulfillment({
                transactionId: transactionId,
                originalAmountPaid: amount,
                payerMsisdn: mpesaNumber,
                payerName: customerName,
                topupNumber: topupNumber,
                sourceCallbackData: callbackData,
                requestType: 'C2B',
                // relatedSaleId is null here as C2B creates its own sale doc
            });
            logger.info(`C2B Confirmation for TransID ${transactionId} completed. Fulfillment Result:`, fulfillmentResult);
        }

        res.json({ "ResultCode": 0, "ResultDesc": "C2B Confirmation and Processing Complete." });

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

// Daraja Reversal Result Endpoint
app.post('/daraja-reversal-result', async (req, res) => {
    try {
        const result = req.body?.Result;
        logger.info('📞 Received Daraja Reversal Result Callback:', result);

        const resultCode = result?.ResultCode;
        const resultDesc = result?.ResultDesc;
        const reversalTransactionId = result?.TransactionID;

        const params = result?.ResultParameters?.ResultParameter || [];

        // Extract parameters safely
        const extractParam = (key) => params.find(p => p.Key === key)?.Value;

        const originalTransactionId = extractParam('OriginalTransactionID');
        const amount = extractParam('Amount');
        const creditParty = extractParam('CreditPartyPublicName');
        const debitParty = extractParam('DebitPartyPublicName');

        if (!originalTransactionId) {
            logger.error("❌ Missing OriginalTransactionID in reversal callback", { rawCallback: req.body });
            return res.status(400).json({ ResultCode: 0, ResultDesc: "Missing OriginalTransactionID. Logged for manual review." });
        }

        const transactionRef = transactionsCollection.doc(originalTransactionId);
        const transactionDoc = await transactionRef.get();

        if (!transactionDoc.exists) {
            logger.warn(`⚠️ Reversal result received for unknown OriginalTransactionID: ${originalTransactionId}`);
            return res.json({ ResultCode: 0, ResultDesc: "Acknowledged - Unknown transaction." });
        }

        if (resultCode === 0) {
            logger.info(`✅ Reversal for TransID ${originalTransactionId} COMPLETED successfully.`);
            await transactionRef.update({
                status: 'REVERSED_SUCCESSFULLY',
                reversalConfirmationDetails: result,
                lastUpdated: FieldValue.serverTimestamp(),
            });
            await reconciledTransactionsCollection.doc(originalTransactionId).update({
                status: 'REVERSAL_CONFIRMED',
                reversalConfirmationDetails: result,
                lastUpdated: FieldValue.serverTimestamp(),
            });
        } else {
            logger.error(`❌ Reversal for TransID ${originalTransactionId} FAILED: ${resultDesc}`);
            await transactionRef.update({
                status: 'REVERSAL_FAILED_CONFIRMATION',
                reversalConfirmationDetails: result,
                errorMessage: `Reversal failed: ${resultDesc}`,
                lastUpdated: FieldValue.serverTimestamp(),
            });
            await failedReconciliationsCollection.doc(originalTransactionId).set({
                transactionId: originalTransactionId,
                reversalConfirmationDetails: result,
                reason: resultDesc,
                createdAt: FieldValue.serverTimestamp(),
            }, { merge: true });
        }

        res.json({ ResultCode: 0, ResultDesc: "Reversal result processed successfully." });

    } catch (error) {
        logger.error("❌ Error processing Daraja reversal callback", {
            message: error.message,
            stack: error.stack,
            rawBody: req.body,
        });
        res.status(500).json({ ResultCode: 0, ResultDesc: "Server error during reversal processing." });
    }
});


// --- Daraja Reversal Queue Timeout Endpoint ---
app.post('/daraja-reversal-timeout', async (req, res) => {
    const timeoutData = req.body;
    const now = new Date();
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
                status: 'REVERSAL_TIMED_OUT', // New status for timed-out reversals
                reversalTimeoutDetails: timeoutData,
                lastUpdated: FieldValue.serverTimestamp(),
            });
        } else {
            logger.warn(`⚠️ Reversal Timeout received for unknown or unlinked TransID/OriginatorConversationID: ${transactionIdToUpdate}`);
        }

        // Always record the timeout in a dedicated collection for auditing/manual review
        await reversalTimeoutsCollection.add({
            transactionId: transactionIdToUpdate, // The ID you're tracking internally
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
        // Still send a success response to Daraja to avoid repeated callbacks
        res.json({ "ResultCode": 0, "ResultDesc": "Internal server error during Queue Timeout processing." });
    }
});
        
// --- NEW AIRTIME BONUS API ENDPOINTS ---
const CURRENT_BONUS_DOC_PATH = 'airtime_bonuses/current_settings'; // Document path for current settings
// BONUS_HISTORY_COLLECTION is already defined at the top as a const

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

app.post('/api/trigger-daraja-reversal', async (req, res) =>{
    // Removed shortCode parameter as it's fetched from env
    const {transactionId, mpesaNumber, amount} = req.body;
    logger.info(`🔄 Attempting Daraja reversal for TransID: ${transactionId}, Amount: ${amount}`);
    try {
        const accessToken = await getDarajaAccessToken(); // Function to get Daraja access token

        if (!accessToken) {
            throw new Error("Failed to get Daraja access token for reversal.");
        }

        const url = process.env.MPESA_REVERSAL_URL; 
        const shortCode = process.env.MPESA_SHORTCODE; 
        const initiator = process.env.MPESA_INITIATOR_NAME; 
        const password=process.env.MPESA_SECURITY_PASSWORD;
        const securityCredential = generateSecurityCredential(password);  
        

        if (!url || !shortCode || !initiator || !securityCredential) {
            throw new Error("Missing Daraja reversal environment variables.");
        }

        const payload = {
            Initiator: initiator,
            SecurityCredential: securityCredential, // Use your actual security credential
            CommandID: "TransactionReversal",
            TransactionID: transactionId, // The M-Pesa TransID to be reversed
            Amount: amount, // The amount to reverse
            ReceiverParty: shortCode, 
            RecieverIdentifierType: "11",
            QueueTimeOutURL: process.env.MPESA_REVERSAL_QUEUE_TIMEOUT_URL, // URL for timeout callbacks
            ResultURL: process.env.MPESA_REVERSAL_RESULT_URL, // URL for result callbacks
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
                // You might store the ConversationID for tracking if provided
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
})

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
            batch.set(bonusHistoryCollection.doc(), { // Use the initialized collection variable
                company: 'Safaricom',
                oldPercentage: oldSettings.safaricomPercentage || 0,
                newPercentage: safaricomPercentage,
                timestamp: FieldValue.serverTimestamp(),
                actor: actor || 'system', // Default to 'system' if actor is not provided
            });
            logger.info(`Safaricom bonus changed from ${oldSettings.safaricomPercentage} to ${safaricomPercentage} by ${actor || 'system'}.`);
        }
        if (africastalkingPercentage !== oldSettings.africastalkingPercentage) {
            batch.set(bonusHistoryCollection.doc(), { // Use the initialized collection variable
                company: 'AfricasTalking',
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
        logger.error('Error updating airtime bonuses:', { message: error.message, stack: error.stack }); // Completed the error message
        res.status(500).json({ error: 'Failed to update airtime bonuses.' });
    }
});

// --- Endpoint to receive fulfillment requests from STK Server ---
app.post('/api/fulfill-airtime', async (req, res) => {
    const fulfillmentRequest = req.body;
    const now = FieldValue.serverTimestamp();

    logger.info('📦 Received fulfillment request from STK Server:', fulfillmentRequest);
    const {
        checkoutRequestID,
        merchantRequestID,
        mpesaReceiptNumber,
        amountPaid,
        recipientNumber,
        customerPhoneNumber,
        carrier
    } = fulfillmentRequest;
    
    if (!checkoutRequestID || !amountPaid || !recipientNumber || !customerPhoneNumber || !carrier) {
        logger.error('❌ Missing required fields in fulfillment request:', fulfillmentRequest);
        await errorsCollection.add({
            type: 'OFFLINE_FULFILLMENT_REQUEST_ERROR',
            error: 'Missing required fields in request body.',
            requestBody: fulfillmentRequest,
            createdAt: now,
        });
        return res.status(400).json({ success: false, message: 'Missing required fulfillment details.' });
    }
    // Respond with an error to the STK server
    return res.status(500).json({ success: false, message: 'Internal server error during fulfillment request processing.' });
});

//Keep live tracker
app.get("/ping", (req, res) => {
  res.status(200).send("pong");
});

// Start the server
app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
    console.log(`Server running on port ${PORT}`);
});

app.set('trust proxy', 1);

function generateTimestamp() {
  const now = new Date();
  const yyyy = now.getFullYear();
  const MM = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  const HH = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  return `${yyyy}${MM}${dd}${HH}${mm}${ss}`;
}

// --- BULK AIRTIME ENDPOINT ---
app.post('/api/bulk-airtime', async (req, res) => {
  const { requests, totalAmount, userId } = req.body;
  if (!Array.isArray(requests) || requests.length === 0 || !totalAmount || !userId) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  // Validate totalAmount matches sum of all amounts
  const sumAmounts = requests.reduce((sum, r) => sum + Number(r.amount || 0), 0);
  if (Number(totalAmount) !== sumAmounts) {
    return res.status(400).json({ error: 'totalAmount does not match sum of request amounts.' });
  }

  const results = [];
  for (let i = 0; i < requests.length; i++) {
    const { phoneNumber, amount, telco, name } = requests[i];
    let status = 'FAILED';
    let message = '';
    let dispatchResult = null;
    try {
      // Use your existing logic for sending airtime (carrier detection, fallback, float management, etc.)
      // For this example, we'll use sendSafaricomAirtime/sendAfricasTalkingAirtime based on telco
      let result;
      if (telco && telco.toLowerCase() === 'safaricom') {
        result = await sendSafaricomAirtime(phoneNumber, amount);
        if (result && result.status === 'SUCCESS') {
          status = 'SUCCESS';
          message = 'Airtime sent via Safaricom';
        } else {
          // Fallback to Africa's Talking
          result = await sendAfricasTalkingAirtime(phoneNumber, amount, telco);
          if (result && result.status === 'SUCCESS') {
            status = 'SUCCESS';
            message = 'Airtime sent via Africa\'s Talking fallback';
          } else {
            message = result && result.message ? result.message : 'Both Safaricom and fallback failed';
          }
        }
      } else {
        // Non-Safaricom: use Africa's Talking
        result = await sendAfricasTalkingAirtime(phoneNumber, amount, telco);
        if (result && result.status === 'SUCCESS') {
          status = 'SUCCESS';
          message = 'Airtime sent via Africa\'s Talking';
        } else {
          message = result && result.message ? result.message : 'Africa\'s Talking failed';
        }
      }
      dispatchResult = result;
    } catch (err) {
      message = err.message || 'Exception during airtime dispatch';
    }

    // Log each attempt in Firestore
    try {
      await firestore.collection('bulk_airtime_logs').add({
        userId,
        phoneNumber,
        amount,
        telco,
        name,
        status,
        message,
        dispatchResult,
        requestedAt: FieldValue.serverTimestamp(),
        requestIndex: i,
      });
    } catch (logErr) {
      console.error('Failed to log bulk airtime attempt:', logErr);
    }

    results.push({ phoneNumber, amount, telco, name, status, message });
    // Wait 3 seconds before next
    if (i < requests.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }

  res.json({ results });
});

// --- BULK AIRTIME QUEUE ENDPOINTS ---
// 1. Submit a bulk airtime job
app.post('/api/bulk-airtime', async (req, res) => {
  const { requests, totalAmount, userId } = req.body;
  if (!Array.isArray(requests) || requests.length === 0 || !totalAmount || !userId) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }
  // Validate totalAmount matches sum of all amounts
  const sumAmounts = requests.reduce((sum, r) => sum + Number(r.amount || 0), 0);
  if (Number(totalAmount) !== sumAmounts) {
    return res.status(400).json({ error: 'totalAmount does not match sum of request amounts.' });
  }
  try {
    const jobDoc = await firestore.collection('bulk_airtime_jobs').add({
      userId,
      requests,
      totalAmount,
      status: 'pending',
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
      results: [],
      currentIndex: 0
    });
    res.json({ jobId: jobDoc.id });
  } catch (err) {
    console.error('Failed to create bulk airtime job:', err);
    res.status(500).json({ error: 'Failed to create job.' });
  }
});

// 2. Poll job status/results
app.get('/api/bulk-airtime-status/:jobId', async (req, res) => {
  const { jobId } = req.params;
  try {
    const jobDoc = await firestore.collection('bulk_airtime_jobs').doc(jobId).get();
    if (!jobDoc.exists) {
      return res.status(404).json({ error: 'Job not found.' });
    }
    res.json(jobDoc.data());
  } catch (err) {
    console.error('Failed to fetch bulk airtime job:', err);
    res.status(500).json({ error: 'Failed to fetch job.' });
  }
});

// 3. Background worker to process jobs
const BULK_AIRTIME_WORKER_INTERVAL = 10000; // 10 seconds
const BULK_AIRTIME_RECIPIENT_DELAY = 3000; // 3 seconds

async function processBulkAirtimeJobs() {
  try {
    // Get jobs with status 'pending' or 'processing'
    const jobsSnap = await firestore.collection('bulk_airtime_jobs')
      .where('status', 'in', ['pending', 'processing'])
      .orderBy('createdAt')
      .limit(2) // process up to 2 jobs at a time
      .get();
    for (const jobDoc of jobsSnap.docs) {
      const job = jobDoc.data();
      const jobId = jobDoc.id;
      let { requests, results = [], currentIndex = 0, status } = job;
      if (!Array.isArray(requests) || currentIndex >= requests.length) {
        // Already done
        await firestore.collection('bulk_airtime_jobs').doc(jobId).update({
          status: 'completed',
          updatedAt: FieldValue.serverTimestamp()
        });
        continue;
      }
      // Mark as processing
      if (status !== 'processing') {
        await firestore.collection('bulk_airtime_jobs').doc(jobId).update({
          status: 'processing',
          updatedAt: FieldValue.serverTimestamp()
        });
      }
      // Process up to 5 recipients per run (to avoid long locks)
      let processed = 0;
      while (currentIndex < requests.length && processed < 5) {
        const { phoneNumber, amount, telco, name } = requests[currentIndex];
        let recipientStatus = 'FAILED';
        let message = '';
        let dispatchResult = null;
        try {
          let result;
          if (telco && telco.toLowerCase() === 'safaricom') {
            result = await sendSafaricomAirtime(phoneNumber, amount);
            if (result && result.status === 'SUCCESS') {
              recipientStatus = 'SUCCESS';
              message = 'Airtime sent via Safaricom';
            } else {
              // Fallback to Africa's Talking
              result = await sendAfricasTalkingAirtime(phoneNumber, amount, telco);
              if (result && result.status === 'SUCCESS') {
                recipientStatus = 'SUCCESS';
                message = 'Airtime sent via Africa\'s Talking fallback';
              } else {
                message = result && result.message ? result.message : 'Both Safaricom and fallback failed';
              }
            }
          } else {
            result = await sendAfricasTalkingAirtime(phoneNumber, amount, telco);
            if (result && result.status === 'SUCCESS') {
              recipientStatus = 'SUCCESS';
              message = 'Airtime sent via Africa\'s Talking';
            } else {
              message = result && result.message ? result.message : 'Africa\'s Talking failed';
            }
          }
          dispatchResult = result;
        } catch (err) {
          message = err.message || 'Exception during airtime dispatch';
        }
        results[currentIndex] = { phoneNumber, amount, telco, name, status: recipientStatus, message };
        // Update job after each recipient
        await firestore.collection('bulk_airtime_jobs').doc(jobId).update({
          results,
          currentIndex: currentIndex + 1,
          updatedAt: FieldValue.serverTimestamp()
        });
        currentIndex++;
        processed++;
        // Wait 3 seconds before next recipient
        if (currentIndex < requests.length) {
          await new Promise(resolve => setTimeout(resolve, BULK_AIRTIME_RECIPIENT_DELAY));
        }
      }
      // If all done, mark as completed
      if (currentIndex >= requests.length) {
        await firestore.collection('bulk_airtime_jobs').doc(jobId).update({
          status: 'completed',
          updatedAt: FieldValue.serverTimestamp()
        });
      }
    }
  } catch (err) {
    console.error('Bulk airtime worker error:', err);
  }
}
setInterval(processBulkAirtimeJobs, BULK_AIRTIME_WORKER_INTERVAL);
// --- END BULK AIRTIME QUEUE ENDPOINTS ---

// --- STK PUSH INITIATION ENDPOINT ---
app.post('/api/mpesa/stkpush', async (req, res) => {
  const { amount, phoneNumber, accountNumber } = req.body;
  if (!amount || !phoneNumber || !accountNumber) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  try {
    // Use existing timestamp and password generation functions/variables
    const timestamp = generateTimestamp();
    const password = generatePassword(SHORTCODE, PASSKEY, timestamp);
    // Use existing token function (getAccessToken or getDarajaAccessToken)
    const token = await getAccessToken();

    const payload = {
      BusinessShortCode: SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Number(amount),
      PartyA: phoneNumber,
      PartyB: SHORTCODE,
      PhoneNumber: phoneNumber,
      CallBackURL: STK_CALLBACK_URL,
      AccountReference: accountNumber,
      TransactionDesc: 'Wallet Top Up'
    };

    const stkRes = await axios.post(
      'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
      payload,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    res.json({
      message: 'STK Push initiated. Await callback for confirmation.',
      merchantRequestID: stkRes.data.MerchantRequestID,
      checkoutRequestID: stkRes.data.CheckoutRequestID,
      responseDescription: stkRes.data.ResponseDescription
    });
  } catch (err) {
    console.error('STK Push error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to initiate STK Push.' });
  }
});
