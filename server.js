// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const serverless = require('serverless-http');
const morgan = require('morgan');
const winston = require('winston');
const axios = require('axios');
const crypto = require('crypto');

// Create Winston logger for detailed logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

const app = express();
const PORT = process.env.PORT || 4000;

// ---------------------------
// Security Middlewares Setup
// ---------------------------
app.use(express.json());
app.use(bodyParser.json());
app.use(cookieParser());
app.use(helmet());
app.use(cors({
  // adjust to your frontend domain if needed
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
}));

// HTTP request logging with Morgan (integrated with Winston)
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Rate limiting: 100 requests per 15 minutes per IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// ---------------------------
// MongoDB Connection Setup
// ---------------------------
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  logger.error('MONGODB_URI is not defined in .env');
  throw new Error('Please define the MONGODB_URI environment variable');
}
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => logger.info('MongoDB connected'))
  .catch(err => logger.error('MongoDB connection error:', err));

// ---------------------------
// User Schema & Model Definition
// ---------------------------
const userSchema = new mongoose.Schema({
  username:    { type: String, required: true },
  email:       { type: String, required: true, unique: true },
  password:    { type: String, required: true },
  country:     { type: String, required: true },
  phoneNumber: { type: String, required: true },
  investmentBalance: { type: Number, default: 0 },
  mines: { type: Number, default: 0 },
  totalInvested: { type: Number, default: 0 },
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', userSchema);

// ---------------------------
// Utility: Generate JWT Token
// ---------------------------
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
};

// ---------------------------
// Middleware: Protect Routes
// ---------------------------
const protect = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.warn('Unauthorized access attempt: no token provided');
    return res.status(401).json({ error: 'Not authorized, no token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    logger.error('Token verification failed:', err);
    res.status(401).json({ error: 'Not authorized, token failed' });
  }
};

// ---------------------------
// Authentication Routes
// ---------------------------
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const baseURL = 'https://api.paystack.co';

// Sign Up Route
app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password, country, phoneNumber } = req.body;
  if (!username || !email || !password || !country || !phoneNumber) {
    logger.warn('Signup failed: Missing fields', req.body);
    return res.status(400).json({ error: 'Please provide all required fields' });
  }
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      logger.warn('Signup failed: User already exists', { email });
      return res.status(400).json({ error: 'User already exists' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      country,
      phoneNumber,
    });
    const token = generateToken(user);
    logger.info('User signed up successfully', { email: user.email, id: user._id });
    // Set token in an HttpOnly cookie
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.status(201).json({ message: 'Sign up successful' });
  } catch (error) {
    logger.error('Signup error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Sign In Route
// Sign In Route
app.post('/api/auth/signin', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
      logger.warn('Signin failed: Missing email or password');
      return res.status(400).json({ error: 'Please provide email and password' });
    }
    try {
      const user = await User.findOne({ email });
      if (!user) {
        logger.warn('Signin failed: User not found', { email });
        return res.status(400).json({ error: 'Invalid credentials' });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        logger.warn('Signin failed: Incorrect password', { email });
        return res.status(400).json({ error: 'Invalid credentials' });
      }
      const token = generateToken(user);
      logger.info('User signed in successfully', { email: user.email, id: user._id });
      // Set token in an HttpOnly cookie
      res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
      // Return token along with the success message
      res.status(200).json({ message: 'Sign in successful', token });
    } catch (error) {
      logger.error('Signin error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  });
  
// Protected Route Example
app.get('/api/auth/protected', protect, (req, res) => {
  logger.info('Protected route accessed', { user: req.user });
  res.status(200).json({ message: 'This is a protected route', user: req.user });
});

// ---------------------------
// Payment & Verification Logic
// ---------------------------

function logTransaction(action, details) {
    console.log({
      level: 'info',
      timestamp: new Date().toISOString(),
      action,
      details
    });
  }
  
  // Helper function to verify a transaction using Paystack API
  async function verifyTransaction(reference) {
    try {
      const response = await axios.get(
        `${baseURL}/transaction/verify/${encodeURIComponent(reference)}`,
        {
          headers: {
            Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`
          }
        }
      );
      logTransaction('VerificationResponse', {
        reference,
        status: response.status,
        data: response.data
      });
      return response.data;
    } catch (error) {
      logTransaction('VerificationError', {
        reference,
        error: error.response ? error.response.data : error.message
      });
      throw error;
    }
  }
  
  // Initiate Payment Endpoint
  // This endpoint calls Paystack to initiate a mobile money charge (using Mpesa) and waits for verification.
  app.post('/initiate-payment', async (req, res) => {
    try {
      const { amount, email, phone } = req.body;
      logTransaction('PaymentInitiated', { amount, email, phone });
      const response = await axios.post(
        `${baseURL}/charge`,
        {
          amount: amount * 100, // Convert to kobo
          email,
          mobile_money: { phone, provider: 'mpesa' }
        },
        {
          headers: {
            Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
            'Content-Type': 'application/json'
          }
        }
      );
      logTransaction('PaystackAPIResponse', { status: response.status, data: response.data });
      // Await immediate verification from Paystack
      const verification = await verifyTransaction(response.data.data.reference);
      // Return payment and verification result
      res.json({ success: true, paymentInitiated: response.data, verificationResult: verification });
    } catch (error) {
      logTransaction('PaymentError', { error: error.response ? error.response.data : error.message, stack: error.stack });
      const statusCode = error.response?.status || 500;
      res.status(statusCode).json({ success: false, error: error.response?.data});
    }
  });
  
  // Dedicated Verification Endpoint
  // This endpoint verifies a transaction and updates the user's record if the payment is successful.
  app.get('/verify-payment/:reference', async (req, res) => {
    try {
      const { reference } = req.params;
      logTransaction('ManualVerificationAttempt', { reference });
      const result = await verifyTransaction(reference);
      if (result.data.status === 'success') {
        const amount = result.data.amount / 100;
        const user = await User.findOne({ email: result.data.customer.email });
        if (user) {
          user.investmentBalance += amount;
          user.totalInvested += amount;
          user.mines = Math.floor(user.investmentBalance / 500);
          await user.save();
        }
      }
      res.json({ success: true, verifiedData: result.data });
    } catch (error) {
      res.status(500).json({ success: false, error: error.response?.data || error.message });
    }
  });
  
  // Paystack Webhook Handler
  // This endpoint processes incoming webhooks from Paystack to automatically update user records.
  app.post('/paystack-webhook', (req, res) => {
    const signature = req.headers['x-paystack-signature'];
    const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY)
                       .update(JSON.stringify(req.body))
                       .digest('hex');
    if (hash !== signature) {
      logTransaction('WebhookSecurityFail', { receivedSignature: signature, computedHash: hash });
      return res.status(401).send('Unauthorized');
    }
    const event = req.body;
    logTransaction('WebhookReceived', event);
    switch (event.event) {
      case 'charge.success':
        logTransaction('PaymentSuccess', event.data);
        // Update user record based on customer email
        User.findOne({ email: event.data.customer.email }).then(user => {
          if (user) {
            user.investmentBalance += event.data.amount / 100;
            user.totalInvested += event.data.amount / 100;
            user.mines = Math.floor(user.investmentBalance / 500);
            user.save();
          }
        });
        break;
      case 'charge.failed':
        logTransaction('PaymentFailed', event.data);
        break;
      case 'transfer.success':
        logTransaction('TransferSuccess', event.data);
        break;
      default:
        logTransaction('UnhandledEvent', event);
    }
    res.sendStatus(200);
  });

// ---------------------------
// Start Server & Serverless Handler
// ---------------------------
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});
module.exports.handler = serverless(app);
