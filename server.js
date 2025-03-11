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

// Create Express app
const app = express();

// -----------------------------
// Logger Setup with Winston
// -----------------------------
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

// -----------------------------
// Middlewares
// -----------------------------
app.use(express.json());
app.use(bodyParser.json());
app.use(cookieParser());
app.use(helmet());

// CORS configuration for allowed origins
const allowedOrigins = [
  'https://crypto1-rfzlrngqc-vikiman365s-projects.vercel.app',
  'https://crypto1-ten.vercel.app',
];

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g., curl or mobile apps)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      return callback(new Error('CORS policy does not allow access from this origin: ' + origin), false);
    }
    return callback(null, true);
  },
  credentials: true,
};

app.use(cors(corsOptions));
// Ensure that preflight (OPTIONS) requests are handled correctly
app.options('*', cors(corsOptions));

app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Rate limiter to protect against too many requests
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// -----------------------------
// MongoDB Connection
// -----------------------------
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  logger.error('MONGODB_URI is not defined in .env');
  process.exit(1);
}
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => logger.info('MongoDB connected'))
.catch(err => logger.error('MongoDB connection error:', err));

// -----------------------------
// User Schema & Model
// -----------------------------
const userSchema = new mongoose.Schema({
  username:    { type: String, required: true },
  email:       { type: String, required: true, unique: true },
  password:    { type: String, required: true },
  country:     { type: String, required: true },
  phoneNumber: { type: String, required: true },
  investmentBalance: { type: Number, default: 0 },
  totalInvested: { type: Number, default: 0 },
  mines: { type: Number, default: 0 },
  role: { type: String, default: "user" },
  refreshToken: { type: String },
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', userSchema);

// -----------------------------
// Utility Functions
// -----------------------------
const generateAccessToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
};

// -----------------------------
// Middleware: Protect Route
// -----------------------------
const protect = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Not authorized, no token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
  } catch (error) {
      return res.status(401).json({ error: 'Not authorized, token failed' });
  }
};

// -----------------------------
// Routes
// -----------------------------

// SignUp Route
app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password, country, phoneNumber } = req.body;
  if (!username || !email || !password || !country || !phoneNumber) {
      return res.status(400).json({ error: 'Please provide all required fields' });
  }
  try {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
          return res.status(409).json({ error: 'Username or Email already exists' });
      }
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const user = await User.create({
          username,
          email,
          password: hashedPassword,
          country,
          phoneNumber,
          role: "user"
      });
      // Generate tokens for immediate sign-in if desired
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);
      user.refreshToken = refreshToken;
      await user.save();
      res.cookie('refreshToken', refreshToken, { 
          httpOnly: true, 
          secure: process.env.NODE_ENV === "production", 
          sameSite: "Strict", 
          maxAge: 7 * 24 * 60 * 60 * 1000 
      });
      res.status(201).json({ message: 'Sign up successful. Please sign in.', accessToken });
  } catch (error) {
      logger.error('Sign up error:', error);
      res.status(500).json({ error: 'Server error' });
  }
});

// SignIn Route
app.post('/api/auth/signin', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
      return res.status(400).json({ error: 'Please provide email and password' });
  }
  try {
      const user = await User.findOne({ email });
      if (!user) {
          return res.status(401).json({ error: 'Invalid credentials' });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
          return res.status(401).json({ error: 'Invalid credentials' });
      }
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);
      user.refreshToken = refreshToken;
      await user.save();
      res.cookie('refreshToken', refreshToken, { 
          httpOnly: true, 
          secure: process.env.NODE_ENV === "production", 
          sameSite: "Strict", 
          maxAge: 7 * 24 * 60 * 60 * 1000 
      });
      res.status(200).json({ message: 'Sign in successful', accessToken, roles: [user.role] });
  } catch (error) {
      logger.error('Sign in error:', error);
      res.status(500).json({ error: 'Server error' });
  }
});

// Protected Route: Returns user details needed for Dashboard
app.get('/api/auth/protected', protect, async (req, res) => {
  try {
      const user = await User.findById(req.user.id).select('-password -__v -refreshToken');
      if (!user) {
          return res.status(404).json({ error: 'User not found' });
      }
      res.status(200).json({ user });
  } catch (error) {
      logger.error('Protected route error:', error);
      res.status(500).json({ error: 'Server error' });
  }
});

// Refresh Token Route
app.post('/api/auth/refresh', async (req, res) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token provided' });
  }
  try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      const user = await User.findById(decoded.id);
      if (!user || user.refreshToken !== refreshToken) {
          return res.status(403).json({ error: 'Invalid refresh token' });
      }
      const newAccessToken = generateAccessToken(user);
      const newRefreshToken = generateRefreshToken(user);
      user.refreshToken = newRefreshToken;
      await user.save();
      res.cookie('refreshToken', newRefreshToken, { 
          httpOnly: true, 
          secure: process.env.NODE_ENV === "production", 
          sameSite: "Strict", 
          maxAge: 7 * 24 * 60 * 60 * 1000 
      });
      res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
      logger.error('Refresh token error:', error);
      res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// -----------------------------
// Payment & Verification Logic
// -----------------------------
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const baseURL = process.env.PAYSTACK_BASE_URL || 'https://api.paystack.co';

// Helper function to log transactions
function logTransaction(action, details) {
    logger.info({ action, details, timestamp: new Date().toISOString() });
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
app.post('/initiate-payment', async (req, res) => {
  try {
    const { amount, email, phone } = req.body;
    logTransaction('PaymentInitiated', { amount, email, phone });
    const response = await axios.post(
      `${baseURL}/charge`,
      {
        amount: amount * 100, // Convert amount if needed
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
    res.json({ success: true, paymentInitiated: response.data, verificationResult: verification });
  } catch (error) {
    logTransaction('PaymentError', { error: error.response ? error.response.data : error.message, stack: error.stack });
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({ success: false, error: error.response?.data });
  }
});

// Dedicated Verification Endpoint
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

// -----------------------------
// Start Server & Serverless Handler
// -----------------------------
const PORT = process.env.PORT || 3000;
// For local development, start the server. In Vercel, the exported handler is used.
if (process.env.NODE_ENV !== 'serverless') {
  app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
  });
}

// Export the serverless handler for Vercel
module.exports.handler = serverless(app);
