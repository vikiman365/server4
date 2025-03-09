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
  origin: 'http://localhost:3000', // adjust to your frontend domain
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
    // Set token in an HttpOnly cookie (do not send it in JSON)
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.status(201).json({ message: 'Sign up successful' });
  } catch (error) {
    logger.error('Signup error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

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
    // Set token in an HttpOnly cookie instead of returning it in JSON
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.status(200).json({ message: 'Sign in successful' });
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
// Wrap Express App for Serverless Deployment
// ---------------------------
app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
   });
   
module.exports.handler = serverless(app);

// For local development, uncomment below:
