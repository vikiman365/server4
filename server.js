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
const serverless = require('serverless-http');

const app = express();
const PORT = process.env.PORT || 4000;

// ---------------------------
// Security Middleware Setup
// ---------------------------
app.use(express.json());
app.use(bodyParser.json());
app.use(helmet());
app.use(cors({
  origin: 'http://localhost:3000', // Adjust to your frontend domain
  credentials: true,
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// ---------------------------
// MongoDB Connection Setup
// ---------------------------
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  throw new Error('Please define the MONGODB_URI environment variable in your .env file');
}

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// ---------------------------
// User Schema & Model
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
    return res.status(401).json({ error: 'Not authorized, no token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(401).json({ error: 'Not authorized, token failed' });
  }
};

// ---------------------------
// Routes
// ---------------------------

// Sign Up Route
app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password, country, phoneNumber } = req.body;
  if (!username || !email || !password || !country || !phoneNumber) {
    return res.status(400).json({ error: 'Please provide all required fields' });
  }
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'User already exists' });
    
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
    res.status(201).json({ token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Sign In Route
app.post('/api/auth/signin', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Please provide email and password' });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });
    
    const token = generateToken(user);
    res.status(200).json({ token });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Protected Route Example
app.get('/api/auth/protected', protect, (req, res) => {
  res.status(200).json({ message: 'This is a protected route', user: req.user });
});

// ---------------------------
// Start HTTP Server (Serverless Ready)
// ---------------------------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports.handler = serverless(app);
