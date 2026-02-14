require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const YahooFinance = require('yahoo-finance2').default;
const yahooFinance = new YahooFinance();
yahooFinance._notices.suppress(['yahooSurvey']);
const emailService = require('./services/emailService');
const { createServer } = require('http');
const { Server } = require('socket.io');



const { HoldingsModel } = require("./model/HoldingsModel");
const { PositionsModel } = require("./model/PositionsModel");
const { OrdersModel } = require("./model/OrdersModel");
const { UserModel } = require("./model/UserModel");
const stockRoutes = require('./routes/stockRoutes');

const PORT = process.env.PORT || 3000;
const uri = process.env.MONGO_URL || "mongodb://localhost:27017/test";
const NODE_ENV = process.env.NODE_ENV || 'development';

// Case-insensitive email lookup (emails are case-insensitive per RFC)
const findUserByEmail = (email) => {
  if (!email || !email.trim()) return null;
  const escaped = String(email).trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return UserModel.findOne({ email: { $regex: new RegExp(`^${escaped}$`, 'i') } });
};

// Allowed origins for CORS
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5174',
  'https://stocksathi.vercel.app',
  'https://stocksathi-dashboard.vercel.app',
  process.env.FRONTEND_URL,
  process.env.DASHBOARD_URL
].filter(Boolean);

// Add wildcard for Vercel preview deployments
if (process.env.NODE_ENV === 'production') {
  allowedOrigins.push(/vercel\.app$/);
}

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'x-user-data'],
    // Allow all origins in development
    ...(process.env.NODE_ENV === 'development' && { origin: '*' })
  }
});

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) {
      return callback(null, true);
    }
    
    // In production, allow Vercel preview deployments
    if (process.env.NODE_ENV === 'production') {
      // Allow Vercel preview deployments
      if (origin && typeof origin === 'string' && origin.includes('vercel.app')) {
        console.log('✅ CORS allowed (Vercel):', origin);
        return callback(null, true);
      }
      
      // Check against explicit allowed origins
      const isAllowed = allowedOrigins.some(allowed => {
        if (typeof allowed === 'string') {
          return allowed === origin;
        } else if (allowed instanceof RegExp) {
          return allowed.test(origin);
        }
        return false;
      });
      
      if (isAllowed) {
        console.log('✅ CORS allowed:', origin);
        return callback(null, true);
      }
      
      // Log blocked origins for monitoring
      console.warn('⚠️ CORS blocked origin:', origin);
      console.warn('Allowed origins:', allowedOrigins);
      // Still allow in production to prevent issues, but log for monitoring
      return callback(null, true);
    } else {
      // In development, allow localhost and explicit origins
      if (allowedOrigins.indexOf(origin) !== -1) {
        return callback(null, true);
      }
      
      // Allow localhost in development
      if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
        return callback(null, true);
      }
      
      console.warn('⚠️ CORS blocked origin in development:', origin);
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-data', 'X-Requested-With'],
  exposedHeaders: ['Content-Range', 'X-Content-Range']
}));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
    sameSite: NODE_ENV === 'production' ? 'none' : 'lax', // Allow cross-site cookies in production
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Helper to generate unique client codes (9-10 digits)
async function generateUniqueClientCode() {
  let code;
  let exists = true;
  while (exists) {
    code = String(Math.floor(100000000 + Math.random() * 900000000)); // 9 digits
    // Ensure uniqueness
    // eslint-disable-next-line no-await-in-loop
    exists = await UserModel.exists({ clientCode: code });
  }
  return code;
}

// Helper to generate 6-digit verification codes
function generateVerificationCode() {
  return String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
}

passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const user = await UserModel.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google OAuth Strategy Configuration
// NOTE: The branding name shown during Google OAuth login (e.g., "StockSathi" vs "stocksathi.onrender.com")
// is configured in Google Cloud Console under "APIs & Services" > "OAuth consent screen"
// 
// IMPORTANT FOR PRODUCTION:
// - The "App name" in OAuth consent screen must be explicitly set to "StockSathi" (not auto-generated)
// - Authorized domains must include your production domain (e.g., "render.com" and "stocksathi.onrender.com")
// - Changes may take 5-15 minutes to propagate globally
// - See README.md for detailed setup instructions
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await UserModel.findOne({ email: profile.emails[0].value });
    if (!user) {
      user = new UserModel({
        username: profile.displayName,
        email: profile.emails[0].value,
        provider: 'google',
        googleId: profile.id,
        avatar: profile.photos && profile.photos[0] ? profile.photos[0].value : undefined,
      });
      await user.save();
    } 
    else if (!user.googleId) {
      user.provider = 'google';
      user.googleId = profile.id;
      user.avatar = profile.photos && profile.photos[0] ? profile.photos[0].value : user.avatar;
      await user.save();
    }
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

// Google Auth Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/', session: true }),
  (req, res) => {
    (async () => {
      // Ensure clientCode exists for Google users as well
      if (!req.user.clientCode) {
        req.user.clientCode = await generateUniqueClientCode();
        await req.user.save();
      }
      // Create a simple token (or use session ID)
      const token = Buffer.from(`${req.user._id}-${Date.now()}`).toString('base64');
      // Pass user info and token as URL params
      const params = new URLSearchParams({
        token,
        user: JSON.stringify({
          id: req.user._id,
          name: req.user.username,
          email: req.user.email,
          clientCode: req.user.clientCode,
        }),
        isLoggedIn: 'true'
      });
      const dashboardURL = process.env.DASHBOARD_URL || 'http://localhost:5174';
      res.redirect(`${dashboardURL}/?${params.toString()}`);
    })();
  }
);

app.get('/auth/logout', (req, res) => {
  req.logout(() => {
    const frontendURL = process.env.FRONTEND_URL || 'http://localhost:5173';
    res.redirect(frontendURL); // Redirect to main landing home page
  });
});

app.get('/auth/me', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ user: req.user });
  } else {
    res.status(401).json({ user: null });
  }
});

// Middleware to handle authentication (both session and token)
const authenticateUser = async (req, res, next) => {
  try {
    // First check if user is authenticated via session (Passport.js)
    if (req.isAuthenticated()) {
      return next();
    }
    
    // If not authenticated via session, check for token in headers or user data in request
    const authHeader = req.headers.authorization;
    const userDataHeader = req.headers['x-user-data'];
    
    if (userDataHeader) {
      try {
        const userData = JSON.parse(decodeURIComponent(userDataHeader));
        if (userData.id) {
          // Find user in database to verify
          const user = await UserModel.findById(userData.id);
          if (user) {
            req.user = user;
            return next();
          }
        }
      } catch (error) {
        console.error('Error parsing user data header:', error);
      }
    }
    
    // If token is provided, try to validate it
    if (authHeader) {
      const token = authHeader.replace('Bearer ', '');
      try {
        // Decode the simple token (userId-timestamp format)
        const decoded = Buffer.from(token, 'base64').toString();
        const [userId] = decoded.split('-');
        
        const user = await UserModel.findById(userId);
        if (user) {
          req.user = user;
          return next();
        }
      } catch (error) {
        console.error('Error validating token:', error);
      }
    }
    
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  } catch (error) {
    console.error('Authentication middleware error:', error);
    return res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

// Test authentication endpoint
app.get('/api/auth/test', authenticateUser, (req, res) => {
  res.json({ 
    success: true, 
    message: 'Authentication successful', 
    user: {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email
    }
  });
});

// API endpoint to buy a stock
app.post('/api/orders/buy', authenticateUser, async (req, res) => {
  try {
    
    const { symbol, name, quantity, price } = req.body;
    
    if (!symbol || !name || !quantity || !price) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }
    
    // Create a new order
    const newOrder = new OrdersModel({
      userId: req.user._id,
      name: name,
      qty: quantity,
      price: price,
      mode: 'buy',
      timestamp: new Date()
    });
    
    await newOrder.save();
    
    // Check if user already has holdings for this stock
    let holding = await HoldingsModel.findOne({ 
      userId: req.user._id,
      name: name
    });
    
    if (holding) {
      // Update existing holding
      const totalShares = holding.qty + quantity;
      const totalCost = (holding.qty * holding.avg) + (quantity * price);
      const newAvgPrice = totalCost / totalShares;
      
      holding.qty = totalShares;
      holding.avg = newAvgPrice;
      holding.price = price; // Current price
      await holding.save();
    } else {
      // Create new holding
      const newHolding = new HoldingsModel({
        userId: req.user._id,
        name: name,
        qty: quantity,
        avg: price,
        price: price,
        net: '0%',
        day: '0%'
      });
      
      await newHolding.save();
    }
    
    res.status(201).json({ 
      success: true, 
      message: 'Order placed successfully',
      order: newOrder
    });
    
  } catch (error) {
    console.error('Error placing order:', error);
    res.status(500).json({ success: false, message: 'Failed to place order' });
  }
});

// API endpoint to sell a stock
app.post('/api/orders/sell', authenticateUser, async (req, res) => {
  try {
    
    const { symbol, name, quantity, price } = req.body;
    
    if (!symbol || !name || !quantity || !price) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }
    
    // Check if user has enough holdings to sell
    const holding = await HoldingsModel.findOne({ 
      userId: req.user._id,
      name: name
    });
    
    if (!holding || holding.qty < quantity) {
      return res.status(400).json({ 
        success: false, 
        message: 'Not enough shares to sell' 
      });
    }
    
    // Create a new sell order
    const newOrder = new OrdersModel({
      userId: req.user._id,
      name: name,
      qty: quantity,
      price: price,
      mode: 'sell',
      timestamp: new Date()
    });
    
    await newOrder.save();
    
    // Update holdings
    const remainingShares = holding.qty - quantity;
    
    if (remainingShares > 0) {
      // Update existing holding if shares remain
      holding.qty = remainingShares;
      holding.price = price; // Update current price
      await holding.save();
    } else {
      // Remove holding if all shares are sold
      await HoldingsModel.deleteOne({ _id: holding._id });
    }
    
    res.status(201).json({ 
      success: true, 
      message: 'Sell order placed successfully',
      order: newOrder
    });
    
  } catch (error) {
    console.error('Error placing sell order:', error);
    res.status(500).json({ success: false, message: 'Failed to place sell order' });
  }
});

// API endpoint to get all orders for a user
app.get('/api/orders', authenticateUser, async (req, res) => {
  try {
    const orders = await OrdersModel.find({ userId: req.user._id })
      .sort({ timestamp: -1 });
    
    res.json({ success: true, orders });
    
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch orders' });
  }
});

// API endpoint to get a specific order by ID
app.get('/api/orders/:orderId', authenticateUser, async (req, res) => {
  try {
    const { orderId } = req.params;
    
    const order = await OrdersModel.findOne({ 
      _id: orderId,
      userId: req.user._id 
    });
    
    if (!order) {
      return res.status(404).json({ 
        success: false, 
        message: 'Order not found' 
      });
    }
    
    // Create enhanced order object with additional fields for display
    const enhancedOrder = {
      ...order.toObject(),
      type: 'Delivery',
      subtype: 'Regular', 
      market: 'NSE',
      exchange: 'NSE',
      duration: 'Day',
      avgPrice: order.price, // For now, avg price same as order price
      mktPrice: order.price, // Current market price (could be fetched from live API)
      status: 'Executed', // All orders are executed in our system
      statusSteps: [
        {
          label: 'Request Verified',
          time: new Date(order.timestamp).toLocaleString('en-GB', { 
            hour: '2-digit', 
            minute: '2-digit',
            day: '2-digit',
            month: 'short'
          }),
          completed: true
        },
        {
          label: 'Order Placed with NSE',
          time: new Date(order.timestamp).toLocaleString('en-GB', { 
            hour: '2-digit', 
            minute: '2-digit',
            day: '2-digit',
            month: 'short'
          }),
          completed: true
        },
        {
          label: 'Order Executed',
          time: new Date(order.timestamp).toLocaleString('en-GB', { 
            hour: '2-digit', 
            minute: '2-digit',
            day: '2-digit',
            month: 'short'
          }),
          completed: true
        }
      ],
      trades: [
        {
          time: new Date(order.timestamp).toLocaleString('en-GB', { 
            hour: '2-digit', 
            minute: '2-digit'
          }),
          price: order.price,
          qty: order.qty,
          amount: order.price * order.qty
        }
      ],
      orderValue: order.price * order.qty
    };
    
    res.json({ success: true, order: enhancedOrder });
    
  } catch (error) {
    console.error('Error fetching order:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch order details' });
  }
});

// API endpoint to get all holdings for a user
app.get('/api/holdings', authenticateUser, async (req, res) => {
  try {
    
    const holdings = await HoldingsModel.find({ userId: req.user._id });
    
    res.json({ success: true, holdings });
    
  } catch (error) {
    console.error('Error fetching holdings:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch holdings' });
  }
});

// Get user profile by ID
app.get('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const user = await UserModel.findById(id);
    if (!user) return res.status(404).json({ success:false, message:'User not found' });

    return res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        dateOfBirth: user.dateOfBirth,
        gender: user.gender,
        phone: user.phone,
        clientCode: user.clientCode,
        pan: user.pan,
        maritalStatus: user.maritalStatus,
        fatherName: user.fatherName,
        demat: user.demat,
        incomeRange: user.incomeRange,
        avatar: user.avatar
      }
    });
  } catch (err) {
    console.error('❌ Error fetching user profile:', err);
    res.status(500).json({ success:false, message:'Server error' });
  }
});

// Update user profile
app.put('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const allowed = [
      'username','email','dateOfBirth','gender','phone','pan','maritalStatus','fatherName','demat','incomeRange','avatar'
    ];
    const update = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) update[key] = req.body[key];
    }

    // If dateOfBirth is a string, try to convert to Date
    if (update.dateOfBirth && typeof update.dateOfBirth === 'string') {
      const d = new Date(update.dateOfBirth);
      if (!isNaN(d)) update.dateOfBirth = d;
    }

    const user = await UserModel.findByIdAndUpdate(id, update, { new: true });
    if (!user) return res.status(404).json({ success:false, message:'User not found' });

    return res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        dateOfBirth: user.dateOfBirth,
        gender: user.gender,
        phone: user.phone,
        clientCode: user.clientCode,
        pan: user.pan,
        maritalStatus: user.maritalStatus,
        fatherName: user.fatherName,
        demat: user.demat,
        incomeRange: user.incomeRange,
        avatar: user.avatar
      }
    });
  } catch (err) {
    console.error('❌ Error updating user profile:', err);
    res.status(500).json({ success:false, message:'Server error' });
  }
});

// Add test endpoint
app.get("/api/test", (req, res) => {
  res.json({ message: "Backend is running!" });
});

// Health check + email debug (http://localhost:3000/api/health)
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "OK", 
    timestamp: new Date().toISOString(),
    clientsConnected: connectedClients,
    stocksTracked: currentStockData.size,
    environment: process.env.NODE_ENV || 'development',
    email: {
      ready: emailService.isInitialized && emailService.apiKey,
      provider: 'Brevo',
      sender: emailService.senderEmail || process.env.BREVO_SENDER_EMAIL,
      BREVO_API_KEY_set: !!process.env.BREVO_API_KEY,
      BREVO_SENDER_EMAIL_set: !!(process.env.BREVO_SENDER_EMAIL || process.env.EMAIL_FROM),
      hint: !process.env.BREVO_API_KEY ? 'Add BREVO_API_KEY + BREVO_SENDER_EMAIL to .env' : null
    }
  });
});

// Email debug - same info (http://localhost:3000/api/email/debug)
app.get(["/api/email/debug", "/api/emaildebug"], (req, res) => {
  res.json({
    emailReady: emailService.isInitialized && emailService.apiKey,
    provider: 'Brevo',
    BREVO_API_KEY_set: !!process.env.BREVO_API_KEY,
    BREVO_SENDER_EMAIL: process.env.BREVO_SENDER_EMAIL || process.env.EMAIL_FROM || 'gjain0229@gmail.com',
    setup: '1. Get API key: app.brevo.com → SMTP & API → API Keys. 2. Add sender: Senders & IP → verify gjain0229@gmail.com. 3. Add to .env: BREVO_API_KEY, BREVO_SENDER_EMAIL'
  });
});

// WebSocket test endpoint
app.get("/api/ws-test", (req, res) => {
  res.json({ 
    status: "OK", 
    message: "WebSocket server is running",
    clientsConnected: connectedClients,
    stocksTracked: currentStockData.size,
    timestamp: new Date().toISOString()
  });
});

// Add database test endpoint
app.get("/api/test-db", async (req, res) => {
  try {
    const dbState = mongoose.connection.readyState;
    const states = {
      0: "disconnected",
      1: "connected", 
      2: "connecting",
      3: "disconnecting"
    };
    
    res.json({ 
      message: "Database connection test",
      status: states[dbState] || "unknown",
      readyState: dbState,
      connected: dbState === 1
    });
  } catch (error) {
    res.status(500).json({ 
      error: "Database test failed", 
      details: error.message 
    });
  }
});

// Use .env variable for MongoDB connection
mongoose.connect(uri)
.then(() => {
  console.log("✅ Connected to MongoDB successfully!");
})
.catch((err) => {
  console.error("❌ MongoDB connection error:", err);
  console.log("💡 Make sure MongoDB is running on your system");
});

// Secure password hashing with bcrypt
const hashPassword = async (password) => {
  const saltRounds = 12; // Higher number = more secure but slower
  return await bcrypt.hash(password, saltRounds);
};

const verifyPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

// app.get("/addHoldings", async (req, res) => {
//   let tempHoldings = [
//     {
//       name: "BHARTIARTL",
//       qty: 2,
//       avg: 538.05,
//       price: 541.15,
//       net: "+0.58%",
//       day: "+2.99%",
//     },
//     {
//       name: "HDFCBANK",
//       qty: 2,
//       avg: 1383.4,
//       price: 1522.35,
//       net: "+10.04%",
//       day: "+0.11%",
//     },
//     {
//       name: "HINDUNILVR",
//       qty: 1,
//       avg: 2335.85,
//       price: 2417.4,
//       net: "+3.49%",
//       day: "+0.21%",
//     },
//     {
//       name: "INFY",
//       qty: 1,
//       avg: 1350.5,
//       price: 1555.45,
//       net: "+15.18%",
//       day: "-1.60%",
//       isLoss: true,
//     },
//     {
//       name: "ITC",
//       qty: 5,
//       avg: 202.0,
//       price: 207.9,
//       net: "+2.92%",
//       day: "+0.80%",
//     },
//     {
//       name: "KPITTECH",
//       qty: 5,
//       avg: 250.3,
//       price: 266.45,
//       net: "+6.45%",
//       day: "+3.54%",
//     },
//     {
//       name: "M&M",
//       qty: 2,
//       avg: 809.9,
//       price: 779.8,
//       net: "-3.72%",
//       day: "-0.01%",
//       isLoss: true,
//     },
//     {
//       name: "RELIANCE",
//       qty: 1,
//       avg: 2193.7,
//       price: 2112.4,
//       net: "-3.71%",
//       day: "+1.44%",
//     },
//     {
//       name: "SBIN",
//       qty: 4,
//       avg: 324.35,
//       price: 430.2,
//       net: "+32.63%",
//       day: "-0.34%",
//       isLoss: true,
//     },
//     {
//       name: "SGBMAY29",
//       qty: 2,
//       avg: 4727.0,
//       price: 4719.0,
//       net: "-0.17%",
//       day: "+0.15%",
//     },
//     {
//       name: "TATAPOWER",
//       qty: 5,
//       avg: 104.2,
//       price: 124.15,
//       net: "+19.15%",
//       day: "-0.24%",
//       isLoss: true,
//     },
//     {
//       name: "TCS",
//       qty: 1,
//       avg: 3041.7,
//       price: 3194.8,
//       net: "+5.03%",
//       day: "-0.25%",
//       isLoss: true,
//     },
//     {
//       name: "WIPRO",
//       qty: 4,
//       avg: 489.3,
//       price: 577.75,
//       net: "+18.08%",
//       day: "+0.32%",
//     },
//   ];

//   tempHoldings.forEach((item) => {
//     let newHolding = new HoldingsModel({
//       name: item.name,
//       qty: item.qty,
//       avg: item.avg,
//       price: item.price,
//       net: item.day,
//       day: item.day,
//     });

//     newHolding.save();
//   });
//   res.send("Done!");
// });

// app.get("/addPositions", async (req, res) => {
//   let tempPositions = [
//     {
//       product: "CNC",
//       name: "EVEREADY",
//       qty: 2,
//       avg: 316.27,
//       price: 312.35,
//       net: "+0.58%",
//       day: "-1.24%",
//       isLoss: true,
//     },
//     {
//       product: "CNC",
//       name: "JUBLFOOD",
//       qty: 1,
//       avg: 3124.75,
//       price: 3082.65,
//       net: "+10.04%",
//       day: "-1.35%",
//       isLoss: true,
//     },
//   ];

//   tempPositions.forEach((item) => {
//     let newPosition = new PositionsModel({
//       product: item.product,
//       name: item.name,
//       qty: item.qty,
//       avg: item.avg,
//       price: item.price,
//       net: item.net,
//       day: item.day,
//       isLoss: item.isLoss,
//     });

//     newPosition.save();
//   });
//   res.send("Done!");
// });

app.get("/allHoldings", async (req, res) => {
  try {
    const { userId } = req.query;
    console.log("📊 Fetching holdings for userId:", userId);
    
    if (!userId || userId === 'undefined' || userId === 'null') {
      console.log("❌ No valid userId provided, returning empty array");
      return res.status(200).json([]);
    }
    
    // Check if MongoDB is connected
    if (mongoose.connection.readyState !== 1) {
      console.error("❌ MongoDB not connected. ReadyState:", mongoose.connection.readyState);
      return res.status(500).json({ 
        error: "Database connection not available", 
        details: "MongoDB is not connected. Please check if MongoDB is running." 
      });
    }
    
    let allHoldings = await HoldingsModel.find({ userId });
    console.log(`✅ Found ${allHoldings.length} holdings for user ${userId}`);
    res.json(allHoldings);
  } catch (error) {
    console.error("❌ Error fetching holdings:", error);
    console.error("Error details:", {
      name: error.name,
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ 
      error: "Failed to fetch holdings", 
      details: error.message,
      type: error.name
    });
  }
});

app.get("/allPositions", async (req, res) => {
  let allPositions = await PositionsModel.find({});
  res.json(allPositions);
});

// Authentication endpoints
app.post("/api/users/register", async (req, res) => {
  try {
    const { name, email, password, provider } = req.body;
    if (provider === 'google') {
      return res.status(400).json({ success: false, message: "Google signup is not allowed here. Use 'Continue with Google' instead." });
    }
    
    console.log("🔍 Registration attempt:", { name, email, password: password ? "PROVIDED" : "MISSING" });
    
    // Validate input
    if (!name || !email || !password) {
      console.log("❌ Missing required fields");
      return res.status(400).json({ 
        success: false, 
        message: "Name, email, and password are required" 
      });
    }
    
    // Check if user already exists by email only (names can be the same)
    const existingUser = await UserModel.findOne({ email });
    
    if (existingUser) {
      console.log("❌ User with email already exists:", existingUser.email);
      return res.status(400).json({ 
        success: false, 
        message: "User with this email already exists" 
      });
    }
    
    console.log("✅ No existing user found, creating new user...");
    
    // Create new user
    const hashedPassword = await hashPassword(password);
    const newUser = new UserModel({
      username: name,
      email,
      password: hashedPassword,
      clientCode: await generateUniqueClientCode()
    });
    
    console.log("💾 Saving new user to database...");
    await newUser.save();
    console.log("✅ User saved successfully:", { id: newUser._id, username: newUser.username, email: newUser.email });
    
    // Create a simple token (in production, use JWT)
    const token = Buffer.from(`${newUser._id}-${Date.now()}`).toString('base64');
    
    // Generate and send verification code
    const verificationCode = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    
    newUser.emailVerificationCode = verificationCode;
    newUser.emailVerificationExpires = expiresAt;
    await newUser.save();
    
    // Send verification email using Resend (recipient = the user's email)
    console.log('[REGISTER] Email check:', { initialized: emailService.isInitialized, hasKey: !!emailService.apiKey, recipient: newUser.email });
    if (emailService.isInitialized && emailService.apiKey) {
      try {
        const recipientEmail = (newUser.email || '').trim();
        if (!recipientEmail) {
          console.error('[REGISTER] ❌ Cannot send: user email is empty');
        } else {
          await emailService.sendVerificationEmail({
            email: recipientEmail,
            verificationCode: verificationCode,
            isWelcome: true
          });
          console.log('[REGISTER] ✅ Verification email sent to:', recipientEmail);
        }
      } catch (emailError) {
        console.error('[REGISTER] ❌ Failed to send verification email:', emailError?.message || emailError);
        console.error('[REGISTER] Full error:', emailError);
      }
    } else {
      console.warn('[REGISTER] ⚠️ Email NOT configured. Add BREVO_API_KEY + BREVO_SENDER_EMAIL to .env');
    }
    
    res.json({ 
      success: true, 
      message: "User created successfully. Please check your email for verification code.",
      token: token,
      user: {
        id: newUser._id,
        name: newUser.username,
        email: newUser.email,
        clientCode: newUser.clientCode,
        role: "user",
        isEmailVerified: newUser.isEmailVerified
      }
    });
  } catch (error) {
    console.error("❌ Error in signup:", error);
    console.error("Error details:", {
      name: error.name,
      message: error.message,
      code: error.code,
      keyPattern: error.keyPattern
    });
    
    // Provide more specific error messages
    if (error.code === 11000) {
      // Duplicate key error
      const field = Object.keys(error.keyPattern)[0];
      console.log("🔍 Duplicate key error for field:", field);
      return res.status(400).json({ 
        success: false, 
        message: `${field} already exists` 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: "Error creating user",
      error: error.message 
    });
  }
});

app.post("/api/users/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user by email
    const user = await UserModel.findOne({ email });
    
    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: "User not found" 
      });
    }
    
    // Verify password
    if (!await verifyPassword(password, user.password)) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid password" 
      });
    }
    
    // Check if email is verified
    if (!user.isEmailVerified) {
      return res.status(400).json({ 
        success: false, 
        message: "Please verify your email address before logging in" 
      });
    }
    
    // Ensure clientCode exists
    if (!user.clientCode) {
      user.clientCode = await generateUniqueClientCode();
      await user.save();
    }
    // Create a simple token (in production, use JWT)
    const token = Buffer.from(`${user._id}-${Date.now()}`).toString('base64');
    
    res.json({ 
      success: true, 
      message: "Login successful",
      token: token,
      user: {
        id: user._id,
        name: user.username,
        email: user.email,
        clientCode: user.clientCode,
        role: "user"
      }
    });
  } catch (error) {
    console.error("Error in login:", error);
    res.status(500).json({ success: false, message: "Error during login" });
  }
});

// Send email verification code
app.post('/api/users/send-verification-code', async (req, res) => {
  try {
    const { email } = req.body;
    const recipientEmail = (email || '').trim();
    console.log('[SEND-VERIFY] Request:', { emailFromBody: email, recipientEmail });

    if (!recipientEmail || !recipientEmail.includes('@')) {
      console.log('[SEND-VERIFY] ❌ Invalid email');
      return res.status(400).json({ success: false, message: 'Valid email is required' });
    }

    const user = await findUserByEmail(recipientEmail);
    if (!user) {
      console.log('[SEND-VERIFY] ❌ User not found for:', recipientEmail);
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Generate 6-digit verification code
    const verificationCode = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    
    // Save code to user
    user.emailVerificationCode = verificationCode;
    user.emailVerificationExpires = expiresAt;
    await user.save();
    
    // Send email with verification code using Resend
    if (!emailService.isInitialized || !emailService.apiKey) {
      return res.status(500).json({ success: false, message: 'Email not configured. Add BREVO_API_KEY to .env' });
    }
    
    try {
      await emailService.sendVerificationEmail({
        email: user.email,
        verificationCode: verificationCode,
        isWelcome: false
      });
      console.log('[SEND-VERIFY] ✅ Sent to:', user.email);
    } catch (emailError) {
      console.error('[SEND-VERIFY] ❌ Email send failed:', emailError?.message || emailError);
      return res.status(500).json({ success: false, message: 'Failed to send verification email' });
    }

    res.json({ success: true, message: 'Verification code sent to your email' });
  } catch (err) {
    console.error('[SEND-VERIFY] ❌ Error:', err);
    res.status(500).json({ success: false, message: 'Failed to send verification code' });
  }
});

// Verify email with code
app.post('/api/users/verify-email', async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({ success: false, message: 'Email and code are required' });
    }
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Check if code is valid and not expired
    if (user.emailVerificationCode !== code) {
      return res.status(400).json({ success: false, message: 'Invalid verification code' });
    }
    
    if (user.emailVerificationExpires < new Date()) {
      return res.status(400).json({ success: false, message: 'Verification code has expired' });
    }
    
    // Update user as verified
    user.isEmailVerified = true;
    user.emailVerificationCode = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();
    
    res.json({ success: true, message: 'Email verified successfully' });
  } catch (err) {
    console.error('❌ Error verifying email:', err);
    res.status(500).json({ success: false, message: 'Failed to verify email' });
  }
});

// Send password reset code
app.post('/api/users/send-password-reset-code', async (req, res) => {
  try {
    const { email } = req.body;
    const recipientEmail = (email || '').trim();
    console.log('[PWD-RESET] Request:', { recipientEmail });

    if (!recipientEmail || !recipientEmail.includes('@')) {
      return res.status(400).json({ success: false, message: 'Valid email is required' });
    }

    const user = await findUserByEmail(recipientEmail);
    if (!user) {
      // For security, we don't reveal if the email exists or not
      return res.json({ success: true, message: 'If the email exists, a reset code has been sent' });
    }
    
    // Generate 6-digit reset code
    const resetCode = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    
    // Save code to user
    user.passwordResetCode = resetCode;
    user.passwordResetExpires = expiresAt;
    await user.save();
    
    // Send email with reset code using Resend
    if (!emailService.isInitialized || !emailService.apiKey) {
      return res.status(500).json({ success: false, message: 'Email not configured. Add BREVO_API_KEY to .env' });
    }
    
    try {
      await emailService.sendPasswordResetEmail({
        email: user.email,
        resetCode: resetCode
      });
      console.log('[PWD-RESET] ✅ Sent to:', user.email);
    } catch (emailError) {
      console.error('[PWD-RESET] ❌ Email send failed:', emailError?.message || emailError);
      return res.status(500).json({ success: false, message: 'Failed to send password reset email' });
    }
    
    res.json({ success: true, message: 'Password reset code sent to your email' });
  } catch (err) {
    console.error('❌ Error sending password reset code:', err);
    res.status(500).json({ success: false, message: 'Failed to send password reset code' });
  }
});

// Reset password with code
app.post('/api/users/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    
    // Validate input
    if (!email || !code || !newPassword) {
      return res.status(400).json({ success: false, message: 'Email, code, and new password are required' });
    }
    
    // Validate password strength
    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long' });
    }
    
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Check if code is valid and not expired
    if (user.passwordResetCode !== code) {
      return res.status(400).json({ success: false, message: 'Invalid reset code' });
    }
    
    if (user.passwordResetExpires < new Date()) {
      return res.status(400).json({ success: false, message: 'Reset code has expired' });
    }
    
    // Hash new password
    const hashedPassword = await hashPassword(newPassword);
    
    // Update user password and clear reset code
    user.password = hashedPassword;
    user.passwordResetCode = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (err) {
    console.error('❌ Error resetting password:', err);
    res.status(500).json({ success: false, message: 'Failed to reset password' });
  }
});

app.get("/allOrders", async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ error: "User ID is required" });
    }
    
    let allOrders = await OrdersModel.find({ userId }).sort({ timestamp: -1 });
    res.json(allOrders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});

// Check if user exists
app.get("/user/:userId", async (req, res) => {
  try {
    const user = await UserModel.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
    res.json({ 
      success: true, 
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email 
      } 
    });
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ success: false, message: "Error fetching user" });
  }
});

// Add Twelve Data price API endpoint
app.get('/api/price/:symbol', async (req, res) => {
  const symbol = req.params.symbol;
  const apiKey = process.env.TWELVE_DATA_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'API key not set in .env' });
  }
  try {
    const url = `https://api.twelvedata.com/price?symbol=${symbol}.NSE&apikey=${apiKey}`;
    const response = await fetch(url);
    const data = await response.json();
    if (data.price) {
      res.json({ price: data.price });
    } else {
      res.status(404).json({ error: data.message || 'Price not found' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Helper to fetch live price internally
async function getLivePrice(symbol) {
  try {
    const apiKey = process.env.TWELVE_DATA_API_KEY;
    if (!apiKey) return null;
    const url = `https://api.twelvedata.com/price?symbol=${symbol}.NSE&apikey=${apiKey}`;
    const response = await fetch(url);
    const data = await response.json();
    if (data && data.price) {
      return parseFloat(data.price);
    }
    return null;
  } catch (err) {
    return null;
  }
}

// Positions API - derive from holdings for the user with live prices
app.get("/positions", async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(200).json([]);
    }

    if (mongoose.connection.readyState !== 1) {
      return res.status(500).json({ error: "Database connection not available" });
    }

    const userHoldings = await HoldingsModel.find({ userId });
    // Build positions array with live price if possible
    const positions = await Promise.all(userHoldings.map(async (h) => {
      const livePrice = await getLivePrice(h.name) || h.price || h.avg;
      const quantity = h.qty || 0;
      const avgPrice = h.avg || 0;
      const value = livePrice * quantity;
      const pnl = (livePrice - avgPrice) * quantity;
      return {
        product: "CNC",
        name: h.name,
        qty: quantity,
        avg: avgPrice,
        ltp: livePrice,
        value,
        pnl,
        // placeholders for day change if previous close not tracked
        dayChangePct: null,
        isLoss: pnl < 0,
      };
    }));

    res.json(positions);
  } catch (error) {
    console.error("❌ Error fetching positions:", error);
    res.status(500).json({ error: "Failed to fetch positions" });
  }
});

// Square-off (close) a position entirely for a user
app.post("/positions/close", async (req, res) => {
  try {
    const { userId, name } = req.body;
    if (!userId || !name) {
      return res.status(400).json({ success: false, message: "userId and name are required" });
    }

    const holding = await HoldingsModel.findOne({ userId, name });
    if (!holding || holding.qty <= 0) {
      return res.status(400).json({ success: false, message: "No open position to square off" });
    }

    const sellQty = holding.qty;
    const livePrice = await getLivePrice(name) || holding.price || holding.avg || 0;

    // Record an order entry for SELL
    const sellOrder = new OrdersModel({
      userId,
      name,
      qty: sellQty,
      price: livePrice,
      mode: "SELL",
      timestamp: new Date()
    });
    await sellOrder.save();

    // Remove or reduce holding to 0
    await HoldingsModel.deleteOne({ _id: holding._id });

    res.json({ success: true, message: "Position squared off", soldQty: sellQty, price: livePrice });
  } catch (error) {
    console.error("❌ Error squaring off position:", error);
    res.status(500).json({ success: false, message: "Failed to square off position" });
  }
});

// Partial close a position
app.post("/positions/partial-close", async (req, res) => {
  try {
    const { userId, name, qty } = req.body;
    const quantity = parseInt(qty, 10);
    if (!userId || !name || !quantity || quantity <= 0) {
      return res.status(400).json({ success: false, message: "userId, name and positive qty are required" });
    }

    const holding = await HoldingsModel.findOne({ userId, name });
    if (!holding || holding.qty <= 0) {
      return res.status(400).json({ success: false, message: "No open position to close" });
    }
    if (quantity > holding.qty) {
      return res.status(400).json({ success: false, message: "Cannot sell more than held quantity" });
    }

    const livePrice = await getLivePrice(name) || holding.price || holding.avg || 0;

    const sellOrder = new OrdersModel({
      userId,
      name,
      qty: quantity,
      price: livePrice,
      mode: "SELL",
      timestamp: new Date()
    });
    await sellOrder.save();

    holding.qty = holding.qty - quantity;
    if (holding.qty <= 0) {
      await HoldingsModel.deleteOne({ _id: holding._id });
    } else {
      holding.price = livePrice;
      await holding.save();
    }

    res.json({ success: true, message: "Partial position closed", soldQty: quantity, price: livePrice });
  } catch (error) {
    console.error("❌ Error partial closing position:", error);
    res.status(500).json({ success: false, message: "Failed to partial close position" });
  }
});

app.post("/newOrder", async (req, res) => {
  try {
    const { userId, name, qty, price, mode } = req.body;
    if (!userId) {
      return res.status(400).json({ success: false, message: "User ID is required" });
    }
    // For BUY orders, validate price against live market price
    if (mode === "BUY") {
      const apiKey = process.env.TWELVE_DATA_API_KEY;
      const url = `https://api.twelvedata.com/price?symbol=${name}.NSE&apikey=${apiKey}`;
      const response = await fetch(url);
      const data = await response.json();
      if (!data.price) {
        return res.status(400).json({ success: false, message: data.message || 'Live price unavailable' });
      }
      const livePrice = parseFloat(data.price);
      if (parseFloat(price) < livePrice) {
        return res.status(400).json({ success: false, message: `Buy price (₹${price}) cannot be below live market price (₹${livePrice})` });
      }
    }
    // Save the order
    let newOrder = new OrdersModel({
      userId: userId,
      name: name,
      qty: qty,
      price: price,
      mode: mode,
    });

    await newOrder.save();

    // If it's a BUY order, update holdings
    if (mode === "BUY") {
      // Check if the stock already exists in holdings for this user
      let existingHolding = await HoldingsModel.findOne({ 
        name: name, 
        userId: userId 
      });
      
      if (existingHolding) {
        // Update existing holding - calculate new average price
        const totalQty = existingHolding.qty + parseInt(qty);
        const totalValue = (existingHolding.avg * existingHolding.qty) + (parseFloat(price) * parseInt(qty));
        const newAvgPrice = totalValue / totalQty;
        
        existingHolding.qty = totalQty;
        existingHolding.avg = newAvgPrice;
        existingHolding.price = parseFloat(price); // Update current price
        await existingHolding.save();
      } else {
        // Create new holding
        let newHolding = new HoldingsModel({
          userId: userId,
          name: name,
          qty: parseInt(qty),
          avg: parseFloat(price),
          price: parseFloat(price),
          net: "+0.00%",
          day: "+0.00%",
        });
        await newHolding.save();
      }
    }
    // If it's a SELL order, update holdings
    else if (mode === "SELL") {
      let existingHolding = await HoldingsModel.findOne({ 
        name: name, 
        userId: userId 
      });
      if (!existingHolding) {
        return res.status(400).json({ success: false, message: "No holdings to sell for this stock." });
      }
      const sellQty = parseInt(qty);
      if (sellQty > existingHolding.qty) {
        return res.status(400).json({ success: false, message: "Cannot sell more than you own." });
      }
      existingHolding.qty -= sellQty;
      existingHolding.price = parseFloat(price); // Update current price
      if (existingHolding.qty === 0) {
        await HoldingsModel.deleteOne({ _id: existingHolding._id });
      } else {
        await existingHolding.save();
      }
    }

    res.json({ success: true, message: "Order saved and holdings updated!" });
  } catch (error) {
    console.error("Error processing order:", error);
    res.status(500).json({ success: false, message: "Error processing order" });
  }
});

// Test stock data endpoint
app.get("/api/stocks/test", async (req, res) => {
  try {
    console.log('Testing stock data fetch');
    // Test with a few known symbols
    const testSymbols = ['RELIANCE.NS', 'HDFCBANK.NS', 'TCS.NS'];
    const results = await Promise.all(
      testSymbols.map(async (symbol) => {
        try {
          console.log('Fetching data for:', symbol);
          const data = await yahooFinance.quote(symbol);
          console.log('Received data for:', symbol, data.regularMarketPrice);
          return {
            symbol,
            price: data.regularMarketPrice,
            name: data.shortName,
            success: true
          };
        } catch (error) {
          console.error('Error fetching data for:', symbol, error.message);
          return {
            symbol,
            error: error.message,
            success: false
          };
        }
      })
    );
    
    res.json({ 
      success: true,
      timestamp: new Date().toISOString(),
      results
    });
  } catch (error) {
    console.error('Error in stock test endpoint:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Register stockRoutes before the hardcoded endpoints
app.use('/api/stocks', stockRoutes);

app.post("/api/users/change-password", async (req, res) => {
  try {
    const { email, currentPassword, newPassword } = req.body;
    console.log('🔑 Change password request:', { email, currentPassword: !!currentPassword, newPassword: !!newPassword });
    if (!email || !currentPassword || !newPassword) {
      console.log('❌ Missing required fields');
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    const user = await UserModel.findOne({ email });
    if (!user) {
      console.log('❌ User not found for email:', email);
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const isMatch = await verifyPassword(currentPassword, user.password);
    if (!isMatch) {
      console.log('❌ Current password is incorrect for user:', email);
      return res.status(400).json({ success: false, message: "Current password is incorrect" });
    }

    const newHash = await hashPassword(newPassword);
    user.password = newHash;
    await user.save();
    console.log('✅ Password updated for user:', email);

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    console.error("❌ Error changing password:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// Support contact endpoint - sends emails from contact form
app.post('/api/support/contact', async (req, res) => {
  const startTime = Date.now();
  
  try {
    console.log('📧 Support contact request received:', {
      timestamp: new Date().toISOString(),
      body: { 
        name: req.body?.name, 
        email: req.body?.email, 
        subject: req.body?.subject,
        purpose: req.body?.purpose,
        hasMessage: !!req.body?.message
      }
    });

    const { name, email, subject, purpose, message } = req.body || {};
    
    // Validate input
    if (!name || !email || !message) {
      console.warn('⚠️ Validation failed: Missing required fields', {
        hasName: !!name,
        hasEmail: !!email,
        hasMessage: !!message
      });
      return res.status(400).json({ 
        success: false, 
        message: 'Name, email and message are required' 
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.warn('⚠️ Validation failed: Invalid email format', { email });
      return res.status(400).json({ 
        success: false, 
        message: 'Please provide a valid email address' 
      });
    }

    // Check if email service is configured
    if (!emailService.isInitialized || !emailService.apiKey) {
      console.error('❌ Email not configured. Add BREVO_API_KEY and BREVO_SENDER_EMAIL to .env');
      return res.status(500).json({ 
        success: false, 
        message: 'Email service is not configured on the server. Please contact support directly at gjain0229@gmail.com' 
      });
    }

    // Send email using the email service
    console.log('📤 Sending support email...');
    const emailResult = await emailService.sendSupportEmail({
      name: name.trim(),
      email: email.trim(),
      subject: subject?.trim(),
      purpose: purpose?.trim() || 'General inquiry',
      message: message.trim()
    });

    const duration = Date.now() - startTime;
    
    // Verify email was actually accepted
    if (!emailResult.accepted || emailResult.accepted.length === 0) {
      console.error('❌ Email was not accepted:', emailResult);
      throw new Error('Email was rejected by the email service. Please check the recipient address.');
    }
    
    console.log(`✅ Support email sent successfully in ${duration}ms:`, {
      messageId: emailResult.messageId,
      accepted: emailResult.accepted,
      from: email,
      to: process.env.SUPPORT_TO || 'gjain0229@gmail.com'
    });

    return res.json({ 
      success: true, 
      message: 'Message sent successfully. We will get back to you shortly.',
      messageId: emailResult.messageId
    });

  } catch (err) {
    const duration = Date.now() - startTime;
    console.error(`❌ Support email endpoint error (${duration}ms):`, {
      message: err.message || err.userMessage,
      code: err.code,
      responseCode: err.responseCode,
      responseMessage: err.responseMessage,
      stack: err.stack,
      originalError: err.originalError,
      // Additional debugging info
      emailServiceStatus: {
        isInitialized: emailService.isInitialized,
        hasApiKey: !!emailService.apiKey,
        apiKeyPrefix: emailService.apiKey ? emailService.apiKey.substring(0, 10) + '...' : 'missing'
      }
    });
    
    // Return user-friendly error message
    let errorMessage = err.userMessage || err.message || 'An unexpected error occurred. Please try again later.';
    
    // Don't append the contact email if it's already in the message
    if (!errorMessage.includes('gjain0229@gmail.com')) {
      errorMessage += ' If the problem persists, please contact support directly at gjain0229@gmail.com';
    }
    
    return res.status(500).json({ 
      success: false, 
      message: errorMessage,
      error: process.env.NODE_ENV === 'development' ? {
        message: err.message,
        code: err.code,
        responseCode: err.responseCode,
        responseMessage: err.responseMessage
      } : undefined
    });
  }
});

// FAQs endpoint - beginner-friendly FAQs for Help & Support
app.get('/api/support/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        id: 'what-is-a-stock',
        question: 'What is a stock?',
        answer:
          'A stock represents a small ownership share in a company. When you buy a stock, you own a portion of that company and may benefit if the company grows in value.'
      },
      {
        id: 'how-do-stocks-make-money',
        question: 'How can I make money from stocks?',
        answer:
          'You can potentially earn through capital gains (selling at a higher price than you bought) and dividends (periodic payouts companies may distribute to shareholders).'
      },
      {
        id: 'what-is-diversification',
        question: 'What is diversification and why is it important?',
        answer:
          'Diversification means spreading your investments across different companies, sectors, or asset classes. It helps reduce risk because poor performance in one area can be offset by better performance in another.'
      },
      {
        id: 'what-is-volatility',
        question: 'What does market volatility mean?',
        answer:
          'Volatility is how much and how quickly prices move. High volatility means prices can change rapidly in either direction, which can increase both risk and opportunity.'
      },
      {
        id: 'long-term-vs-short-term',
        question: 'Is stock investing better for the long term or short term?',
        answer:
          'While strategies vary, many investors focus on long-term investing to smooth out short-term ups and downs and benefit from compound growth over time.'
      },
      {
        id: 'what-is-stop-loss',
        question: 'What is a stop-loss order?',
        answer:
          'A stop-loss is an order that automatically sells your stock if it falls to a set price. It helps limit potential losses and manage risk.'
      },
      {
        id: 'how-much-to-invest',
        question: 'How much should I invest as a beginner?',
        answer:
          'Start small and only invest money you can afford to leave invested for a while. Focus on learning, building discipline, and diversifying as your knowledge grows.'
      },
      {
        id: 'what-are-fees',
        question: 'Are there any fees when trading stocks?',
        answer:
          'Depending on your broker and market, you may pay brokerage, taxes, and other regulatory charges. Always review the fee breakdown before placing orders.'
      }
    ];

    res.json({ success: true, items: faqs });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to load FAQs' });
  }
});

// Real-time stock data management
const stockSymbols = [
  'RELIANCE.NS', 'HDFCBANK.NS', 'ICICIBANK.NS', 'TCS.NS', 'BHARTIARTL.NS',
  'INFY.NS', 'ITC.NS', 'KOTAKBANK.NS', 'LT.NS', 'SBIN.NS', 'AXISBANK.NS',
  'HINDUNILVR.NS', 'BAJFINANCE.NS', 'HCLTECH.NS', 'MARUTI.NS', 'ASIANPAINT.NS',
  'SUNPHARMA.NS', 'TITAN.NS', 'ULTRACEMCO.NS', 'NTPC.NS', 'TATAMOTORS.NS',
  'POWERGRID.NS', 'TATASTEEL.NS', 'JSWSTEEL.NS', 'NESTLEIND.NS', 'HDFCLIFE.NS',
  'TECHM.NS', 'WIPRO.NS', 'BAJAJFINSV.NS', 'GRASIM.NS', 'ADANIGREEN.NS',
  'ADANIPORTS.NS', 'COALINDIA.NS', 'BPCL.NS', 'UPL.NS', 'HINDALCO.NS',
  'EICHERMOT.NS', 'DIVISLAB.NS', 'CIPLA.NS', 'BRITANNIA.NS', 'M&M.NS',
  'BAJAJ_AUTO.NS', 'HERO.NS', 'DRREDDY.NS', 'DABUR.NS', 'APOLLOHOSP.NS',
  'TATACONSUM.NS', 'ONGC.NS', 'INDUSINDBK.NS', 'HDFC.NS',
  '^NSEI', '^BSESN' // Add NIFTY 50 and SENSEX
];

let currentStockData = new Map();
let connectedClients = 0;

// Helper function to delay execution
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Map a single Yahoo quote result to our stock format
function mapQuoteToStock(data) {
  if (!data) return null;
  const symbol = data.symbol || '';
  const previousClose = data?.regularMarketPreviousClose || null;
  const regularMarketPrice = data?.regularMarketPrice || data?.currentPrice || null;
  if (!regularMarketPrice) return null;
  const lowerCircuit = previousClose ? Number((previousClose * 0.95).toFixed(2)) : null;
  const upperCircuit = previousClose ? Number((previousClose * 1.05).toFixed(2)) : null;
  let displaySymbol = symbol.replace('.NS', '');
  if (symbol === '^NSEI') displaySymbol = 'NIFTY 50';
  else if (symbol === '^BSESN') displaySymbol = 'SENSEX';
  return {
    symbol: displaySymbol,
    name: data?.shortName || displaySymbol,
    price: regularMarketPrice,
    change: data?.regularMarketChange ?? null,
    percentChange: data?.regularMarketChangePercent ?? null,
    previousClose,
    lowerCircuit,
    upperCircuit,
    volume: data?.regularMarketVolume ?? null,
    marketCap: data?.marketCap ?? null,
    lastUpdate: new Date().toISOString()
  };
}

// Fetch live stock data using ONE batch request (avoids Yahoo 429 rate limit)
async function fetchLiveStockData() {
  const maxRetries = 3;
  const baseDelay = 5000; // 5s initial backoff for rate limit

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`Fetching live stock data for ${stockSymbols.length} symbols (attempt ${attempt}/${maxRetries})`);
      // Single HTTP request for all symbols - avoids "Failed to get crumb" 429 from Yahoo
      const results = await yahooFinance.quote(stockSymbols, { return: 'array' });
      if (!results || !Array.isArray(results)) {
        throw new Error('Invalid quote response');
      }
      const validResults = results.map(mapQuoteToStock).filter(Boolean);

      // Update current data and emit changes
      if (validResults.length > 0) {
        validResults.forEach(stock => {
          currentStockData.set(stock.symbol, stock);
          io.emit('stockUpdate', stock);
        });
        io.emit('bulkStockUpdate', validResults);
        console.log(`✅ Updated ${validResults.length}/${stockSymbols.length} stocks at ${new Date().toLocaleTimeString()}`);
        return;
      }
      console.warn('⚠️  No valid results in quote response');
    } catch (error) {
      const isRateLimit = error.message?.includes('429') ||
                         error.message?.includes('Too Many Requests') ||
                         error.message?.includes('crumb') ||
                         error.status === 429 ||
                         error.code === 429;
      if (isRateLimit && attempt < maxRetries) {
        const backoffDelay = baseDelay * Math.pow(2, attempt - 1) + Math.random() * 2000;
        console.warn(`Rate limit (429) on batch request, retrying in ${Math.round(backoffDelay)}ms (attempt ${attempt}/${maxRetries})`);
        await delay(backoffDelay);
        continue;
      }
      console.error('❌ Error in fetchLiveStockData:', error.message);
      break;
    }
  }

  // No new data: emit cached data if available
  if (currentStockData.size > 0) {
    const fallbackData = Array.from(currentStockData.values());
    io.emit('bulkStockUpdate', fallbackData);
    console.log(`📦 Emitted ${fallbackData.length} cached stocks as fallback`);
  }
}

// WebSocket connection handling
io.on('connection', (socket) => {
  connectedClients++;
  console.log(`Client connected. Total clients: ${connectedClients}`);
  
  // Log connection details
  console.log('Socket connection details:', {
    id: socket.id,
    remoteAddress: socket.conn.remoteAddress,
    transport: socket.conn.transport.name
  });
  
  // Send current data to newly connected client
  if (currentStockData.size > 0) {
    const allStocks = Array.from(currentStockData.values());
    socket.emit('initialStockData', allStocks);
  }

  socket.on('disconnect', (reason) => {
    connectedClients--;
    console.log(`Client disconnected. Total clients: ${connectedClients}, Reason: ${reason}`);
  });

  socket.on('requestStockUpdate', () => {
    if (currentStockData.size > 0) {
      const allStocks = Array.from(currentStockData.values());
      socket.emit('bulkStockUpdate', allStocks);
    }
  });
  
  // Handle connection errors
  socket.on('error', (error) => {
    console.error('Socket error:', error);
  });
});

// Add better error handling for the HTTP server
server.on('error', (error) => {
  console.error('Server error:', error);
});

server.on('clientError', (error, socket) => {
  console.error('Client error:', error);
  socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

// One batch request per cycle - 60s interval to stay under Yahoo's rate limit
setInterval(fetchLiveStockData, 60000);

// Initial data fetch
fetchLiveStockData();

server.listen(PORT, () => {
  console.log(`Server started on port ${PORT}!`);
  console.log("DB started!");
  console.log("WebSocket server ready for real-time stock updates!");
  
  // Log email service status
  console.log('\n📧 Email (Brevo):');
  if (emailService.isInitialized && emailService.apiKey) {
    console.log('   ✅ Ready. Sends to ANY email. Sender:', emailService.senderEmail);
  } else {
    console.log('   ❌ Not configured. Add BREVO_API_KEY + BREVO_SENDER_EMAIL to .env');
  }
  console.log('');
});