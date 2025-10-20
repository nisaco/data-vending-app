// --- 1. IMPORTS AND SETUP ---
require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sgMail = require('@sendgrid/mail');
const axios = require('axios');
const cron = require('node-cron');
const { User, Order, mongoose } = require('./database.js'); // Import mongoose object

const app = express();
const PORT = process.env.PORT || 10000;

// --- 2. DATA (PLANS) - STATIC COST PRICE AND ID SETUP ---
const allPlans = {
    "MTN": [
        { id: '1', name: '1GB', price: 450 }, 
        { id: '2', name: '2GB', price: 930 }, 
        { id: '5', name: '5GB', price: 2300 }, 
        { id: '10', name: '10GB', price: 4200 }
    ],
    "AirtelTigo": [
        { id: '1', name: '1GB', price: 370 }, 
        { id: '2', name: '2GB', price: 750 }, 
        { id: '5', name: '5GB', price: 1930 }, 
        { id: '10', name: '10GB', price: 3600 }
    ],
    "Telecel": [
        { id: '5', name: '5GB', price: 2120 }, 
        { id: '10', name: '10GB', price: 4000 }, 
        { id: '15', name: '15GB', price: 5700 }, 
        { id: '20', name: '20GB', price: 7900 }
    ]
};

// --- HELPER: MAP INTERNAL NETWORK NAME TO API networkKey ---
const NETWORK_KEY_MAP = {
    "MTN": 'YELLO',
    "AirtelTigo": 'AT_PREMIUM', 
    "Telecel": 'TELECEL',
};

// --- HELPER FUNCTIONS (omitted for brevity, unchanged) ---
async function sendAdminAlertEmail(order) { /* ... implementation ... */ }
async function runPendingOrderCheck() { /* ... implementation ... */ }
async function executeDataPurchase(userId, orderDetails, paymentMethod) { /* ... implementation ... */ }


// --- 3. MIDDLEWARE ---
app.set('trust proxy', 1); 

const sessionSecret = process.env.SESSION_SECRET || 'fallback-secret-for-local-dev-only-12345';
app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true, maxAge: 1000 * 60 * 60 } 
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


// --- 4. DATA API ROUTES ---
const isAuthenticated = (req, res, next) => req.session.user ? next() : res.redirect('/login.html');

app.get('/api/data-plans', (req, res) => {
    // 🛑 DEBUG CHECK: This ensures allPlans is accessible
    if (Object.keys(allPlans).length === 0 || !allPlans[req.query.network]) {
         console.error('Data plans requested but allPlans object is empty or missing network data.');
         return res.json([]);
    }
    
    const costPlans = allPlans[req.query.network] || [];
    
    const sellingPlans = costPlans.map(p => {
        const FIXED_MARKUP = 20; 
        const rawSellingPrice = p.price + FIXED_MARKUP;
        const sellingPrice = Math.ceil(rawSellingPrice / 5) * 5; 
        
        return {
            id: p.id, 
            name: p.name,
            price: sellingPrice 
        };
    });

    res.json(sellingPlans);
});

// All other API routes (omitted for brevity, unchanged)
app.get('/api/my-orders', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
app.get('/api/get-all-orders', async (req, res) => { /* ... implementation ... */ });
app.get('/api/admin/all-users-status', async (req, res) => { /* ... implementation ... */ });
app.get('/api/admin/user-count', async (req, res) => { /* ... implementation ... */ });
app.post('/api/admin/update-order', async (req, res) => { /* ... implementation ... */ });
app.post('/paystack/verify', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
app.post('/api/wallet-purchase', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
app.post('/api/signup', async (req, res) => { /* ... implementation ... */ });
app.post('/api/login', async (req, res) => { /* ... implementation ... */ });
app.get('/api/logout', (req, res) => { /* ... implementation ... */ });
app.get('/api/user-info', isAuthenticated, async (req, res) => { /* ... implementation ... */ });


// --- 5. SERVER AND ROUTE DEFINITION ---
// Serve static routes (HTML files)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/purchase', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'purchase.html')));
app.get('/dashboard', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

// CRITICAL STEP: Only start the server and cron job once Mongoose confirms connection
mongoose.connection.once('open', () => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server is LIVE on port ${PORT}`);
        console.log('Database connection is stable. Starting cron job...');
    });
    // Start the cron job after the server is listening
    cron.schedule('*/5 * * * *', runPendingOrderCheck);
});
