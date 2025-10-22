// --- 1. IMPORTS AND SETUP ---
require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sgMail = require('@sendgrid/mail');
const axios = require('axios');
const cron = require('node-cron');
const { User, Order, mongoose } = require('./database.js'); 

const app = express();
const PORT = process.env.PORT || 10000;

// --- 2. DATA (PLANS) - STATIC COST PRICE AND ID SETUP (FINALIZED) ---
const allPlans = {
    // PRICES ARE THE WHOLESALE COST (in PESEWAS)
    
    // 1. MTN (No Markup, Final Costs)
    "MTN": [
        { id: '1', name: '1GB', price: 480 },  // ₵4.80
        { id: '2', name: '2GB', price: 960 },  // ₵9.60
        { id: '3', name: '3GB', price: 1420 }, // ₵14.20
        { id: '4', name: '4GB', price: 2000 }, // ₵20.00
        { id: '5', name: '5GB', price: 2400 }, // ₵24.00
        { id: '6', name: '6GB', price: 2800 }, // ₵28.00
        { id: '8', name: '8GB', price: 3600 }, // ₵36.00
        { id: '10', name: '10GB', price: 4400 },// ₵44.00
        { id: '15', name: '15GB', price: 6400 },
        { id: '20', name: '20GB', price: 8200 },
        { id: '25', name: '25GB', price: 10200 },
        { id: '30', name: '30GB', price: 12200 },
        { id: '40', name: '40GB', price: 16200 },
        { id: '50', name: '50GB', price: 19800 }
    ],

    // 2. AIRTELTIGO (Final Costs)
    "AirtelTigo": [
        { id: '1', name: '1GB', price: 400 },   // ₵4.00
        { id: '2', name: '2GB', price: 800 },   // ₵8.00
        { id: '3', name: '3GB', price: 1200 },  // ₵12.00
        { id: '4', name: '4GB', price: 1600 },  // ₵16.00
        { id: '5', name: '5GB', price: 2000 },  // ₵20.00
        { id: '6', name: '6GB', price: 2420 },  // ₵24.20
        { id: '7', name: '7GB', price: 2800 },  // ₵28.00
        { id: '8', name: '8GB', price: 3200 },  // ₵32.00
        { id: '9', name: '9GB', price: 3600 },  // ₵36.00
        { id: '10', name: '10GB', price: 4200 },// ₵42.00 (Adjusted ₵44 to ₵42 for cleaner round)
        { id: '12', name: '12GB', price: 5000 },// ₵50.00 (Adjusted ₵50 to ₵50)
        { id: '15', name: '15GB', price: 6200 },// ₵62.00
        { id: '20', name: '20GB', price: 8200 } // ₵82.00
    ],

    // 3. TELECEL (Final Costs)
    "Telecel": [
        { id: '5', name: '5GB', price: 2300 },   // ₵23.00
        { id: '10', name: '10GB', price: 4300 }, // ₵43.00
        { id: '15', name: '15GB', price: 6300 }, // ₵63.00
        { id: '20', name: '20GB', price: 8300 }, // ₵83.00
        { id: '25', name: '25GB', price: 10300 },// ₵103.00
        { id: '30', name: '30GB', price: 12300 },// ₵123.00
        { id: '40', name: '40GB', price: 15500 },// ₵155.00
        { id: '50', name: '50GB', price: 19500 },// ₵195.00
        { id: '100', name: '100GB', price: 39000}// ₵390.00
    ]
};

const NETWORK_KEY_MAP = {
    "MTN": 'YELLO', "AirtelTigo": 'AT_PREMIUM', "Telecel": 'TELECEL',
};


// --- HELPER FUNCTIONS ---
function findBaseCost(network, capacityId) {
    const networkPlans = allPlans[network];
    if (!networkPlans) return 0;
    const plan = networkPlans.find(p => p.id === capacityId);
    return plan ? plan.price : 0; 
}
function calculatePaystackFee(chargedAmountInPesewas) {
    const TRANSACTION_FEE_RATE = 0.0022; // 0.22%
    const TRANSACTION_FEE_CAP = 2000;
    
    let amountToCalculateFeeOn = chargedAmountInPesewas;
    let fullFee = (amountToCalculateFeeOn * TRANSACTION_FEE_RATE) + 80;
    
    let totalFeeChargedByPaystack = Math.min(fullFee, TRANSACTION_FEE_CAP);
    return totalFeeChargedByPaystack;
}
async function sendAdminAlertEmail(order) { /* ... implementation ... */ }
async function executeDataPurchase(userId, orderDetails, paymentMethod) { /* ... implementation ... */ }
async function runPendingOrderCheck() { /* ... implementation ... */ }


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


// --- 4. CORE ROUTE DEFINITION (IMMEDIATE START) ---
const isAuthenticated = (req, res, next) => req.session.user ? next() : res.redirect('/login.html');

// --- USER AUTHENTICATION & INFO ROUTES ---
app.post('/api/signup', async (req, res) => { /* ... implementation ... */ });
app.post('/api/login', async (req, res) => { /* ... implementation ... */ });
app.get('/api/logout', (req, res) => { /* ... implementation ... */ });
app.get('/api/user-info', isAuthenticated, async (req, res) => { /* ... implementation ... */ });


// --- DATA & PROTECTED PAGES ---
app.get('/api/data-plans', (req, res) => {
    const costPlans = allPlans[req.query.network] || [];
    
    const sellingPlans = costPlans.map(p => {
        const FIXED_MARKUP = 0; // ⬅️ FINAL FIX: ZERO MARKUP
        const rawSellingPrice = p.price + FIXED_MARKUP;
        const sellingPrice = Math.ceil(rawSellingPrice / 5) * 5; 
        
        return { id: p.id, name: p.name, price: sellingPrice };
    });

    res.json(sellingPlans);
});

app.get('/api/my-orders', isAuthenticated, async (req, res) => { /* ... implementation ... */ });


// --- WALLET & PAYMENT ROUTES ---
app.post('/api/topup', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
app.post('/api/wallet-purchase', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
app.post('/paystack/verify', isAuthenticated, async (req, res) => { /* ... implementation ... */ });


// --- ADMIN & MANAGEMENT ROUTES ---
app.get('/api/get-all-orders', async (req, res) => { /* ... implementation ... */ });
app.get('/api/admin/all-users-status', async (req, res) => { /* ... implementation ... */ });
app.get('/api/admin/user-count', async (req, res) => { /* ... implementation ... */ });
app.post('/api/admin/update-order', async (req, res) => { /* ... implementation ... */ });
app.get('/api/admin/metrics', async (req, res) => { /* ... implementation ... */ });


// --- SERVE HTML FILES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/purchase', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'purchase.html')));
app.get('/dashboard', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));


// --- SERVER START ---
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is LIVE on port ${PORT}`);
    console.log('Database connection is initializing...');
});

// Start the cron job after the server is listening
cron.schedule('*/5 * * * *', runPendingOrderCheck);
