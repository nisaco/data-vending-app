// --- 1. IMPORTS AND SETUP ---
require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sgMail = require('@sendgrid/mail');
const axios = require('axios');
const { User, Order } = require('./database.js'); 
const mongoose = require('mongoose'); 

const app = express();
const PORT = process.env.PORT || 10000;

// --- 2. DATA (PLANS) - STATIC COST PRICE AND ID SETUP ---
const allPlans = {
    // Note: The 'price' here is the WHOLESALE COST in PESEWAS.
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

// --- HELPER: REVERSE PAYSTACK FEE CALCULATION ---
// This is used to calculate the Paystack fee paid on an order.
function calculatePaystackFee(chargedAmountInPesewas) {
    const TRANSACTION_FEE_RATE = 0.019;
    const TRANSACTION_FEE_FLAT = 80; 
    const TRANSACTION_FEE_CAP = 2000;
    
    // We reverse the process used on the client-side to find the fee absorbed by the business.
    // The amount paid by the customer includes the selling price (Cost + Markup) + 1.9% variable fee.
    
    // 1. Estimate the full fee (for comparison with the cap)
    let fullFee = (chargedAmountInPesewas / 1.019) * 0.019 + TRANSACTION_FEE_FLAT;

    // 2. Apply Cap Check (simplification: maximum fee is 2000 pesewas)
    let totalFeeChargedByPaystack = Math.min(fullFee, TRANSACTION_FEE_CAP);
    
    // 3. The business absorbed the 80 pesewas flat fee.
    // We only need to know what the customer paid and subtract costs.
    
    // The amount *charged to the customer* (in pesewas)
    const customerPayment = chargedAmountInPesewas; 

    // The amount Paystack deducts
    let paystackDeduction = totalFeeChargedByPaystack; 

    return paystackDeduction;
}


// --- HELPER: FIND BASE COST PRICE ---
function findBaseCost(network, capacityId) {
    const networkPlans = allPlans[network];
    if (!networkPlans) return 0;
    const plan = networkPlans.find(p => p.id === capacityId);
    return plan ? plan.price : 0; // Returns cost in pesewas
}


// --- HELPER: SEND ADMIN ALERT EMAIL (omitted for brevity, unchanged) ---
async function sendAdminAlertEmail(order) { /* ... same as previous ... */ }


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


// --- 4. AUTHENTICATION & PAGE ROUTES (omitted for brevity, unchanged) ---
const isAuthenticated = (req, res, next) => req.session.user ? next() : res.redirect('/login.html');

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.post('/api/signup', async (req, res) => { /* ... same as previous ... */ });
app.post('/api/login', async (req, res) => { /* ... same as previous ... */ });
app.get('/api/logout', (req, res) => { /* ... same as previous ... */ });
app.get('/purchase', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'purchase.html')));
app.get('/dashboard', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));


// --- 5. DATA API ROUTES (omitted for brevity, unchanged) ---
app.get('/api/data-plans', (req, res) => {
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
app.get('/api/my-orders', isAuthenticated, async (req, res) => { /* ... same as previous ... */ });
app.get('/api/get-all-orders', async (req, res) => { /* ... same as previous ... */ });
app.post('/api/admin/update-order', async (req, res) => { /* ... same as previous ... */ });


// --- NEW ADMIN ENDPOINT: PROFIT METRICS ---
app.get('/api/admin/metrics', async (req, res) => {
    if (req.query.secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized" });

    try {
        const successfulOrders = await Order.find({ status: 'data_sent' });
        
        let totalRevenueGHS = 0;
        let totalCostGHS = 0;
        let totalPaystackFeeGHS = 0;

        successfulOrders.forEach(order => {
            const chargedAmountInPesewas = Math.round(order.amount * 100);
            
            // 1. Calculate Reseller Cost (in Pesewas)
            const resellerCostInPesewas = findBaseCost(order.network, order.dataPlan);
            
            // 2. Calculate Paystack Fee (in Pesewas)
            const paystackFeeInPesewas = calculatePaystackFee(chargedAmountInPesewas);
            
            // 3. Accumulate Totals
            totalRevenueGHS += order.amount; // Revenue is the amount paid by the customer
            totalPaystackFeeGHS += (paystackFeeInPesewas / 100);
            totalCostGHS += (resellerCostInPesewas / 100); // Reseller cost is cost to the business

        });
        
        // Final Calculations (in GHS)
        const totalNetCostGHS = totalCostGHS + totalPaystackFeeGHS;
        const totalNetProfitGHS = totalRevenueGHS - totalNetCostGHS;

        res.json({
            revenue: totalRevenueGHS.toFixed(2),
            cost: totalCostGHS.toFixed(2),
            paystackFee: totalPaystackFeeGHS.toFixed(2),
            netProfit: totalNetProfitGHS.toFixed(2),
            totalOrders: successfulOrders.length
        });

    } catch (error) {
        console.error('Metrics error:', error);
        res.status(500).json({ error: "Failed to calculate metrics" });
    }
});


// --- ADMIN ENDPOINTS (omitted for brevity, unchanged) ---
app.get('/api/admin/all-users-status', async (req, res) => { /* ... same as previous ... */ });
app.get('/api/admin/user-count', async (req, res) => { /* ... same as previous ... */ });


// --- 6. PAYMENT AND DATA TRANSFER ROUTE (omitted for brevity, unchanged) ---
app.post('/paystack/verify', isAuthenticated, async (req, res) => { /* ... same as previous ... */ });


// --- 7. SERVER START ---
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
