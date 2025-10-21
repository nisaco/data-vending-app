// --- 1. IMPORTS AND SETUP ---
require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sgMail = require('@sendgrid/mail');
const axios = require('axios');
const cron = require('node-cron');
// 🛑 FIX: Import mongoose alongside the models
const { User, Order, mongoose } = require('./database.js'); 

const app = express();
const PORT = process.env.PORT || 10000;

// --- 2. DATA (PLANS) & HELPERS (omitted for brevity, unchanged) ---
const allPlans = { /* ... implementation ... */ };
const NETWORK_KEY_MAP = { /* ... implementation ... */ };
async function sendAdminAlertEmail(order) { /* ... implementation ... */ }
async function runPendingOrderCheck() { /* ... implementation ... */ }
async function executeDataPurchase(userId, orderDetails, paymentMethod) { /* ... implementation ... */ }
function findBaseCost(network, capacityId) { /* ... implementation ... */ }
function calculatePaystackFee(chargedAmountInPesewas) { /* ... implementation ... */ }


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


// --- 4. CORE ROUTE DEFINITION (The Fix: Executed after DB is stable) ---
mongoose.connection.once('open', () => {

    console.log('Database connection stable. Registering routes...');

    const isAuthenticated = (req, res, next) => req.session.user ? next() : res.redirect('/login.html');

    // --- USER AUTHENTICATION & INFO ROUTES ---
    app.post('/api/signup', async (req, res) => { /* ... implementation ... */ });
    app.post('/api/login', async (req, res) => { /* ... implementation ... */ });
    app.get('/api/logout', (req, res) => { /* ... implementation ... */ });
    
    app.get('/api/user-info', isAuthenticated, async (req, res) => {
        try {
            const user = await User.findById(req.session.user.id).select('username walletBalance email');
            if (!user) {
                req.session.destroy(() => res.status(404).json({ error: 'User not found' }));
                return;
            }
            req.session.user.walletBalance = user.walletBalance; 
            res.json({ username: user.username, walletBalance: user.walletBalance, email: user.email });
        } catch (error) {
            res.status(500).json({ error: 'Failed to fetch user data' });
        }
    });


    // --- DATA & PROTECTED PAGES ---
    app.get('/api/data-plans', (req, res) => {
        const costPlans = allPlans[req.query.network] || [];
        
        const sellingPlans = costPlans.map(p => {
            const FIXED_MARKUP = 20; 
            const rawSellingPrice = p.price + FIXED_MARKUP;
            const sellingPrice = Math.ceil(rawSellingPrice / 5) * 5; 
            
            return { id: p.id, name: p.name, price: sellingPrice };
        });

        res.json(sellingPlans);
    });

    app.get('/api/my-orders', isAuthenticated, async (req, res) => {
        try {
            const orders = await Order.find({ userId: req.session.user.id })
                                        .sort({ createdAt: -1 }); 
            res.json({ orders });
        } catch (error) {
            res.status(500).json({ error: "Failed to fetch orders" });
        }
    });

    // --- WALLET & PAYSTACK ROUTES (omitted for brevity, unchanged) ---
    app.post('/api/topup', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
    app.post('/api/wallet-purchase', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
    app.post('/paystack/verify', isAuthenticated, async (req, res) => { /* ... implementation ... */ });


    // --- ADMIN & MANAGEMENT ROUTES (omitted for brevity, unchanged) ---
    app.get('/api/get-all-orders', async (req, res) => { /* ... implementation ... */ });
    app.get('/api/admin/metrics', async (req, res) => { /* ... implementation ... */ });
    app.get('/api/admin/all-users-status', async (req, res) => { /* ... implementation ... */ });
    app.get('/api/admin/user-count', async (req, res) => { /* ... implementation ... */ });
    app.post('/api/admin/update-order', async (req, res) => { /* ... implementation ... */ });


    // --- SERVE HTML FILES ---
    app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
    app.get('/purchase', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'purchase.html')));
    app.get('/dashboard', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

    
    // --- SERVER START ---
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server is LIVE on port ${PORT}`);
        console.log('Database connection is stable. Starting cron job...');
    });
    cron.schedule('*/5 * * * *', runPendingOrderCheck);
});
