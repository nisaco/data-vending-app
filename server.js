// --- 1. IMPORTS AND SETUP ---
require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sgMail = require('@sendgrid/mail');
const axios = require('axios');
const cron = require('node-cron');
const crypto = require('crypto');
const { User, Order, mongoose } = require('./database.js'); 

const app = express();
const PORT = process.env.PORT || 10000;

// --- 2. DATA (PLANS) AND MAPS ---
const allPlans = {
    "MTN": [
        { id: '1', name: '1GB', price: 480 }, { id: '2', name: '2GB', price: 960 }, { id: '3', name: '3GB', price: 1420 }, 
        { id: '4', name: '4GB', price: 2000 }, { id: '5', name: '5GB', price: 2400 }, { id: '6', name: '6GB', price: 2800 }, 
        { id: '8', name: '8GB', price: 3600 }, { id: '10', name: '10GB', price: 4400 }, { id: '15', name: '15GB', price: 6400 },
        { id: '20', name: '20GB', price: 8200 }, { id: '25', name: '25GB', price: 10200 }, { id: '30', name: '30GB', price: 12200 },
        { id: '40', name: '40GB', price: 16200 }, { id: '50', name: '50GB', price: 19800 }
    ],
    "AirtelTigo": [
        { id: '1', name: '1GB', price: 370 }, { id: '2', name: '2GB', price: 740 }, { id: '3', name: '3GB', price: 1110 },  
        { id: '4', name: '4GB', price: 1480 }, { id: '5', name: '5GB', price: 1850 }, { id: '6', name: '6GB', price: 2220 },  
        { id: '7', name: '7GB', price: 2590 }, { id: '8', name: '8GB', price: 2960 }, { id: '9', name: '9GB', price: 3330 },  
        { id: '10', name: '10GB', price: 3700 }, { id: '12', name: '12GB', price: 4440 }, { id: '15', name: '15GB', price: 5550 },
        { id: '20', name: '20GB', price: 7400 }
    ],
    "Telecel": [
        { id: '5', name: '5GB', price: 2000 }, { id: '10', name: '10GB', price: 3800 }, { id: '15', name: '15GB', price: 5500 }, 
        { id: '20', name: '20GB', price: 7300 }, { id: '25', name: '25GB', price: 9000 }, { id: '30', name: '30GB', price: 11000 },
        { id: '40', name: '40GB', price: 14300 }, { id: '50', name: '50GB', price: 18000 }, { id: '100', name: '100GB', price: 35000}
    ]
};

const NETWORK_KEY_MAP = {
    "MTN": 'YELLO', "AirtelTigo": 'AT_PREMIUM', "Telecel": 'TELECEL',
};


// --- HELPER FUNCTIONS ---
function findBaseCost(network, capacityId) { /* ... implementation ... */ return 0; }
function calculatePaystackFee(chargedAmountInPesewas) { /* ... implementation ... */ return 0; }
function calculateClientTopupFee(netDepositPesewas) { /* ... implementation ... */ return 0; }
async function sendAdminAlertEmail(order) { /* ... implementation ... */ }
async function executeDataPurchase(userId, orderDetails, paymentMethod) { /* ... implementation ... */ return { status: 'error' }; }
async function runPendingOrderCheck() { /* ... implementation ... */ }
async function sendResetEmail(user, token) { /* ... implementation ... */ }


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


// --- 4. DATABASE CHECK MIDDLEWARE ---
const isDbReady = (req, res, next) => {
    if (mongoose.connection.readyState !== 1) {
        console.error("DB NOT READY. State:", mongoose.connection.readyState);
        return res.status(503).json({ message: 'Database connection is temporarily unavailable. Please try again in 10 seconds.' });
    }
    next();
};

const isAuthenticated = (req, res, next) => req.session.user ? next() : res.redirect('/login.html');

// --- USER AUTHENTICATION & INFO ROUTES ---
app.post('/api/signup', isDbReady, async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ username, email, password: hashedPassword, walletBalance: 0 }); 
        res.status(201).json({ message: 'User created successfully! Please log in.' });
    } catch (error) { 
        if (error.code === 11000) return res.status(400).json({ message: 'Username or email already exists.' });
        res.status(500).json({ message: 'Server error during signup.' }); 
    }
});

app.post('/api/login', isDbReady, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password are required.' });
    try {
        const user = await User.findOne({ username });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        // 🛑 CRITICAL FIX: Ensure session is updated with the current balance on login
        req.session.user = { id: user._id, username: user.username, walletBalance: user.walletBalance }; 
        res.json({ message: 'Logged in successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.get('/api/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login.html'));
});

app.get('/api/user-info', isDbReady, isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id).select('username walletBalance email');
        if (!user) {
            req.session.destroy(() => res.status(404).json({ error: 'User not found' }));
            return;
        }
        // 🛑 FIX: Update session balance here too, before sending
        req.session.user.walletBalance = user.walletBalance; 
        res.json({ username: user.username, walletBalance: user.walletBalance, email: user.email });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user data' });
    }
});

app.post('/api/forgot-password', isDbReady, async (req, res) => { /* ... implementation ... */ });
app.post('/api/reset-password', isDbReady, async (req, res) => { /* ... implementation ... */ });


// --- DATA & PROTECTED PAGES ---
app.get('/api/data-plans', isDbReady, (req, res) => {
    const costPlans = allPlans[req.query.network] || [];
    
    const sellingPlans = costPlans.map(p => {
        const FIXED_MARKUP = 0; 
        const rawSellingPrice = p.price + FIXED_MARKUP;
        const sellingPrice = Math.ceil(rawSellingPrice / 5) * 5; 
        
        return { id: p.id, name: p.name, price: sellingPrice };
    });

    res.json(sellingPlans);
});

app.get('/api/my-orders', isDbReady, isAuthenticated, async (req, res) => {
    try {
        const orders = await Order.find({ userId: req.session.user.id })
                                    .sort({ createdAt: -1 }); 
        res.json({ orders });
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch orders" });
    }
});


// --- WALLET & PAYMENT ROUTES ---
app.post('/api/topup', isDbReady, isAuthenticated, async (req, res) => {
    const { reference, amount } = req.body; 
    if (!reference || !amount) {
        return res.status(400).json({ status: 'error', message: 'Reference and amount are required.' });
    }
    
    let topupAmountPesewas = Math.round(amount * 100);
    const userId = req.session.user.id;

    const finalChargedAmountPesewas = calculateClientTopupFee(topupAmountPesewas);

    try {
        // --- STEP 1: VERIFY PAYMENT WITH PAYSTACK ---
        const paystackUrl = `https://api.paystack.co/transaction/verify/${reference}`;
        const paystackResponse = await axios.get(paystackUrl, { 
            headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } 
        });
        const { status, data } = paystackResponse.data;

        if (!status || data.status !== 'success') {
            return res.status(400).json({ status: 'error', message: 'Payment verification failed.' });
        }
        
        if (Math.abs(data.amount - finalChargedAmountPesewas) > 5) {
            console.error(`Fraud Alert: Charged ${data.amount} but expected ${finalChargedAmountPesewas}`);
            return res.status(400).json({ status: 'error', message: 'Amount charged mismatch detected.' });
        }
        
        // --- STEP 2: UPDATE USER WALLET BALANCE (NET DEPOSIT) ---
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { $inc: { walletBalance: netDepositPesewas } }, // Deposit the net amount (e.g., 5000)
            { new: true, runValidators: true }
        );
        
        // 🛑 CRITICAL FIX: Update the session balance HERE immediately after the DB update
        req.session.user.walletBalance = updatedUser.walletBalance; 

        // Log the top-up as a successful order for tracking
        await Order.create({
            userId: userId,
            reference: reference,
            amount: finalChargedAmountPesewas / 100, // Log the total charged amount
            status: 'topup_successful',
            paymentMethod: 'paystack',
            dataPlan: 'WALLET TOP-UP',
            network: 'WALLET' 
        });
        
        // Send the updated balance back to the client
        res.json({ status: 'success', message: `Wallet topped up successfully! GHS ${netDepositAmountGHS.toFixed(2)} deposited.`, newBalance: updatedUser.walletBalance });

    } catch (error) {
        console.error('Topup Verification Error:', error);
        res.status(500).json({ status: 'error', message: 'An internal server error occurred during top-up.' });
    }
});

app.post('/api/wallet-purchase', isDbReady, isAuthenticated, async (req, res) => { /* ... implementation ... */ });

app.post('/paystack/verify', isDbReady, isAuthenticated, async (req, res) => { /* ... implementation ... */ });


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
app.get('/forgot.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'forgot.html')));
app.get('/reset.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset.html')));


// --- SERVER START ---
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is LIVE on port ${PORT}`);
    console.log('Database connection is initializing...');
});

cron.schedule('*/5 * * * *', runPendingOrderCheck);
