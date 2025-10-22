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

// --- 2. DATA (PLANS) - STATIC COST PRICE AND ID SETUP (FINALIZED) ---
const allPlans = {
    // PRICES ARE THE WHOLESALE COST (in PESEWAS)
    "MTN": [
        { id: '1', name: '1GB', price: 480 }, { id: '2', name: '2GB', price: 960 }, { id: '3', name: '3GB', price: 1420 }, 
        { id: '4', name: '4GB', price: 2000 }, { id: '5', name: '5GB', price: 2400 }, { id: '6', name: '6GB', price: 2800 }, 
        { id: '8', name: '8GB', price: 3600 }, { id: '10', name: '10GB', price: 4400 }, { id: '15', name: '15GB', price: 6400 },
        { id: '20', name: '20GB', price: 8200 }, { id: '25', name: '25GB', price: 10200 }, { id: '30', name: '30GB', price: 12200 },
        { id: '40', name: '40GB', price: 16200 }, { id: '50', name: '50GB', price: 19800 }
    ],
    "AirtelTigo": [
        { id: '1', name: '1GB', price: 400 }, { id: '2', name: '2GB', price: 800 }, { id: '3', name: '3GB', price: 1200 },  
        { id: '4', name: '4GB', price: 1600 }, { id: '5', name: '5GB', price: 2000 }, { id: '6', name: '6GB', price: 2420 },  
        { id: '7', name: '7GB', price: 2800 }, { id: '8', name: '8GB', price: 3200 }, { id: '9', name: '9GB', price: 3600 },  
        { id: '10', name: '10GB', price: 4200 }, { id: '12', name: '12GB', price: 5000 }, { id: '15', name: '15GB', price: 6200 },
        { id: '20', name: '20GB', price: 8200 } // NOTE: Used 8200 instead of 7400 to match new data's price progression
    ],
    "Telecel": [
        { id: '5', name: '5GB', price: 2300 }, { id: '10', name: '10GB', price: 4300 }, { id: '15', name: '15GB', price: 6300 }, 
        { id: '20', name: '20GB', price: 8300 }, { id: '25', name: '25GB', price: 10300 }, { id: '30', name: '30GB', price: 12300 },
        { id: '40', name: '40GB', price: 15500 }, { id: '50', name: '50GB', price: 19500 }, { id: '100', name: '100GB', price: 39000}
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
    const TRANSACTION_FEE_RATE = 0.00205; const TRANSACTION_FEE_CAP = 2000;
    let fullFee = (chargedAmountInPesewas * TRANSACTION_FEE_RATE) + 80;
    let totalFeeChargedByPaystack = Math.min(fullFee, TRANSACTION_FEE_CAP);
    return totalFeeChargedByPaystack;
}
async function sendAdminAlertEmail(order) {
    if (!process.env.SENDGRID_API_KEY) {
        console.error("SENDGRID_API_KEY not set. Cannot send alert email.");
        return;
    }
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    const msg = {
        to: 'ajcustomercare2@gmail.com', 
        from: 'jnkpappoe@gmail.com, 
        subject: `🚨 MANUAL REVIEW REQUIRED: ${order.network} Data Transfer Failed`,
        html: `
            <h1>Urgent Action Required!</h1>
            <p>A customer payment was successful, but the data bundle transfer failed automatically. Please fulfill this order manually through the Datahub Ghana dashboard.</p>
            <hr>
            <p><strong>Status:</strong> PENDING REVIEW</p>
            <p><strong>Network:</strong> ${order.network}</p>
            <p><strong>Plan:</strong> ${order.dataPlan}</p>
            <p><strong>Phone:</strong> ${order.phoneNumber}</p>
            <p><strong>Amount Paid:</strong> GHS ${order.amount.toFixed(2)}</p>
            <p><strong>Reference:</strong> ${order.reference}</p>
            <p><strong>Action:</strong> Go to the Admin Dashboard and click 'Mark Sent' after fulfilling manually.</p>
        `,
    };
    try {
        await sgMail.send(msg);
        console.log(`Manual alert email sent for reference: ${order.reference}`);
    } catch (error) {
        console.error('Failed to send admin alert email:', error.response?.body || error);
    }
}
async function executeDataPurchase(userId, orderDetails, paymentMethod) {
    const { network, dataPlan, amount } = orderDetails;
    
    let finalStatus = 'payment_success'; 
    const reference = `${paymentMethod.toUpperCase()}-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`; 

    // --- STEP 1: TRANSFER DATA VIA RESELLER API ---
    const resellerApiUrl = 'https://console.ckgodsway.com/api/data-purchase';
    const networkKey = NETWORK_KEY_MAP[network];
    
    const resellerPayload = {
        networkKey: networkKey,       
        recipient: orderDetails.phoneNumber,      
        capacity: dataPlan,          
        reference: reference          
    };
    
    try {
        const transferResponse = await axios.post(resellerApiUrl, resellerPayload, {
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': process.env.DATA_API_SECRET
            }
        });

        if (transferResponse.data.success === true) {
            finalStatus = 'data_sent';
        } else {
            console.error('Data API failed response:', transferResponse.data);
            finalStatus = 'pending_review';
        }

    } catch (transferError) {
        console.error('Data API Network Error:', transferError.message);
        finalStatus = 'pending_review';
    }

    // --- STEP 2: SAVE FINAL ORDER STATUS TO MONGODB & SEND ALERT ---
    await Order.create({
        userId: userId,
        reference: reference,
        phoneNumber: orderDetails.phoneNumber,
        network: network,
        dataPlan: dataPlan,
        amount: amount,
        status: finalStatus,
        paymentMethod: paymentMethod
    });

    if (finalStatus === 'pending_review') {
        await sendAdminAlertEmail(orderDetails); 
    }

    return { status: finalStatus, reference: reference };
}

async function runPendingOrderCheck() {
    console.log('--- CRON: Checking for pending orders needing status update... ---');
    const CHECK_API_ENDPOINT = 'https://console.ckgodsway.com/api/order-status'; 

    try {
        if (mongoose.connection.readyState !== 1) {
            console.log('CRON: Skipping check, database not ready (State: ' + mongoose.connection.readyState + ')');
            return;
        }

        const pendingOrders = await Order.find({ status: 'pending_review' }).limit(20); 

        if (pendingOrders.length === 0) {
            console.log('CRON: No orders currently pending review.');
            return;
        }

        for (const order of pendingOrders) {
            try {
                const statusResponse = await axios.get(`${CHECK_API_ENDPOINT}?reference=${order.reference}`, {
                    headers: { 'X-API-Key': process.env.DATA_API_SECRET }
                });

                const apiData = statusResponse.data;

                if (apiData.success && apiData.data.status === 'SUCCESSFUL') {
                    await Order.findByIdAndUpdate(order._id, { status: 'data_sent' });
                    console.log(`CRON SUCCESS: Order ${order.reference} automatically marked 'data_sent'.`);

                } else if (apiData.success && apiData.data.status === 'FAILED') {
                    await Order.findByIdAndUpdate(order._id, { status: 'data_failed' });
                    console.log(`CRON FAILURE: Order ${order.reference} marked 'data_failed'.`);
                }
            } catch (apiError) {
                console.error(`CRON ERROR: Failed to check status for ${order.reference}.`, apiError.message);
            }
        }

    } catch (dbError) {
        console.error('CRON FATAL ERROR: Database read failed.', dbError.message);
    }
}


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
    // Check if Mongoose is in the 'connected' state (state 1)
    if (mongoose.connection.readyState !== 1) {
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
app.post('/api/topup', isDbReady, isAuthenticated, async (req, res) => { /* ... implementation ... */ });
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

// Start the cron job after the server is listening
cron.schedule('*/5 * * * *', runPendingOrderCheck);
