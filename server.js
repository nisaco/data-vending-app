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

// --- HELPER: SEND ADMIN ALERT EMAIL (omitted for brevity, unchanged) ---
async function sendAdminAlertEmail(order) { /* ... implementation ... */ }

// --- 3. CORE AUTOMATION: STATUS CHECK SCHEDULER (omitted for brevity, unchanged) ---
const CHECK_API_ENDPOINT = 'https://console.ckgodsway.com/api/order-status'; 

async function runPendingOrderCheck() {
    console.log('--- CRON: Checking for pending orders needing status update... ---');

    try {
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
        console.error('CRON FATAL ERROR: Database read failed. Server is likely unstable.', dbError.message);
    }
}


// --- 4. MIDDLEWARE ---
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


// --- 5. AUTHENTICATION & PAGE ROUTES (omitted for brevity, largely unchanged) ---
const isAuthenticated = (req, res, next) => req.session.user ? next() : res.redirect('/login.html');

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.post('/api/signup', async (req, res) => {
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

app.post('/api/login', async (req, res) => {
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

// GET user info (including balance)
app.get('/api/user-info', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id).select('username walletBalance');
        if (!user) {
            req.session.destroy(() => res.status(404).json({ error: 'User not found' }));
            return;
        }
        req.session.user.walletBalance = user.walletBalance; 
        res.json({ username: user.username, walletBalance: user.walletBalance });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user data' });
    }
});

app.get('/purchase', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'purchase.html')));
app.get('/dashboard', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));


// --- 6. WALLET TOP-UP ROUTE ---
app.post('/api/topup', isAuthenticated, async (req, res) => {
    const { reference, amount } = req.body; 
    if (!reference || !amount) {
        return res.status(400).json({ status: 'error', message: 'Reference and amount are required.' });
    }
    
    let topupAmountPesewas = Math.round(amount * 100);
    const userId = req.session.user.id;

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
        
        // Security check
        if (data.amount !== topupAmountPesewas) {
            console.error(`Fraud Alert: Charged ${data.amount} but expected ${topupAmountPesewas}`);
            return res.status(400).json({ status: 'error', message: 'Amount mismatch detected.' });
        }
        
        // --- STEP 2: UPDATE USER WALLET BALANCE ---
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { $inc: { walletBalance: topupAmountPesewas } },
            { new: true, runValidators: true }
        );
        
        req.session.user.walletBalance = updatedUser.walletBalance; 

        // Log the top-up as a successful order for tracking
        await Order.create({
            userId: userId,
            reference: reference,
            amount: amount,
            status: 'topup_successful',
            paymentMethod: 'paystack',
            dataPlan: 'WALLET TOP-UP'
        });

        res.json({ 
            status: 'success', 
            message: `Wallet topped up successfully!`, 
            newBalance: updatedUser.walletBalance 
        });

    } catch (error) {
        console.error('Topup Verification Error:', error);
        res.status(500).json({ status: 'error', message: 'An internal server error occurred during top-up.' });
    }
});


// --- 7. WALLET PURCHASE ROUTE ---
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
        await sendAdminAlertEmail(orderDetails); // Send email notification
    }

    return { status: finalStatus, reference: reference };
}

app.post('/api/wallet-purchase', isAuthenticated, async (req, res) => {
    const { network, dataPlan, phone_number, amountInPesewas } = req.body;
    const userId = req.session.user.id;
    
    if (!network || !dataPlan || !phone_number || !amountInPesewas) {
        return res.status(400).json({ message: 'Missing required order details.' });
    }

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: 'User not found.' });

        // 1. Check Balance
        if (user.walletBalance < amountInPesewas) {
            return res.status(400).json({ message: 'Insufficient wallet balance.' });
        }

        // 2. Debit Wallet (Atomically)
        const debitResult = await User.findByIdAndUpdate(
            userId,
            { $inc: { walletBalance: -amountInPesewas } },
            { new: true, runValidators: true }
        );
        
        req.session.user.walletBalance = debitResult.walletBalance;

        // 3. Execute Data Purchase
        const result = await executeDataPurchase(userId, {
            network,
            dataPlan,
            phoneNumber: phone_number,
            amount: amountInPesewas / 100 // Store in GHS
        }, 'wallet');
        
        if (result.status === 'data_sent') {
            return res.json({ status: 'success', message: 'Data successfully sent from wallet!' });
        } else {
            return res.status(202).json({ 
                status: 'pending', 
                message: `Data purchase initiated. Status: ${result.status}. Check dashboard.` 
            });
        }

    } catch (error) {
        console.error('Wallet Purchase Error:', error);
        res.status(500).json({ message: 'Server error during wallet purchase.' });
    }
});


// --- 8. PAYSTACK PAYMENT ROUTE (MODIFIED) ---
app.post('/paystack/verify', isAuthenticated, async (req, res) => {
    const { reference } = req.body;
    if (!reference) return res.status(400).json({ status: 'error', message: 'Reference is required.' });

    let finalStatus = 'payment_success'; 
    let orderDetails = null; 
    
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

        const { phone_number, network, data_plan } = data.metadata; 
        const amountInGHS = data.amount / 100;
        const userId = req.session.user.id;
        
        // Prepare details for data purchase function
        orderDetails = {
            userId: userId,
            reference: reference,
            phoneNumber: phone_number,
            network: network,
            dataPlan: data_plan,
            amount: amountInGHS,
            status: finalStatus
        };
        
        // Execute the data transfer and save order (same logic as wallet purchase)
        const result = await executeDataPurchase(userId, orderDetails, 'paystack');

        if (result.status === 'data_sent') {
            return res.json({ status: 'success', message: `Payment verified. Data transfer successful!` });
        } else {
            return res.status(202).json({ 
                status: 'pending', 
                message: `Payment successful! Data transfer is pending manual review. Contact support with reference: ${reference}.` 
            });
        }

    } catch (error) {
        let errorMessage = 'An internal server error occurred during verification.';
        
        if (error.response && error.response.data && error.response.data.error) {
            errorMessage = `External API Error: ${error.response.data.error}`;
        } else if (error.message) {
            errorMessage = `Network Error: ${error.message}`;
        }
        
        console.error('Fatal Verification Failure:', error); 
        
        return res.status(500).json({ status: 'error', message: errorMessage });
    }
});


// --- 9. ADMIN/STATISTICS ROUTES (omitted for brevity, unchanged) ---
app.get('/api/data-plans', (req, res) => { /* ... implementation ... */ });
app.get('/api/my-orders', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
app.get('/api/get-all-orders', async (req, res) => { /* ... implementation ... */ });
app.get('/api/admin/metrics', async (req, res) => { /* ... implementation ... */ });
app.get('/api/admin/all-users-status', async (req, res) => { /* ... implementation ... */ });
app.get('/api/admin/user-count', async (req, res) => { /* ... implementation ... */ });
app.post('/api/admin/update-order', async (req, res) => { /* ... implementation ... */ });


// --- 10. SERVER START ---
// Wait for Mongoose to connect before starting the server and the cron job
mongoose.connection.once('open', () => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server running on port ${PORT}`);
    });
    // Start the cron job after the server is listening
    cron.schedule('*/5 * * * *', runPendingOrderCheck);
});
