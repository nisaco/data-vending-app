// --- 1. IMPORTS AND SETUP ---
require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sgMail = require('@sendgrid/mail'); // ⬅️ USED FOR EMAIL
const axios = require('axios');
const { User, Order } = require('./database.js'); 
const mongoose = require('mongoose'); 

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

// --- HELPER: SEND ADMIN ALERT EMAIL (NEW FUNCTIONALITY) ---
async function sendAdminAlertEmail(order) {
    if (!process.env.SENDGRID_API_KEY) {
        console.error("SENDGRID_API_KEY not set. Cannot send alert email.");
        return;
    }
    
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    
    const msg = {
        to: 'YOUR_ADMIN_RECEIVING_EMAIL@example.com', // ⬅️ CRITICAL: Your email to receive alerts
        from: 'YOUR_VERIFIED_SENDER_EMAIL@example.com', // ⬅️ CRITICAL: Your verified SendGrid sender email
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

app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ username, email, password: hashedPassword });
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
        req.session.user = { id: user._id, username: user.username };
        res.json({ message: 'Logged in successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.get('/api/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login.html'));
});

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

app.get('/api/my-orders', isAuthenticated, async (req, res) => {
    try {
        const orders = await Order.find({ userId: req.session.user.id })
                                    .sort({ createdAt: -1 }); 
        res.json({ orders });
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch orders" });
    }
});

app.get('/api/get-all-orders', async (req, res) => {
    if (req.query.secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized" });
    try {
        const orders = await Order.find({})
                                  .sort({ createdAt: -1 })
                                  .populate('userId', 'username'); 
        
        const formattedOrders = orders.map(order => ({
            id: order._id,
            username: order.userId ? order.userId.username : 'Deleted User',
            phone_number: order.phoneNumber,
            network: order.network,
            data_plan: order.dataPlan,
            amount: order.amount,
            status: order.status,
            created_at: order.createdAt,
        }));

        res.json({ orders: formattedOrders });
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch orders" });
    }
});

// --- ADMIN ENDPOINT: FETCH ALL USERS + ONLINE STATUS (omitted for brevity, unchanged) ---
app.get('/api/admin/all-users-status', async (req, res) => {
    if (req.query.secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized" });
    
    try {
        const registeredUsers = await User.find({}).select('username email createdAt').lean();

        const sessionsCollection = mongoose.connection.db.collection('sessions');
        const rawSessions = await sessionsCollection.find({}).toArray();

        const activeUserIds = new Set();
        rawSessions.forEach(sessionDoc => {
            try {
                const sessionData = JSON.parse(sessionDoc.session);
                if (sessionData.user && sessionData.user.id) {
                    let sessionId = sessionData.user.id.toString().replace(/['"]+/g, '');
                    activeUserIds.add(sessionId);
                }
            } catch (e) { }
        });

        const userListWithStatus = registeredUsers.map(user => {
            const userIdString = user._id.toString();
            
            return {
                username: user.username,
                email: user.email,
                signedUp: user.createdAt,
                isOnline: activeUserIds.has(userIdString)
            };
        });

        res.json({ users: userListWithStatus });
        
    } catch (error) {
        console.error('All users status error:', error);
        res.status(500).json({ error: "Failed to fetch user list and status" });
    }
});


// --- ADMIN ENDPOINT: FETCH USER COUNT (omitted for brevity, unchanged) ---
app.get('/api/admin/user-count', async (req, res) => {
    if (req.query.secret !== process.env.ADMIN_SECRET) {
        return res.status(403).json({ error: "Unauthorized" });
    }
    try {
        const count = await User.countDocuments({});
        res.json({ count: count });
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch user count" });
    }
});

// --- ADMIN ENDPOINT: MANUAL STATUS UPDATE (omitted for brevity, unchanged) ---
app.post('/api/admin/update-order', async (req, res) => {
    const { orderId, newStatus, adminSecret } = req.body;
    
    if (adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized access." });
    if (!orderId || !newStatus) return res.status(400).json({ error: "Order ID and new status are required." });

    try {
        const result = await Order.findByIdAndUpdate(orderId, { status: newStatus }, { new: true });
        if (!result) return res.status(404).json({ message: "Order not found." });
        
        res.json({ status: 'success', message: `Order ${orderId} status updated to ${newStatus}.` });

    } catch (error) {
        res.status(500).json({ error: "Failed to update order status." });
    }
});


// --- 6. PAYMENT AND DATA TRANSFER ROUTE (WITH EMAIL ALERT) ---
app.post('/paystack/verify', isAuthenticated, async (req, res) => {
    const { reference } = req.body;
    if (!reference) return res.status(400).json({ status: 'error', message: 'Reference is required.' });

    let finalStatus = 'payment_success'; 
    let orderDetails = null; // Will hold data to be saved/emailed

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
        
        // Prepare details for saving and emailing
        orderDetails = {
            userId: userId,
            reference: reference,
            phoneNumber: phone_number,
            network: network,
            dataPlan: data_plan,
            amount: amountInGHS,
            status: finalStatus
        };
        
        // --- STEP 2: TRANSFER DATA VIA RESELLER API (Datahub Ghana) ---
        const resellerApiUrl = 'https://console.ckgodsway.com/api/data-purchase';
        const networkKey = NETWORK_KEY_MAP[network];
        
        const resellerPayload = {
            networkKey: networkKey,       
            recipient: phone_number,      
            capacity: data_plan,          
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

        // --- STEP 3: SAVE FINAL ORDER STATUS TO MONGODB ---
        orderDetails.status = finalStatus;
        await Order.create(orderDetails);
        
        // --- STEP 4: SEND ALERT IF FAILED ---
        if (finalStatus === 'pending_review') {
            await sendAdminAlertEmail(orderDetails); // Send email notification immediately
        }

        if (finalStatus === 'data_sent') {
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

// --- 7. SERVER START ---
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});

