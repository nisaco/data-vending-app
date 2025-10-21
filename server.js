// --- 1. IMPORTS AND SETUP ---
require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const axios = require('axios');
const cron = require('node-cron');
const { User, Order, mongoose } = require('./database.js'); 
const { allPlans, NETWORK_KEY_MAP, executeDataPurchase, findBaseCost, calculatePaystackFee } = require('./utils.js'); 
const app = express();
const PORT = process.env.PORT || 10000;

// --- CRON JOB (omitted for brevity, implemented below) ---
async function runPendingOrderCheck() { /* ... implementation ... */ }
const CHECK_API_ENDPOINT = 'https://console.ckgodsway.com/api/order-status'; 


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


// --- 5. CORE ROUTE DEFINITION (The Fix: Executed after DB is stable) ---
mongoose.connection.once('open', () => {

    console.log('Database connection stable. Registering routes...');

    const isAuthenticated = (req, res, next) => req.session.user ? next() : res.redirect('/login.html');

    // --- USER AUTHENTICATION & INFO ROUTES ---
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


    // --- WALLET & PAYMENT ROUTES (omitted for brevity, unchanged) ---
    app.post('/api/topup', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
    app.post('/api/wallet-purchase', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
    app.post('/paystack/verify', isAuthenticated, async (req, res) => { /* ... implementation ... */ });


    // --- ADMIN & MANAGEMENT ROUTES ---
    app.get('/api/get-all-orders', async (req, res) => {
        if (req.query.secret !== process.env.ADMIN_SECRET) {
            console.error(`ADMIN ERROR: Failed attempt to fetch orders. Client secret (last 4 chars): [${req.query.secret.slice(-4)}]`);
            return res.status(403).json({ error: "Unauthorized: Invalid Admin Secret" });
        }
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

    app.post('/api/admin/update-order', async (req, res) => {
        if (req.body.adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized access." });
        const { orderId, newStatus } = req.body;
        
        if (!orderId || !newStatus) return res.status(400).json({ error: "Order ID and new status are required." });

        try {
            const result = await Order.findByIdAndUpdate(orderId, { status: newStatus }, { new: true });
            if (!result) return res.status(404).json({ message: "Order not found." });
            
            res.json({ status: 'success', message: `Order ${orderId} status updated to ${newStatus}.` });

        } catch (error) {
            res.status(500).json({ error: "Failed to update order status." });
        }
    });


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
