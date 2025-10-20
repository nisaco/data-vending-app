// --- 1. IMPORTS AND SETUP (omitted for brevity) ---
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

// --- 2. DATA (PLANS) & HELPERS (omitted for brevity) ---
const allPlans = { /* ... implementation ... */ };
const NETWORK_KEY_MAP = { /* ... implementation ... */ };
async function sendAdminAlertEmail(order) { /* ... implementation ... */ }
async function runPendingOrderCheck() { /* ... implementation ... */ }
async function executeDataPurchase(userId, orderDetails, paymentMethod) { /* ... implementation ... */ }

// --- 3. MIDDLEWARE (omitted for brevity, unchanged) ---
app.set('trust proxy', 1); 

const sessionSecret = process.env.env || 'fallback-secret-for-local-dev-only-12345';
app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true, maxAge: 1000 * 60 * 60 } 
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


// --- 4. AUTHENTICATION & CORE ROUTES (omitted for brevity, unchanged) ---
const isAuthenticated = (req, res, next) => req.session.user ? next() : res.redirect('/login.html');
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.post('/api/signup', async (req, res) => { /* ... implementation ... */ });
app.post('/api/login', async (req, res) => { /* ... implementation ... */ });
app.get('/api/logout', (req, res) => { /* ... implementation ... */ });
app.get('/purchase', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'purchase.html')));
app.get('/dashboard', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/api/data-plans', (req, res) => { /* ... implementation ... */ });
app.get('/api/my-orders', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
app.get('/api/user-info', isAuthenticated, async (req, res) => { /* ... implementation ... */ });


// --- 5. ADMIN API ROUTES ---

// FETCH ALL ORDERS (Protected - now logs key failure)
app.get('/api/get-all-orders', async (req, res) => {
    if (req.query.secret !== process.env.ADMIN_SECRET) {
        // 🛑 SECURITY DEBUG: Logs the client secret that failed the check
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

// FETCH ALL USERS + ONLINE STATUS
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

// FETCH USER COUNT
app.get('/api/admin/user-count', async (req, res) => {
    if (req.query.secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized" });
    try {
        const count = await User.countDocuments({});
        res.json({ count: count });
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch user count" });
    }
});

// FETCH PROFIT METRICS
app.get('/api/admin/metrics', async (req, res) => { /* ... implementation ... */ });
app.post('/api/admin/update-order', async (req, res) => { /* ... implementation ... */ });


// --- 6. PAYMENT AND DATA TRANSFER ROUTES (omitted for brevity, unchanged) ---
app.post('/paystack/verify', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
app.post('/api/topup', isAuthenticated, async (req, res) => { /* ... implementation ... */ });
app.post('/api/wallet-purchase', isAuthenticated, async (req, res) => { /* ... implementation ... */ });


// --- 7. SERVER START (omitted for brevity, unchanged) ---
mongoose.connection.once('open', () => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server is LIVE on port ${PORT}`);
        console.log('Database connection is stable. Starting cron job...');
    });
    cron.schedule('*/5 * * * *', runPendingOrderCheck);
});
