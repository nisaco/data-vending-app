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

// --- 2. DATA (PLANS) AND MAPS ---
const allPlans = {
    "MTN": [
        { id: '1', name: '1GB', price: 490 },  
        { id: '2', name: '2GB', price: 980 },  
        { id: '3', name: '3GB', price: 1400 }, 
        { id: '4', name: '4GB', price: 1820 }, 
        { id: '5', name: '5GB', price: 2300 }, 
        { id: '6', name: '6GB', price: 2700 }, 
        { id: '8', name: '8GB', price: 3600 }, 
        { id: '10', name: '10GB', price: 4200 },
        { id: '15', name: '15GB', price: 6300 },
        { id: '20', name: '20GB', price: 8200 },
        { id: '25', name: '25GB', price: 10200 },
        { id: '30', name: '30GB', price: 12200 },
        { id: '40', name: '40GB', price: 16300 },
        { id: '50', name: '50GB', price: 19700 }
    ],
    "AirtelTigo": [
        { id: '1', name: '1GB', price: 370 },   
        { id: '2', name: '2GB', price: 740 },   
        { id: '3', name: '3GB', price: 1110 },  
        { id: '4', name: '4GB', price: 1480 },  
        { id: '5', name: '5GB', price: 1850 },  
        { id: '6', name: '6GB', price: 2220 },  
        { id: '7', name: '7GB', price: 2590 },  
        { id: '8', name: '8GB', price: 2960 },  
        { id: '9', name: '9GB', price: 3330 },  
        { id: '10', name: '10GB', price: 3700 },
        { id: '12', name: '12GB', price: 4440 },
        { id: '15', name: '15GB', price: 5550 },
        { id: '20', name: '20GB', price: 7400 }
    ],
    "Telecel": [
        { id: '5', name: '5GB', price: 2000 },   
        { id: '10', name: '10GB', price: 3800 }, 
        { id: '15', name: '15GB', price: 5500 }, 
        { id: '20', name: '20GB', price: 7300 }, 
        { id: '25', name: '25GB', price: 9000 }, 
        { id: '30', name: '30GB', price: 11000 },
        { id: '40', name: '40GB', price: 14300 },
        { id: '50', name: '50GB', price: 18000 },
        { id: '100', name: '100GB', price: 35000}
    ]
};

const NETWORK_KEY_MAP = {
    "MTN": 'YELLO',
    "AirtelTigo": 'AT_PREMIUM', 
    "Telecel": 'TELECEL',
};


// --- HELPER FUNCTIONS (omitted for brevity) ---
function findBaseCost(network, capacityId) { /* ... implementation ... */ }
function calculatePaystackFee(chargedAmountInPesewas) { /* ... implementation ... */ }
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


// --- 4. CORE ROUTE DEFINITION (The Stable Structure) ---
mongoose.connection.once('open', () => {

    console.log('Database connection stable. Registering routes...');

    const isAuthenticated = (req, res, next) => req.session.user ? next() : res.redirect('/login.html');

    // --- USER AUTHENTICATION & INFO ROUTES ---
    app.post('/api/signup', async (req, res) => { /* ... implementation ... */ });
    app.post('/api/login', async (req, res) => { /* ... implementation ... */ });
    app.get('/api/logout', (req, res) => { /* ... implementation ... */ });
    app.get('/api/user-info', isAuthenticated, async (req, res) => { /* ... implementation ... */ });


    // --- DATA & PROTECTED PAGES ---
    app.get('/api/data-plans', (req, res) => {
        // 🛑 Final Stability Check before accessing allPlans
        if (!allPlans[req.query.network]) {
            console.error('Data plans requested for unknown network:', req.query.network);
            return res.json([]);
        }
        
        const costPlans = allPlans[req.query.network] || [];
        
        const sellingPlans = costPlans.map(p => {
            const FIXED_MARKUP = 15; 
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
        console.log('Database connection is stable. Starting cron job...');
    });
    cron.schedule('*/5 * * * *', runPendingOrderCheck);
});
