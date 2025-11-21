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
const rateLimit = require('express-rate-limit'); 
const MongoStore = require('connect-mongo');

// 🛑 Import AgentShop model 🛑
const { User, Order, AgentShop, mongoose } = require('./database.js'); 

const app = express();
const PORT = process.env.PORT || 10000;

// 🛑 DATAPACKS.SHOP API BASE URL 🛑
const RESELLER_API_BASE_URL = 'https://datapacks.shop/api.php'; 

// --- 2. DATA (PLANS) AND MAPS ---
// PRICES ARE THE WHOLESALE COST (in PESEWAS)
const allPlans = {
    "MTN": [
        { id: '1', name: '1GB', price: 480 }, { id: '2', name: '2GB', price: 960 }, { id: '3', name: '3GB', price: 1420 }, 
        { id: '4', name: '4GB', price: 2000 }, { id: '5', name: '5GB', price: 2400 }, { id: '6', name: '6GB', price: 2800 }, 
        { id: '8', name: '8GB', price: 3600 }, { id: '10', name: '10GB', price: 4400 }, { id: '15', name: '15GB', price: 6400 },
        { id: '20', name: '20GB', price: 8200 }, { id: '25', name: '25GB', price: 10200 }, { id: '30', name: '30GB', price: 12200 },
        { id: '40', name: '40GB', price: 16200 }, { id: '50', name: '50GB', price: 19800 }
    ],
    "AirtelTigo": [
        { id: '1', name: '1GB', price: 430 }, { id: '2', name: '2GB', price: 900 }, { id: '3', name: '3GB', price: 1320 },  
        { id: '4', name: '4GB', price: 1680 }, { id: '5', name: '5GB', price: 2100 }, { id: '6', name: '6GB', price: 2500 },  
        { id: '7', name: '7GB', price: 2830 }, { id: '8', name: '8GB', price: 3400 }, { id: '9', name: '9GB', price: 3800 },  
        { id: '10', name: '10GB', price: 4250 }, { id: '12', name: '12GB', price: 5200 }, { id: '15', name: '15GB', price: 6250 },
        { id: '20', name: '20GB', price: 8400 }
    ],
    "Telecel": [
        { id: '5', name: '5GB', price: 2300 }, { id: '10', name: '10GB', price: 4300 }, { id: '15', name: '15GB', price: 6220 }, 
        { id: '20', name: '20GB', price: 8300 }, { id: '25', name: '25GB', price: 10300 }, { id: '30', name: '30GB', price: 12300 },
        { id: '40', name: '40GB', price: 15500 }, { id: '50', name: '50GB', price: 19500 }, { id: '100', name: '100GB', price: 40000}
    ]
};

const NETWORK_KEY_MAP = {
    "MTN": 'MTN', 
    "AirtelTigo": 'AT', 
    "Telecel": 'VOD', 
};

const AGENT_REGISTRATION_FEE_PESEWAS = 2000;
const TOPUP_FEE_RATE = 0.02;

// --- HELPER FUNCTIONS ---
function findBaseCost(network, capacityId) {
    const networkPlans = allPlans[network];
    if (!networkPlans) return 0;
    const plan = networkPlans.find(p => p.id === capacityId);
    return plan ? plan.price : 0; 
}

function calculatePaystackFee(chargedAmountInPesewas) {
    const TRANSACTION_FEE_RATE = 0.00200; const TRANSACTION_FEE_CAP = 2000;
    let fullFee = (chargedAmountInPesewas * TRANSACTION_FEE_RATE) + 80;
    let totalFeeChargedByPaystack = Math.min(fullFee, TRANSACTION_FEE_CAP);
    return totalFeeChargedByPaystack;
}

function calculateClientTopupFee(netDepositPesewas) {
    const feeAmount = netDepositPesewas * TOPUP_FEE_RATE;
    const finalCharge = netDepositPesewas + feeAmount;
    return Math.ceil(finalCharge); 
}

// Helper to calculate Paystack fee for a batch order (single fee applied to total)
function calculateBatchPaystackCharge(netTotalPesewas) {
    const CUSTOMER_FLAT_FEE_PESEWAS = 25; 
    const totalCharged = netTotalPesewas + CUSTOMER_FLAT_FEE_PESEWAS;
    return Math.round(totalCharged); // Return the total amount to charge the user
}

async function sendAdminAlertEmail(order) {
    if (!process.env.SENDGRID_API_KEY) {
        console.error("SENDGRID_API_KEY not set. Cannot send alert email.");
        return;
    }
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    const msg = {
        to: 'ajcustomercare2@gmail.com', 
        from: process.env.SENDGRID_SENDER_EMAIL || 'jnkpappoe@gmail.com', 
        subject: `🚨 MANUAL REVIEW REQUIRED: ${order.network || 'N/A'} Data Transfer Failed`,
        html: `
            <h1>Urgent Action Required!</h1>
            <p>A customer payment was successful, but the data bundle transfer failed automatically. Please fulfill this order manually through the Datapacks.shop dashboard.</p>
            <hr>
            <p><strong>Status:</strong> PENDING REVIEW</p>
            <p><strong>Network:</strong> ${order.network || 'N/A'}</p>
            <p><strong>Plan:</strong> ${order.dataPlan || 'N/A'}</p>
            <p><strong>Phone:</strong> ${order.phoneNumber || 'N/A'}</p>
            <p><strong>Amount Paid:</strong> GHS ${order.amount ? order.amount.toFixed(2) : 'N/A'}</p>
            <p><strong>Reference:</strong> ${order.reference || 'N/A'}</p>
            <p><strong>Action:</strong> Go to the Admin Dashboard and click 'Mark Sent' after fulfilling manually.</p>
        `,
    };
    try {
        await sgMail.send(msg);
        console.log(`Manual alert email sent for reference: ${order.reference}`);
    } catch (error) {
        console.error('Failed to send admin alert email:', error.response?.body?.errors || error.message);
    }
}

async function executeDataPurchase(userId, orderDetails, paymentMethod) {
    const { network, dataPlan, amount, reference } = orderDetails;
    
    let finalStatus = 'payment_success'; 
    
    // If reference is not provided (single wallet purchase), generate one.
    const purchaseReference = reference || `${paymentMethod.toUpperCase()}-${crypto.randomBytes(16).toString('hex')}`;

    // --- STEP 1: SETUP & VALIDATION ---
    const resellerApiUrl = RESELLER_API_BASE_URL;
    const networkKey = NETWORK_KEY_MAP[network]; 
    const apiToken = process.env.DATA_API_SECRET; 
    
    if (!networkKey) {
        console.error(`ERROR: Invalid network provided: ${network}`);
        finalStatus = 'pending_review';
    }
    if (!apiToken) {
        console.error("CRITICAL ERROR: DATA_API_SECRET is missing in environment variables.");
        finalStatus = 'pending_review'; 
    }
    
    const resellerPayload = {
        network: networkKey,        
        capacity: dataPlan,          
        recipient: orderDetails.phoneNumber,      
        client_ref: purchaseReference      
    };
    
    // --- STEP 2: ATTEMPT DATA TRANSFER ---
    if (finalStatus === 'payment_success') { 
        try {
            const transferResponse = await axios.post(
                `${resellerApiUrl}?action=order`, 
                resellerPayload, 
                {
                    headers: {
                        'Authorization': `Bearer ${apiToken}`, 
                        'Content-Type': 'application/json'
                    }
                }
            );

            const apiResponseData = transferResponse.data;
            const firstResult = apiResponseData.results && apiResponseData.results.length > 0 ? apiResponseData.results[0] : null;

            if (apiResponseData.success === true && firstResult && 
                (firstResult.status === 'processing' || firstResult.success === true)) {
                
                finalStatus = 'data_sent'; 
                
            } else {
                console.error("Data API Failed: Could not confirm successful submission.");
                
                if (firstResult && firstResult.error) {
                    console.error('SPECIFIC RESELLER ERROR:', firstResult.error); 
                }
                
                console.error('Full Reseller API Response:', apiResponseData);
                finalStatus = 'pending_review';
            }

        } catch (transferError) {
            console.error('Data API Network/Authentication Error:', transferError.message);
            if (transferError.response) {
                console.error('Reseller API Error Status:', transferError.response.status);
                console.error('Reseller API Error Data:', transferError.response.data);
            }
            finalStatus = 'pending_review';
        }
    }

    // --- STEP 3: SAVE FINAL ORDER STATUS & ALERT ---
    await Order.create({
        userId: userId,
        reference: purchaseReference,
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

    return { status: finalStatus, reference: purchaseReference };
}


async function runPendingOrderCheck() {
    console.log('--- CRON: Checking for pending orders needing status update... ---');
    
    try {
        if (mongoose.connection.readyState !== 1) {
            console.log('CRON: Skipping check, database not ready (State: ' + mongoose.connection.readyState + ')');
            return;
        }

        // Only checking data transfer orders that failed immediately
        const pendingOrders = await Order.find({ status: 'pending_review' }).limit(20); 

        if (pendingOrders.length === 0) {
            console.log('CRON: No orders currently pending review.');
            return;
        }

        for (const order of pendingOrders) {
            try {
                // DATAPACKS.SHOP STATUS CHECK LOGIC
                const statusPayload = {
                    action: 'status', 
                    ref: order.reference
                };

                const statusResponse = await axios.get(RESELLERC_API_BASE_URL, {
                    params: statusPayload,
                    headers: { 'Authorization': `Bearer ${process.env.DATA_API_SECRET}` }
                });

                const apiData = statusResponse.data;
                
                if (apiData.status === 'SUCCESSFUL' || apiData.status === 'DELIVERED') {
                    await Order.findByIdAndUpdate(order._id, { status: 'data_sent' });
                    console.log(`CRON SUCCESS: Order ${order.reference} automatically marked 'data_sent'.`);

                } else if (apiData.status === 'FAILED' || apiData.status === 'REJECTED') {
                    await Order.findByIdAndUpdate(order._id, { status: 'data_failed' });
                    console.log(`CRON FAILURE: Order ${order.reference} marked 'data_failed'.`);
                }
            } catch (apiError) {
                if (axios.isAxiosError(apiError)) {
                    console.error(`CRON ERROR: Failed to check status for ${order.reference}. Vendor Status: ${apiError.response?.status || 'Network Error'}`);
                } else {
                    console.error(`CRON ERROR: Failed to check status for ${order.reference}.`, apiError.message);
                }
            }
        }

    } catch (dbError) {
        console.error('CRON FATAL ERROR: Database read failed.', dbError.message);
    }
}


// --- 3. MIDDLEWARE ---
app.set('trust proxy', 1); 

const sessionSecret = process.env.SESSION_SECRET || 'fallback-secret-for-local-dev-only-12345';
const mongoUri = process.env.MONGO_URI;

app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: mongoUri, 
        collectionName: 'sessions',
        touchAfter: 24 * 3600 
    }),
    cookie: { 
        secure: true, 
        maxAge: 1000 * 60 * 60 * 24 
    } 
}));

app.use(express.json());

// 🛑 SECURITY HEADERS MIDDLEWARE 🛑
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

// --- ADDED HEALTH CHECK ENDPOINT ---
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', uptime: process.uptime() });
});
// ------------------------------------

app.use(express.static(path.join(__dirname, 'public')));

// 🛑 RATE LIMITING MIDDLEWARE (Applied to Login route) 🛑
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: {
        message: "Too many login attempts from this IP, please try again after 15 minutes."
    },
    standardHeaders: true,
    legacyHeaders: false,
});


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
        
        // Default role is 'Client'
        await User.create({ username, email, password: hashedPassword, walletBalance: 0, payoutWalletBalance: 0, role: 'Client' }); 
        
        res.status(201).json({ message: 'Account created successfully! Please log in.' });
    } catch (error) { 
        if (error.code === 11000) return res.status(400).json({ message: 'Username or email already exists.' });
        res.status(500).json({ message: 'Server error during signup.' }); 
    }
});

// 🛑 APPLY RATE LIMITER TO LOGIN ROUTE
app.post('/api/login', loginLimiter, isDbReady, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password are required.' });
    try {
        const user = await User.findOne({ username });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        
        if (!user.role) {
            user.role = 'Client';
            await User.findByIdAndUpdate(user._id, { role: 'Client' });
        }
        
        const freshUser = await User.findById(user._id).select('username walletBalance role payoutWalletBalance shopId'); 
        
        req.session.user = { id: user._id, username: freshUser.username, walletBalance: freshUser.walletBalance, role: freshUser.role, payoutWalletBalance: freshUser.payoutWalletBalance, shopId: freshUser.shopId }; 
        
        const redirectUrl = '/purchase.html'; 
        
        res.json({ message: 'Logged in successfully!', redirect: redirectUrl });
        
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.get('/api/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/index.html'));
});

app.get('/api/user-info', isDbReady, isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id).select('username walletBalance email role payoutWalletBalance shopId'); 
        if (!user) {
            req.session.destroy(() => res.status(404).json({ error: 'User not found' }));
            return;
        }
        req.session.user.walletBalance = user.walletBalance; 
        res.json({ 
            username: user.username, 
            walletBalance: user.walletBalance, 
            email: user.email, 
            role: user.role,
            payoutWalletBalance: user.payoutWalletBalance || 0,
            shopId: user.shopId || null
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user data' });
    }
});

app.post('/api/forgot-password', isDbReady, async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'If the email exists, a password reset link has been sent.' });
        }
        
        const resetToken = crypto.randomBytes(20).toString('hex');
        
        user.resetToken = resetToken;
        user.resetTokenExpires = Date.now() + 3600000; // 1 hour
        await user.save();
        
        res.json({ message: 'A password reset link has been sent to your email.' });
        
    } catch (error) {
        res.status(500).json({ message: 'Server error while processing request.' });
    }
});

app.post('/api/reset-password', isDbReady, async (req, res) => {
    const { token, newPassword } = req.body;
    try {
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpires: { $gt: Date.now() } 
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token.' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpires = undefined;
        await user.save();

        res.json({ message: 'Password updated successfully. Please log in.' });

    } catch (error) {
        res.status(500).json({ message: 'Server error while resetting password.' });
    }
});

// NOTE: This Agent Signup logic is only needed for users who still want the 'Agent' role explicitly.
app.post('/api/agent-signup', isDbReady, async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
    
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
        return res.status(400).json({ message: 'User already exists.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const finalRegistrationCharge = calculateClientTopupFee(AGENT_REGISTRATION_FEE_PESEWAS);
        
        const tempUser = await User.create({ 
            username, 
            email, 
            password: hashedPassword, 
            walletBalance: 0, 
            payoutWalletBalance: 0, 
            role: 'Agent_Pending' 
        });

        res.status(200).json({ 
            message: 'Initiate payment for registration.',
            userId: tempUser._id,
            amountPesewas: finalRegistrationCharge 
        });

    } catch (error) {
        res.status(500).json({ message: 'Server error during agent signup initiation.' }); 
    }
});

app.post('/api/verify-agent-payment', async (req, res) => {
    const { reference, userId } = req.body;
    
    const expectedCharge = calculateClientTopupFee(AGENT_REGISTRATION_FEE_PESEWAS);

    try {
        const paystackUrl = `https://api.paystack.co/transaction/verify/${reference}`;
        const paystackResponse = await axios.get(paystackUrl, { 
            headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } 
        });
        const { status, data } = paystackResponse.data;
        
        const acceptableMinimum = Math.floor(expectedCharge * 0.95);
        const acceptableMaximum = Math.ceil(expectedCharge * 1.05);
        
        if (data.status === 'success' && data.amount >= acceptableMinimum && data.amount <= acceptableMaximum) {
            
            const user = await User.findByIdAndUpdate(
                userId, 
                { role: 'Agent' }, 
                { new: true }
            );

            if (user) {
                return res.json({ message: 'Registration successful! You are now an Agent.', role: 'Agent' });
            }
        }
        
        res.status(400).json({ message: 'Payment verification failed. Please try again.' });

    } catch (error) {
        console.error('Agent payment verification error:', error);
        await User.findByIdAndDelete(userId);
        res.status(500).json({ message: 'Verification failed. Contact support.' });
    }
});


// 🛑 NEW: AGENT SHOP ENDPOINTS (Accessible to all authenticated users) 🛑

// Agent creates their shop and sets default pricing/name
app.post('/api/agent/create-shop', isDbReady, isAuthenticated, async (req, res) => {
    const userId = req.session.user.id;
    const { shopName } = req.body;

    const user = await User.findById(userId);
    // 🛑 REMOVED ROLE CHECK: Any logged-in user can create a shop.
    if (!user) {
        return res.status(404).json({ message: 'User data not found in session.' });
    }

    // Check if shop already exists
    if (user.shopId) {
        return res.status(400).json({ message: 'Shop already exists.' });
    }

    try {
        // Generate a simple, unique shop ID (8 characters long)
        const shopId = crypto.randomBytes(4).toString('hex');

        // Create Shop with zero markup by default
        await AgentShop.create({
            userId: userId,
            shopId: shopId,
            shopName: shopName || `${user.username}'s Store`,
            customMarkups: {} // Initialize with empty map
        });

        // Link the shop ID back to the user
        await User.findByIdAndUpdate(userId, { shopId: shopId });
        
        // Update session immediately
        req.session.user.shopId = shopId; 

        res.json({
            status: 'success',
            shopId: shopId,
            link: `${req.protocol}://${req.get('host')}/agent_shop.html?shopId=${shopId}`,
            message: 'Shop created successfully!'
        });
    } catch (error) {
        console.error('Shop creation error:', error);
        res.status(500).json({ message: 'Failed to create shop. Server error.' });
    }
});

// Agent sets or retrieves custom plans for their shop
app.get('/api/agent/plans', isDbReady, async (req, res) => {
    const { shopId, network } = req.query;
    if (!shopId || !network) return res.status(400).json({ message: 'Shop ID and network are required.' });

    try {
        const agentShop = await AgentShop.findOne({ shopId });
        const networkPlans = allPlans[network];
        
        if (!networkPlans) return res.status(404).json({ message: 'Invalid network.' });
        if (!agentShop) return res.status(404).json({ message: 'Shop not found.' });

        // Safely access the map for the specific network, defaulting to empty Map if not set
        const networkMarkups = agentShop.customMarkups.get(network) || {}; 

        const sellingPlans = networkPlans.map(p => {
            const wholesalePrice = p.price;
            // Lookup markup using the plan ID (e.g., '1', '5')
            const individualMarkup = networkMarkups[p.id] || 0; 
            
            let rawSellingPrice = wholesalePrice + individualMarkup; 
            // Final price calculation (Rounded to nearest 5 pesewas, ensuring it meets wholesale price)
            const finalPrice = Math.ceil(Math.max(rawSellingPrice, wholesalePrice) / 5) * 5; 
            
            return { 
                id: p.id, 
                name: p.name, 
                price: finalPrice, 
                wholesalePrice: wholesalePrice 
            };
        });

        res.json({ plans: sellingPlans, shopName: agentShop.shopName });
        
    } catch (error) {
        console.error('Agent plans error:', error);
        res.status(500).json({ message: 'Server error loading plans.' });
    }
});

// Updates markup for a single package
app.post('/api/agent/update-markup', isDbReady, isAuthenticated, async (req, res) => {
    const userId = req.session.user.id;
    const { network, capacityId, markupValue } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
        return res.status(403).json({ message: 'Unauthorized. User data not found.' });
    }
    if (!network || !capacityId || markupValue === undefined) {
         return res.status(400).json({ message: 'Missing network, capacity ID, or markup value.' });
    }
    
    try {
        const agentShop = await AgentShop.findOne({ userId });
        if (!agentShop) return res.status(404).json({ message: 'Shop not found. Please create one first.' });

        // 1. Get current markups object for the network
        const networkMarkupsMap = agentShop.customMarkups.get(network) || {}; 
        let updatedNetworkMarkups = { ...networkMarkupsMap };
        
        // 2. Update ONLY the specific capacity ID's markup in the object
        updatedNetworkMarkups[capacityId] = parseInt(markupValue, 10);
        
        // 3. CRITICAL FIX: Set the entire updated object back onto the Mongoose Map field
        // This is necessary for Mongoose to correctly save the nested Map structure
        agentShop.customMarkups.set(network, updatedNetworkMarkups);

        // 4. Force Mongoose to acknowledge the change in the sub-document path
        agentShop.markModified(`customMarkups.${network}`); 

        await agentShop.save();

        res.json({ status: 'success', message: `${network} ${capacityId}GB markup updated to ${markupValue} pesewas.` });
        
    } catch (error) {
        console.error("Mongoose Map Save Error:", error);
        res.status(500).json({ message: 'Failed to update markup. Server error.' });
    }
});


// 🛑 Withdrawal Request 🛑
app.post('/api/withdraw-profit', isDbReady, isAuthenticated, async (req, res) => {
    const userId = req.session.user.id;
    const { amountPesewas, accountDetails } = req.body;
    
    if (!amountPesewas || amountPesewas < 500) { 
        return res.status(400).json({ message: 'Minimum withdrawal is GHS 5.00.' });
    }
    if (!accountDetails || !accountDetails.accountNumber || !accountDetails.network) {
        return res.status(400).json({ message: 'Missing account or network details.' });
    }

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: 'User not found.' });

        if (user.payoutWalletBalance < amountPesewas) {
            return res.status(400).json({ message: 'Insufficient payout balance.' });
        }
        
        const debitResult = await User.findByIdAndUpdate(
            userId,
            { $inc: { payoutWalletBalance: -amountPesewas } },
            { new: true, runValidators: true }
        );

        req.session.user.payoutWalletBalance = debitResult.payoutWalletBalance;

        await Order.create({
            userId: userId,
            reference: `WITHDRAWAL-${crypto.randomBytes(12).toString('hex')}`,
            phoneNumber: accountDetails.accountNumber,
            network: accountDetails.network,
            dataPlan: 'WITHDRAWAL REQUEST',
            amount: amountPesewas / 100, 
            status: 'withdrawal_pending',
            paymentMethod: 'payout'
        });

        res.json({ 
            status: 'success', 
            message: `Withdrawal of GHS ${(amountPesewas / 100).toFixed(2)} requested successfully.`,
            newPayoutBalance: debitResult.payoutWalletBalance
        });

    } catch (error) {
        res.status(500).json({ message: 'Server error during withdrawal request.' });
    }
});


// 🛑 BATCH CHECKOUT (Handles Agent Shop Public Sales) 🛑
app.post('/api/checkout-orders', isDbReady, isAuthenticated, async (req, res) => {
    const { orders, paymentMethod, totalAmountPesewas, reference } = req.body;
    const userId = req.session.user.id;
    
    if (!orders || orders.length === 0 || !totalAmountPesewas) {
        return res.status(400).json({ status: 'error', message: 'Cart is empty or total amount is missing.' });
    }

    let user;
    let chargedAmountPesewas;
    let paymentRef = reference;
    let fulfilledCount = 0;

    try {
        user = await User.findById(userId);
        if (!user) return res.status(404).json({ status: 'error', message: 'User not found.' });

        // --- PHASE 1: HANDLE PAYMENT DEBIT/VERIFICATION ---

        if (paymentMethod === 'wallet') {
            chargedAmountPesewas = totalAmountPesewas;
            if (user.walletBalance < chargedAmountPesewas) {
                return res.status(400).json({ status: 'error', message: 'Insufficient wallet balance for batch order.' });
            }
            await User.findByIdAndUpdate(userId, { $inc: { walletBalance: -chargedAmountPesewas } });
        } else if (paymentMethod === 'paystack' && paymentRef) {
            chargedAmountPesewas = calculateBatchPaystackCharge(totalAmountPesewas);

            // Verify Paystack payment (assuming Paystack verification logic runs here)
            const paystackUrl = `https://api.paystack.co/transaction/verify/${paymentRef}`;
            const paystackResponse = await axios.get(paystackUrl, { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } });
            const { data } = paystackResponse.data;

            if (data.status !== 'success') {
                return res.status(400).json({ status: 'error', message: 'Payment verification failed. Please try again.' });
            }
            // Use flexible check for paystack fees
            const acceptableMin = Math.floor(chargedAmountPesewas * 0.95);
            const acceptableMax = Math.ceil(chargedAmountPesewas * 1.05);

            if (data.amount < acceptableMin || data.amount > acceptableMax) {
                console.error(`Batch Fraud: Charged ${data.amount} expected ${chargedAmountPesewas}`);
                return res.status(400).json({ status: 'error', message: 'Amount charged mismatch detected. Contact support.' });
            }

        } else {
            return res.status(400).json({ status: 'error', message: 'Invalid payment method or missing reference.' });
        }
        
        // Refresh user balance for session
        const updatedUser = await User.findById(userId).select('walletBalance');
        req.session.user.walletBalance = updatedUser.walletBalance;

        const agentShop = await AgentShop.findOne({ shopId: user.shopId });

        let profitToCredit = 0; 
        
        for (const item of orders) {
            try {
                const baseWholesaleCost = findBaseCost(item.network, item.dataPlanId);
                const retailPricePaid = item.amountPesewas;
                
                let itemProfit = 0;
                if (agentShop) {
                    // Use the specific AgentShop markup stored in the nested map
                    const networkMarkups = agentShop.customMarkups.get(item.network) || {};
                    const markup = networkMarkups[item.dataPlanId] || 0;
                    itemProfit = markup; // Profit is simply the explicit markup set by the agent
                } else {
                    // Safety net if shop doesn't exist
                    itemProfit = Math.max(0, retailPricePaid - baseWholesaleCost); 
                }
                
                // 🛑 Profit is credited unconditionally 🛑
                profitToCredit += itemProfit;
                
                const itemDetails = {
                    network: item.network,
                    dataPlan: item.dataPlanId,
                    phoneNumber: item.phoneNumber,
                    // Use WHOLESALE COST for API execution amount
                    amount: baseWholesaleCost / 100, 
                    reference: paymentMethod === 'paystack' ? `${paymentRef}-ITEM-${item.id}` : undefined 
                };
                
                // Execute purchase for single item (using WHOLESALE COST)
                const result = await executeDataPurchase(userId, itemDetails, paymentMethod);
                if (result.status !== 'data_failed') {
                    fulfilledCount++;
                }

            } catch (e) {
                console.error(`Error processing single item in batch: ${e.message}`);
            }
        }
        
        // 3. CREDIT PROFIT (If applicable)
        if (profitToCredit > 0) {
            const finalUser = await User.findByIdAndUpdate(userId, { $inc: { payoutWalletBalance: profitToCredit } }, { new: true });
            req.session.user.payoutWalletBalance = finalUser.payoutWalletBalance;
        }

        if (fulfilledCount > 0) {
            return res.json({ status: 'success', message: `${fulfilledCount} orders placed. Check dashboard.`, fulfilledCount });
        } else {
             return res.status(500).json({ status: 'error', message: 'Zero orders could be fulfilled. Contact support.', fulfilledCount: 0 });
        }

    } catch (error) {
        console.error('Batch Checkout Error:', error);
        res.status(500).json({ status: 'error', message: 'Server error during batch checkout.' });
    }
});


// --- DATA & PROTECTED PAGES ---

app.get('/api/data-plans', isDbReady, async (req, res) => { 
    const sellingPlans = allPlans[req.query.network] || [];
    // Standard app usage defaults to wholesale price
    res.json(sellingPlans.map(p => ({
        id: p.id,
        name: p.name,
        price: p.price
    })));
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


// --- ADMIN & MANAGEMENT ROUTES ---
app.get('/api/admin/all-users-status', async (req, res) => {
    if (req.query.secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized" });
    
    try {
        if (mongoose.connection.readyState !== 1) return res.status(503).json({ error: 'Database not ready.' });

        const registeredUsers = await User.find({}).select('username email createdAt role').lean();

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
            } catch (e) { console.warn("Failed to parse session data:", e.message); }
        });

        const userListWithStatus = registeredUsers.map(user => ({
            username: user.username, email: user.email, signedUp: user.createdAt,
            isOnline: activeUserIds.has(user._id.toString()), role: user.role
        }));

        res.json({ users: userListWithStatus });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user list and status' });
    }
});

app.get('/api/get-all-orders', async (req, res) => {
    if (req.query.secret !== process.env.ADMIN_SECRET) {
        return res.status(403).json({ error: "Unauthorized: Invalid Admin Secret" });
    }
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ error: 'Database not ready for admin query.' });
        }
        
        const orders = await Order.find({})
                                 .sort({ createdAt: -1 })
                                 .populate('userId', 'username'); 
        
        const formattedOrders = orders.map(order => ({
            id: order._id, username: order.userId ? order.userId.username : 'Deleted User',
            phoneNumber: order.phoneNumber, network: order.network || 'N/A', 
            dataPlan: order.dataPlan, amount: order.amount, status: order.status,
            created_at: order.createdAt,
        }));
        res.json({ orders: formattedOrders });
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch orders" });
    }
});

app.get('/api/admin/user-count', async (req, res) => {
    if (req.query.secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Unauthorized' });
    try {
        if (mongoose.connection.readyState !== 1) return res.status(503).json({ error: 'Database not ready.' });

        const count = await User.countDocuments({});
        res.json({ count: count });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user count' });
    }
});

app.post('/api/admin/update-order', async (req, res) => {
    if (req.body.adminSecret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Unauthorized access.' });
    const { orderId, newStatus } = req.body;
    
    if (!orderId || !newStatus) return res.status(400).json({ error: 'Order ID and new status are required.' });

    try {
        const result = await Order.findByIdAndUpdate(orderId, { status: newStatus }, { new: true });
        if (!result) return res.status(404).json({ message: 'Order not found.' });
        
        res.json({ status: 'success', message: `Order ${orderId} status updated to ${newStatus}.` });

    } catch (error) {
        res.status(500).json({ error: 'Failed to update order status.' });
    }
});

app.get('/api/admin/metrics', async (req, res) => {
    if (req.query.secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Unauthorized' });

    try {
        if (mongoose.connection.readyState !== 1) return res.status(503).json({ error: 'Database not ready.' });

        const successfulOrders = await Order.find({ status: 'data_sent' });
        
        let totalRevenueGHS = 0;
        let totalCostGHS = 0;
        let totalPaystackFeeGHS = 0;

        successfulOrders.forEach(order => {
            const chargedAmountInPesewas = Math.round(order.amount * 100);
            
            const resellerCostInPesewas = findBaseCost(order.network, order.dataPlan);
            const paystackFeeInPesewas = calculatePaystackFee(chargedAmountInPesewas);
            
            totalRevenueGHS += order.amount; 
            totalPaystackFeeGHS += (paystackFeeInPesewas / 100);
            totalCostGHS += (resellerCostInPesewas / 100); 
        });
        
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
        res.status(500).json({ error: 'Failed to calculate metrics' });
    }
});

app.delete('/api/admin/delete-user', async (req, res) => {
    const { userId, adminSecret } = req.body;
    
    if (adminSecret !== process.env.ADMIN_SECRET) {
        return res.status(403).json({ error: 'Unauthorized: Invalid Admin Secret' });
    }

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required for deletion.' });
    }

    try {
        // 1. Delete all associated orders first
        const ordersResult = await Order.deleteMany({ userId: userId });

        // 2. Delete the user
        const userResult = await User.findByIdAndDelete(userId);

        if (!userResult) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.json({ 
            status: 'success', 
            message: `User '${userResult.username}' and ${ordersResult.deletedCount} associated orders deleted successfully.` 
        });
    } catch (error) {
        console.error('User Deletion Error:', error);
        res.status(500).json({ error: 'Failed to delete user and associated data.' });
    }
});


// --- SERVE HTML FILES (Includes New Agent Shop Routes) ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/signup.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/purchase.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'purchase.html')));
app.get('/checkout.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'checkout.html')));
app.get('/dashboard.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/forgot.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'forgot.html')));
app.get('/reset.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset.html')));
app.get('/terms.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));
app.get('/privacy.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/support.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'support.html')));
// 🛑 NEW AGENT SHOP ROUTES 🛑
app.get('/agent_shop_setup.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'agent_shop_setup.html')));
app.get('/agent_shop.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'agent_shop.html'))); // Public, no auth required


// --- SERVER START ---
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is LIVE on port ${PORT}`);
    console.log('Database connection is initializing...');
    
    cron.schedule('*/5 * * * *', runPendingOrderCheck); // Runs every 5 minutes
});
