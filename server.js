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

// --- HELPER: SEND ADMIN ALERT EMAIL ---
async function sendAdminAlertEmail(order) {
    if (!process.env.SENDGRID_API_KEY) {
        console.error("SENDGRID_API_KEY not set. Cannot send alert email.");
        return;
    }
    
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    
    const msg = {
        to: 'YOUR_ADMIN_RECEIVING_EMAIL@example.com', 
        from: 'YOUR_VERIFIED_SENDER_EMAIL@example.com', 
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

// --- CORE AUTOMATION: STATUS CHECK SCHEDULER ---
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
        console.error('CRON FATAL ERROR: Database read failed.', dbError.message);
    }
}

// --- HELPER: FIND BASE COST PRICE ---
function findBaseCost(network, capacityId) {
    const networkPlans = allPlans[network];
    if (!networkPlans) return 0;
    const plan = networkPlans.find(p => p.id === capacityId);
    return plan ? plan.price : 0; // Returns cost in pesewas
}

// --- HELPER: CALCULATE PAYSTACK FEE ---
function calculatePaystackFee(chargedAmountInPesewas) {
    const TRANSACTION_FEE_RATE = 0.019;
    const TRANSACTION_FEE_CAP = 2000;
    
    // This function must reverse the client-side logic to find the total Paystack fee incurred.
    // Since the client absorbs the flat 80 pesewas, we look for the total charged.
    
    // We assume the amount charged is (Selling Price) + (1.9% of Selling Price).
    // The amount Paystack deducts is 1.9% of the transaction amount + 80 pesewas (up to cap).
    
    let amountToCalculateFeeOn = chargedAmountInPesewas;
    
    let fullFee = (amountToCalculateFeeOn * TRANSACTION_FEE_RATE) + 80;
    
    // Apply Cap Check
    let totalFeeChargedByPaystack = Math.min(fullFee, TRANSACTION_FEE_CAP);
    
    return totalFeeChargedByPaystack;
}

// --- HELPER: EXECUTE DATA PURCHASE ---
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


// --- 7. SERVER START ---
mongoose.connection.once('open', () => {

    console.log('Database connection stable. Registering routes...');

    // --- MIDDLEWARE (executed after DB is ready) ---
    app.use(express.json());
    app.use(express.static(path.join(__dirname, 'public')));

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
            const user = await User.findById(req.session.user.id).select('username walletBalance email'); // Fetch email too for topup
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

    // --- WALLET & PAYSTACK ROUTES ---
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

            res.json({ status: 'success', message: `Wallet topped up successfully!`, newBalance: updatedUser.walletBalance });

        } catch (error) {
            console.error('Topup Verification Error:', error);
            res.status(500).json({ status: 'error', message: 'An internal server error occurred during top-up.' });
        }
    });

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

    app.post('/paystack/verify', isAuthenticated, async (req, res) => {
        const { reference } = req.body;
        if (!reference) return res.status(400).json({ status: 'error', message: 'Reference is required.' });

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
            
            orderDetails = {
                userId: userId,
                reference: reference,
                phoneNumber: phone_number,
                network: network,
                dataPlan: data_plan,
                amount: amountInGHS,
                status: 'payment_success'
            };
            
            // Execute the data transfer and save order 
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

    app.get('/api/admin/metrics', async (req, res) => {
        if (req.query.secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized" });

        try {
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
            console.error('Metrics error:', error);
            res.status(500).json({ error: "Failed to calculate metrics" });
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


    // --- SERVE HTML FILES ---
    app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
    app.get('/purchase', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'purchase.html')));
    app.get('/dashboard', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

    
    // --- SERVER START ---
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server is LIVE on port ${PORT}`);
        console.log('Database connection is stable. Starting cron job...');
    });
    // Start the cron job after the server is listening
    cron.schedule('*/5 * * * *', runPendingOrderCheck);
});
