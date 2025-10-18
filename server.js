// --- 1. IMPORTS AND SETUP ---
require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sgMail = require('@sendgrid/mail');
const axios = require('axios');
const crypto = require('crypto');
const db = require('./database.js');

const app = express();
const PORT = process.env.PORT || 10000;

// --- 2. DATA (PLANS) ---
const allPlans = {
    "MTN": [{ id: 'mtn_1gb', name: '1GB', price: 450 }, { id: 'mtn_2gb', name: '2GB', price: 930 }, { id: 'mtn_5gb', name: '5GB', price: 2300 }, { id: 'mtn_10gb', name: '10GB', price: 4200 }],
    "AirtelTigo": [{ id: 'tigo_1gb', name: '1GB', price: 370 }, { id: 'tigo_2gb', name: '2GB', price: 750 }, { id: 'tigo_5gb', name: '5GB', price: 1930 }, { id: 'tigo_10gb', name: '10GB', price: 3600 }],
    "Telecel": [{ id: 'telecel_5gb', name: '5GB', price: 2120 }, { id: 'telecel_10gb', name: '10GB', price: 4000 }, { id: 'telecel_15gb', name: '15GB', price: 5700 }, { id: 'telecel_20gb', name: '20GB', price: 7900 }]
};

// --- 3. MIDDLEWARE ---
const sessionSecret = process.env.SESSION_SECRET || 'fallback-secret-for-local-dev-only-12345';
if (sessionSecret === 'fallback-secret-for-local-dev-only-12345') {
    console.log('--- WARNING: SESSION_SECRET not found. Using a temporary secret. OK for local testing. ---');
}
app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 } // 1 hour
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


// --- 4. AUTHENTICATION & PAGE ROUTES ---
const isAuthenticated = (req, res, next) => req.session.user ? next() : res.redirect('/login.html');

app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, [username, email, hashedPassword], function(err) {
            if (err) return res.status(400).json({ message: 'Username or email already exists.' });
            sendConfirmationEmail(email, username);
            res.status(201).json({ message: 'User created successfully!' });
        });
    } catch { res.status(500).json({ message: 'Server error during signup.' }); }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password are required.' });
    
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        req.session.user = { id: user.id, username: user.username };
        res.json({ message: 'Logged in successfully!' });
    });
});

app.get('/api/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login.html'));
});

// Protected page routes
app.get('/purchase', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'purchase.html')));
app.get('/dashboard', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

// --- 5. CLIENT & ADMIN API ROUTES ---
app.get('/api/data-plans', (req, res) => res.json(allPlans[req.query.network] || []));

app.get('/api/my-orders', isAuthenticated, (req, res) => {
    db.all("SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC", [req.session.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: "Failed to fetch orders" });
        res.json({ orders: rows });
    });
});

app.get('/api/get-all-orders', (req, res) => {
    if (req.query.secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized" });
    db.all("SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC", [], (err, rows) => {
        if (err) return res.status(500).json({ error: "Failed to fetch orders" });
        res.json({ orders: rows });
    });
});

// --- 6. PAYMENT ROUTE (WITH DATA VENDING LOGIC) ---
app.post('/paystack/verify', isAuthenticated, async (req, res) => {
    const { reference } = req.body;
    if (!reference) return res.status(400).json({ status: 'error', message: 'Reference is required.' });

    try {
        const url = `https://api.paystack.co/transaction/verify/${reference}`;
        const response = await axios.get(url, { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } });
        const { status, data } = response.data;

        if (status && data.status === 'success') {
            const { phone_number, network, data_plan } = data.metadata;
            let finalStatus = 'payment_success'; // Start with this status

            // =================================================================
            // START: DATA VENDING API CALL
            // =================================================================
            try {
                // Check if the data vendor API key is available
                if (process.env.DATA_VENDOR_API_KEY) {
                    // Make the API call to your data vendor
                    // IMPORTANT: Replace the URL and the structure of the body with your vendor's actual requirements
                    const vendorResponse = await axios.post('https://api.yourdatavendor.com/send-data', {
                        apiKey: process.env.DATA_VENDOR_API_KEY,
                        phoneNumber: phone_number,
                        network: network,
                        plan: data_plan // Note: Your vendor might require a plan ID instead of the text
                    });

                    // Check the response from your vendor to see if it was successful
                    if (vendorResponse.data && vendorResponse.data.status === 'success') {
                        finalStatus = 'data_sent';
                        console.log(`Successfully sent data for order ${reference}`);
                    } else {
                        finalStatus = 'data_failed';
                        console.error(`Data vending failed for order ${reference}:`, vendorResponse.data.message || 'Unknown vendor error');
                    }
                } else {
                    finalStatus = 'data_failed';
                    console.error('DATA_VENDOR_API_KEY is not set. Cannot send data.');
                }
            } catch (vendorError) {
                finalStatus = 'data_failed';
                console.error(`CRITICAL: The call to the data vendor API failed for order ${reference}:`, vendorError.message);
            }
            // =================================================================
            // END: DATA VENDING API CALL
            // =================================================================

            const amountInGHS = data.amount / 100;
            const userId = req.session.user.id;

            // Save the final, real status to the database
            db.run(`INSERT INTO orders (user_id, reference, phone_number, network, data_plan, amount, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [userId, reference, phone_number, network, data_plan, amountInGHS, finalStatus]);

            // Respond to the user
            if (finalStatus === 'data_sent') {
                return res.json({ status: 'success', message: 'Payment successful. Your data is on its way!' });
            } else {
                return res.status(500).json({ status: 'error', message: 'Payment was successful, but data delivery failed. Please contact support.' });
            }
        } else {
            return res.status(400).json({ status: 'error', message: 'Payment verification failed.' });
        }
    } catch (error) {
        console.error('Verification Error:', error.message);
        return res.status(500).json({ status: 'error', message: 'An internal server error occurred during verification.' });
    }
});


// --- 7. HELPER FUNCTION ---
async function sendConfirmationEmail(email, username) {
    if (!process.env.SENDGRID_API_KEY) {
        console.log("SENDGRID_API_KEY not set. Skipping email.");
        return;
    }
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    const msg = {
        to: email,
        from: 'YOUR_VERIFIED_SENDER_EMAIL@example.com', // IMPORTANT: Use your verified SendGrid sender email
        subject: 'Welcome to DataLink!',
        html: `<b>Hello ${username},</b><br><p>Your account has been created successfully.</p>`,
    };
    try {
        await sgMail.send(msg);
        console.log(`Confirmation email sent to ${email}`);
    } catch (error) {
        console.error('Failed to send email:', error.response?.body || error);
    }
}

// --- 8. SERVER START ---
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
