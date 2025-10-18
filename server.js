// --- 1. IMPORTS AND SETUP ---
require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sgMail = require('@sendgrid/mail');
const nodemailer = require('nodemailer');
const axios = require('axios');
const crypto = require('crypto');
const db = require('./database.js');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 2. DATA (PLANS) ---
const allPlans = {
    "MTN": [ { id: 'mtn_1gb', name: '1GB', price: 450 }, { id: 'mtn_2gb', name: '2GB', price: 930 }, { id: 'mtn_5gb', name: '5GB', price: 2300 }, { id: 'mtn_10gb', name: '10GB', price: 4200 }, { id: 'mtn_50gb', name: '50GB', price: 19500 }],
    "AirtelTigo": [ { id: 'tigo_1gb', name: '1GB', price: 370 }, { id: 'tigo_2gb', name: '2GB', price: 750 }, { id: 'tigo_5gb', name: '5GB', price: 1930 }, { id: 'tigo_10gb', name: '10GB', price: 3600 }, { id: 'tigo_50gb', name: '50GB', price: 11200 }],
    "Telecel": [ { id: 'telecel_5gb', name: '5GB', price: 2120 }, { id: 'telecel_10gb', name: '10GB', price: 4000 }, { id: 'telecel_20gb', name: '20GB', price: 7900 }, { id: 'telecel_50gb', name: '50GB', price: 18900 }, { id: 'telecel_100gb', name: '100GB', price: 36800 }]
};

// --- 3. MIDDLEWARE ---
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 1000 * 60 * 60 // 1 hour inactivity timeout
    }
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- 4. AUTHENTICATION & USER ROUTES ---
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login.html');
    }
};
app.get('/purchase', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'purchase.html'));
});



app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, [username, email, hashedPassword], function(err) {
            if (err) return res.status(400).json({ message: 'Username or email already exists.' });
            async function sendConfirmationEmail(email, username) {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);

    const msg = {
        to: email,
        from: 'your-verified-email@example.com', // Use the email you verified as a "Sender" on SendGrid
        subject: 'Welcome to DataLink! ✔',
        html: `<b>Hello ${username},</b><br><p>Your account has been created successfully. You can now log in and purchase data anytime.</p>`,
    };

    try {
        await sgMail.send(msg);
        console.log(`Confirmation email sent to ${email} via SendGrid`);
    } catch (error) {
        console.error('Failed to send email via SendGrid:', error);
        if (error.response) {
            console.error(error.response.body);
        }
    }
   }
            
            res.status(201).json({ message: 'User created successfully!' });
        });
    } catch (error) { res.status(500).json({ message: 'Server error.' }); }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'All fields are required.' });
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (!user) return res.status(401).json({ message: 'Invalid credentials.' });
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            req.session.user = { id: user.id, username: user.username };
            res.json({ message: 'Logged in successfully!' });
        } else {
            res.status(401).json({ message: 'Invalid credentials.' });
        }
    });
});

app.get('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/login.html');
    });
});

app.get('/purchase', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'purchase.html')));
app.get('/dashboard', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

// --- 5. CLIENT & PAYMENT API ROUTES ---
app.get('/api/data-plans', (req, res) => {
    const network = req.query.network;
    res.json(allPlans[network] || []);
});

app.get('/api/my-orders', isAuthenticated, (req, res) => {
    const userId = req.session.user.id;
    db.all("SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC", [userId], (err, rows) => {
        if (err) return res.status(500).json({ error: "Failed to fetch orders" });
        res.json({ orders: rows });
    });
});

app.post('/paystack/verify', isAuthenticated, async (req, res) => {
    const { reference } = req.body;
    if (!reference) return res.status(400).json({ status: 'error', message: 'Reference is required' });
    try {
        const url = `https://api.paystack.co/transaction/verify/${reference}`;
        const response = await axios.get(url, { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } });
        const { status, data } = response.data;
        if (status && data.status === 'success') {
            const { metadata } = data;
            const stmt = db.prepare(`INSERT INTO orders (user_id, reference, email, phone_number, network, data_plan, amount, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'payment_success')`);
            stmt.run(req.session.user.id, reference, data.customer.email, metadata.phone_number, metadata.network, metadata.data_plan, data.amount / 100);
            stmt.finalize();
            // TODO: Add your real data vending logic here, then update status to 'data_sent' or 'data_failed'
            console.log(`SUCCESS: Order ${reference} for ${metadata.phone_number} paid.`);
            return res.json({ status: 'success', message: 'Payment verified.' });
        } else {
            return res.status(400).json({ status: 'error', message: 'Payment verification failed.' });
        }
    } catch (error) {
        return res.status(500).json({ status: 'error', message: 'Internal server error.' });
    }
});

// --- 6. ADMIN & WEBHOOK ROUTES ---
app.post('/paystack/webhook', (req, res) => { /* ... existing webhook logic ... */ });
app.get('/api/get-all-orders', (req, res) => { /* ... existing admin logic ... */ });

// --- 7. HELPER FUNCTIONS ---
async function sendConfirmationEmail(email, username) {
    try {
        let transporter = nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } });
        await transporter.sendMail({
            from: `"DataLink" <${process.env.EMAIL_USER}>`, to: email, subject: "Welcome to DataLink! ✔",
            html: `<b>Hello ${username},</b><br><p>Your account has been created successfully.</p>`,
        });
        console.log(`Confirmation email sent to ${email}`);
    } catch (error) { console.error("Failed to send email:", error); }
}

// --- 8. SERVER START ---
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});



