require('dotenv').config();
const path = require('path');
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const db = require('./database.js');

const app = express();
const PORT = process.env.PORT || 3000;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

// A simple "database" of your data plans.
const allPlans = {
    "MTN": [
        { id: 'mtn_1gb', name: '1GB', price: 450 },
        { id: 'mtn_2gb', name: '2GB', price: 930 },
        { id: 'mtn_3gb', name: '3GB', price: 1400 },
        { id: 'mtn_5gb', name: '5GB', price: 2300 },
        { id: 'mtn_10gb', name: '10GB', price: 4200 },
        { id: 'mtn_15gb', name: '15GB', price: 6200 },
        { id: 'mtn_20gb', name: '20GB', price: 8200 },
        { id: 'mtn_30gb', name: '30GB', price: 12100 },
        { id: 'mtn_50gb', name: '50GB', price: 19500 },
        { id: 'mtn_100gb', name: '100GB', price: 38000 },
    ],
    "AirtelTigo": [
        { id: 'tigo_1gb', name: '1GB', price: 370 },
        { id: 'tigo_2gb', name: '2GB', price: 750 },
        { id: 'tigo_3gb', name: '3GB', price: 1150 },
        { id: 'tigo_5gb', name: '5GB', price: 1930 },
        { id: 'tigo_10gb', name: '10GB', price: 3600 },
        { id: 'tigo_15gb', name: '15GB', price: 57000 },
        { id: 'tigo_20gb', name: '20GB', price: 6000 },
        { id: 'tigo_30gb', name: '30GB', price: 8000 },
        { id: 'tigo_50gb', name: '50GB', price: 11200 },
        { id: 'tigo_100gb', name: '100GB', price: 18600 }
    ],
    "Telecel": [
        { id: 'telecel_5gb', name: '5GB', price: 2120 },
        { id: 'telecel_10gb', name: '10GB', price: 4000 },
        { id: 'telecel_15gb', name: '15GB', price: 5700 },
        { id: 'telecel_20gb', name: '20GB', price: 7900 },
        { id: 'telecel_30gb', name: '30GB', price: 11500 },
        { id: 'telecel_50gb', name: '50GB', price: 18900 },
        { id: 'telecel_100gb', name: '100GB', price: 36800 }
    ]
};

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'Public')));

// API Routes
app.get('/api/data-plans', (req, res) => {
    const network = req.query.network;
    if (network && allPlans[network]) {
        res.json(allPlans[network]);
    } else {
        res.json([]);
    }
});

app.post('/paystack/verify', async (req, res) => {
    const { reference } = req.body;
    if (!reference) {
        return res.status(400).json({ status: 'error', message: 'Reference is required' });
    }
    try {
        const url = `https://api.paystack.co/transaction/verify/${reference}`;
        const response = await axios.get(url, {
            headers: {
                Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`
            }
        });
        const { status, data } = response.data;
        if (status && data.status === 'success') {
            const orderDetails = data.metadata;
            const amountInGHS = data.amount / 100;
            const stmt = db.prepare(`
                INSERT INTO orders (reference, email, phone_number, network, data_plan, amount, status)
                VALUES (?, ?, ?, ?, ?, ?, 'success')
                ON CONFLICT(reference) DO UPDATE SET status = 'success'
            `);
            stmt.run(reference, data.customer.email, orderDetails.phone_number, orderDetails.network, orderDetails.data_plan, amountInGHS);
            stmt.finalize();
            console.log(`SUCCESS: Order ${reference} for ${orderDetails.phone_number} fulfilled.`);
            return res.json({ status: 'success', message: 'Payment verified and order processed.' });
        } else {
            return res.status(400).json({ status: 'error', message: 'Payment verification failed.' });
        }
    } catch (error) {
        console.error('Verification API Error:', error.response ? error.response.data : error.message);
        return res.status(500).json({ status: 'error', message: 'An internal server error occurred.' });
    }
});

app.post('/paystack/webhook', (req, res) => {
    const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(JSON.stringify(req.body)).digest('hex');
    if (hash !== req.headers['x-paystack-signature']) {
        return res.sendStatus(400);
    }
    const event = req.body;
    if (event.event === 'charge.success') {
        const { reference, metadata, amount, customer } = event.data;
        const amountInGHS = amount / 100;
        const stmt = db.prepare(`
            INSERT INTO orders (reference, email, phone_number, network, data_plan, amount, status)
            VALUES (?, ?, ?, ?, ?, ?, 'success')
            ON CONFLICT(reference) DO UPDATE SET status = 'success'
        `);
        stmt.run(reference, customer.email, metadata.phone_number, metadata.network, metadata.data_plan, amountInGHS);
        stmt.finalize();
        console.log(`WEBHOOK: Order ${reference} for ${metadata.phone_number} fulfilled.`);
    }
    res.sendStatus(200);
});
// Add this with your other API routes in server.js

app.get('/api/get-all-orders', (req, res) => {
    const { secret } = req.query;

    // Basic security check
    if (secret !== process.env.ADMIN_SECRET) {
        return res.status(403).json({ error: "Unauthorized" });
    }

    const sql = "SELECT * FROM orders ORDER BY created_at DESC"; // Get newest orders first

    db.all(sql, [], (err, rows) => {
        if (err) {
            console.error("Error fetching orders:", err.message);
            return res.status(500).json({ error: "Failed to fetch orders" });
        }
        res.json({ orders: rows });
    });
});
// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});


