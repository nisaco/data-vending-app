const mongoose = require('mongoose');

// --- SCHEMAS ---

// 1. User Schema 
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    walletBalance: { type: Number, default: 0, min: 0 },
    payoutWalletBalance: { type: Number, default: 0, min: 0 }, 
    role: { type: String, enum: ['Client', 'Agent', 'Admin'], default: 'Client' },
    shopId: { type: String, unique: true, sparse: true }, 
    createdAt: { type: Date, default: Date.now }
});

// 2. Order Schema 
const orderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    reference: { type: String, required: true, unique: true }, 
    phoneNumber: { type: String },
    network: { type: String, enum: ['MTN', 'AirtelTigo', 'Telecel', 'WALLET', 'Bank', null] },
    dataPlan: { type: String, required: true }, 
    amount: { type: Number, required: true },
    status: { type: String, enum: [
        'payment_success', 'payment_failed', 'data_sent', 'pending_review', 'data_failed', 
        'topup_successful', 'INITIATED', 'PROCESSING', 'SUCCESSFUL', 'FAILED', 'CANCELLED',
        'withdrawal_pending', 'withdrawal_sent'
    ], required: true },
    paymentMethod: { type: String, enum: ['paystack', 'wallet', 'payout'] },
    createdAt: { type: Date, default: Date.now }
});

// 3. AgentShop Schema 
const agentShopSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    shopId: { type: String, required: true, unique: true },
    shopName: { type: String, required: true },
    // **This is the correct structure for nested markups:**
    customMarkups: { 
        type: Map, 
        of: { type: Object, default: {} }, 
        default: {} 
    },
    createdAt: { type: Date, default: Date.now }
});

// --- MODELS ---
const User = mongoose.model('User', userSchema);
const Order = mongoose.model('Order', orderSchema);
const AgentShop = mongoose.model('AgentShop', agentShopSchema);


// --- MONGOOSE CONNECTION SETUP ---
const mongoUri = process.env.MONGO_URI;

mongoose.connect(mongoUri)
    .then(() => console.log('MongoDB connection successful.'))
    .catch(err => console.error('MongoDB connection error:', err));


module.exports = {
    User,
    Order,
    AgentShop,
    mongoose
};
