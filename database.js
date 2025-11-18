const mongoose = require('mongoose');

// Define User Schema (Existing)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    walletBalance: { type: Number, default: 0 },
    role: { type: String, enum: ['Client', 'Agent', 'Agent_Pending'], default: 'Client' },
    // 🛑 Agent's Payout Wallet (Profit Commission) 🛑
    payoutWalletBalance: { type: Number, default: 0 }, 
    resetToken: String,
    resetTokenExpires: Date,
    // Link to AgentShop
    shopId: { type: String, unique: true, sparse: true } 
}, { timestamps: true });

// Define Order Schema (Existing)
const orderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    reference: { type: String, required: true, unique: true },
    phoneNumber: String,
    network: String,
    dataPlan: String,
    amount: Number, // Amount charged to customer (in GHS)
    status: { type: String, default: 'payment_success' },
    paymentMethod: String,
    // 🛑 Store Profit Margin for Payout Tracking 🛑
    profitMargin: { type: Number, default: 0 } 
}, { timestamps: true });

// 🛑 NEW MODEL: AgentShop Schema 🛑
const agentShopSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    shopId: { type: String, required: true, unique: true },
    shopName: { type: String, default: 'My Data Shop' },
    // Custom price settings (Markup in pesewas)
    customMarkups: {
        MTN: { type: Number, default: 0 },
        AirtelTigo: { type: Number, default: 0 },
        Telecel: { type: Number, default: 0 }
    }
}, { timestamps: true });

// Database Connection Logic (The warning from before is removed here)
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connection successful.'))
    .catch(err => console.error('MongoDB connection error:', err));

const User = mongoose.model('User', userSchema);
const Order = mongoose.model('Order', orderSchema);
const AgentShop = mongoose.model('AgentShop', agentShopSchema); // Export new model

module.exports = { User, Order, AgentShop, mongoose };
