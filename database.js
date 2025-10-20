const mongoose = require('mongoose');

// --- 1. CONNECTION ---
async function connectDB() {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Connected to MongoDB successfully.');
    } catch (err) {
        console.error('MongoDB connection error:', err);
        process.exit(1); 
    }
}

connectDB();

// --- 2. SCHEMAS AND MODELS ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    walletBalance: { type: Number, default: 0 }, 
    createdAt: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    reference: { type: String, required: true },
    phoneNumber: { type: String },
    network: { type: String },
    dataPlan: { type: String },
    amount: { type: Number },
    status: { type: String, default: 'pending' },
    paymentMethod: { type: String, default: 'paystack' }, 
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Order = mongoose.model('Order', orderSchema);

// Export models AND the connection object
module.exports = { User, Order, mongoose }; 
