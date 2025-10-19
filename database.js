const mongoose = require('mongoose');

// --- 1. CONNECTION ---
async function connectDB() {
    try {
        // Mongoose automatically handles connection pooling and retry logic
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Connected to MongoDB successfully.');
    } catch (err) {
        console.error('MongoDB connection error:', err);
        // Important: Exit the process if we cannot connect to the database
        process.exit(1); 
    }
}

connectDB();

// --- 2. SCHEMAS AND MODELS ---

// User Schema (Collection)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

// Order Schema (Collection)
const orderSchema = new mongoose.Schema({
    // Store the ID of the user who made the order, linking to the 'User' model
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    reference: { type: String, required: true },
    phoneNumber: { type: String },
    network: { type: String },
    dataPlan: { type: String },
    amount: { type: Number },
    status: { type: String, default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

// Create Mongoose Models
const User = mongoose.model('User', userSchema);
const Order = mongoose.model('Order', orderSchema);

module.exports = { User, Order };