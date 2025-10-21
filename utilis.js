const axios = require('axios');
const { User, Order } = require('./database.js'); 

const NETWORK_KEY_MAP = {
    "MTN": 'YELLO',
    "AirtelTigo": 'AT_PREMIUM', 
    "Telecel": 'TELECEL',
};
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

// --- HELPER: FIND BASE COST PRICE ---
function findBaseCost(network, capacityId) {
    const networkPlans = allPlans[network];
    if (!networkPlans) return 0;
    const plan = networkPlans.find(p => p.id === capacityId);
    return plan ? plan.price : 0; 
}

// --- HELPER: EXECUTE DATA PURCHASE (For Wallet/Paystack) ---
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

    // NOTE: Sending email alert logic is omitted here but would be triggered if needed

    return { status: finalStatus, reference: reference };
}


// --- HELPER: CALCULATE PAYSTACK FEE ---
function calculatePaystackFee(chargedAmountInPesewas) {
    const TRANSACTION_FEE_RATE = 0.019;
    const TRANSACTION_FEE_CAP = 2000;
    let amountToCalculateFeeOn = chargedAmountInPesewas;
    let fullFee = (amountToCalculateFeeOn * TRANSACTION_FEE_RATE) + 80;
    let totalFeeChargedByPaystack = Math.min(fullFee, TRANSACTION_FEE_CAP);
    return totalFeeChargedByPaystack;
}


// --- EXPORTS ---
module.exports = {
    allPlans,
    NETWORK_KEY_MAP,
    executeDataPurchase,
    findBaseCost,
    calculatePaystackFee
};
