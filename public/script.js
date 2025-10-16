// Replace your entire script.js file with this code

const PAYSTACK_PUBLIC_KEY = "pk_live_62dc43eeea153c81c216b75e3967f8a44ee94fc3"; // Replace with your key

const paymentForm = document.getElementById('paymentForm');
const statusDiv = document.getElementById('status');
const networkSelect = document.getElementById('network');
const dataplanSelect = document.getElementById('dataplan');

// --- Function to fetch and display plans for a given network ---
const fetchPlansForNetwork = (network) => {
    // Show a loading message
    dataplanSelect.innerHTML = '<option>Loading plans...</option>';

    // Fetch plans from the server for the selected network
    fetch(`/api/data-plans?network=${network}`)
        .then(response => response.json())
        .then(plans => {
            dataplanSelect.innerHTML = ''; // Clear the loading message

            if (plans.length === 0) {
                dataplanSelect.innerHTML = '<option>No plans available</option>';
                return;
            }

            // Create new options from the data we got from the server
            plans.forEach(plan => {
                const option = document.createElement('option');
                option.value = plan.id;
                option.dataset.amount = plan.price;
                option.textContent = `${plan.name} - GHS ${(plan.price / 100).toFixed(2)}`;
                dataplanSelect.appendChild(option);
            });
        })
        .catch(error => {
            console.error('Error fetching data plans:', error);
            // This is the message you were seeing
            dataplanSelect.innerHTML = '<option>Couldn\'t load plans</option>';
        });
};

// --- Event Listeners ---

// 1. Fetch plans when the page first loads
document.addEventListener('DOMContentLoaded', () => {
    const defaultNetwork = networkSelect.value;
    fetchPlansForNetwork(defaultNetwork);
});

// 2. Fetch new plans every time the network is changed
networkSelect.addEventListener('change', () => {
    const selectedNetwork = networkSelect.value;
    fetchPlansForNetwork(selectedNetwork);
});


// 3. Handle the form submission for payment (this part remains the same)
paymentForm.addEventListener("submit", function(e) {
    e.preventDefault();

    const selectedOption = dataplanSelect.options[dataplanSelect.selectedIndex];
    // Make sure an option is selected and has a data-amount
    if (!selectedOption || !selectedOption.dataset.amount) {
        statusDiv.textContent = "Please select a valid data plan.";
        statusDiv.style.color = "red";
        return;
    }
    
    const amountInKobo = selectedOption.dataset.amount;
    const phone = document.getElementById('phone').value;
    const email = document.getElementById('email').value;

    const handler = PaystackPop.setup({
        key: PAYSTACK_PUBLIC_KEY,
        email: email,
        amount: amountInKobo,
        currency: 'GHS',
        ref: '' + Math.floor((Math.random() * 1000000000) + 1),
        metadata: {
            phone_number: phone,
            network: networkSelect.value,
            data_plan: selectedOption.text
        },
        callback: function(response) {
            statusDiv.textContent = "Verifying payment, please wait...";
            statusDiv.style.color = "orange";

            fetch('/paystack/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reference: response.reference }),
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    statusDiv.textContent = 'Payment successful! Your data is on its way.';
                    statusDiv.style.color = 'green';
                    paymentForm.reset();
                } else {
                    statusDiv.textContent = `Verification failed: ${data.message}`;
                    statusDiv.style.color = 'red';
                }
            })
            .catch(err => {
                console.error('Verification error:', err);
                statusDiv.textContent = 'An error occurred during verification.';
                statusDiv.style.color = 'red';
            });
        },
        onClose: function() {
            statusDiv.textContent = "Transaction was cancelled.";
            statusDiv.style.color = "red";
        }
    });

    handler.openIframe();
});