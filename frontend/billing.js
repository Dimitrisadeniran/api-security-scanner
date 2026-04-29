// billing.js (DAY 14 Connection Update for Key-First Auth)

const BASE_URL = "http://localhost:8000"; // Your backend URL

// Function to fetch the current user's usage and tier display
async function loadUserSettings() {
    // 1. Get the authenticated API Key from local storage.
    // We expect the user to have pasted this into index.html
    // and your other JS (results.js) to have saved it.
    const apiKey = localStorage.getItem("shepherd_api_key");

    // DAY 14 ADJ: We are NO LONGER checking for 'userId' on the frontend.
    if (!apiKey) {
        console.warn("User not authorized. No API Key found in localStorage.");
        // Non-authed users can stay on this page but CTAs will fail.
        return;
    }

    // Populate API key input
    const apiKeyInput = document.getElementById("api-key-input");
    if (apiKeyInput) {
        apiKeyInput.value = apiKey;
    }

    try {
        // 2. Fetch current usage and tier
        // authorized by HEADER, the B2B way.
        const response = await fetch(`${BASE_URL}/usage`, {
            method: "GET",
            headers: { "X-API-Key": apiKey } // Use our auth dependency
        });
        
        const usageData = await response.json();
        
        // 3. Update the Tailwind UI based on backend data
        if (response.status === 200) {
            document.getElementById("current-tier-display").innerText = usageData.tier.toUpperCase();
            document.getElementById("scans-used").innerText = usageData.scans_used;
            document.getElementById("scans-limit").innerText = usageData.scans_limit;
            
            // Subtle UI hint: If they are Pro, highlight the Pro card border
            if (usageData.tier === 'pro') {
                const proCard = document.querySelector('.tier-card.pro');
                if (proCard) proCard.classList.add('featured-card', 'border-emerald-500', 'border-2');
            }
        } else {
            console.error("Failed to load usage data:", usageData);
        }

    } catch (error) {
        console.error("Network error loading user settings:", error);
        document.getElementById("current-tier-display").innerText = "ERROR";
        document.getElementById("current-tier-display").style.color = "red";
    }
}

// Function to call the backend to get a Paystack Checkout Link
async function handleUpgrade(requestedTier) {
    const apiKey = localStorage.getItem("shepherd_api_key");
    const statusMessage = document.getElementById("status-message");

    // Show a loading message in the standard UI alert spot
    statusMessage.innerText = `Preparing your ${requestedTier.toUpperCase()} subscription... Please wait.`;
    statusMessage.classList.remove('hidden');
    statusMessage.style.color = "cyan";

    try {
        // DAY 14 ADJ: We are authorized by Header (apiKey).
        // We are NO LONGER passing the 'userId' in the body.
        // The backend will automatically find the userId from the key.
        const response = await fetch(`${BASE_URL}/billing/upgrade`, {
            method: "POST",
            headers: {
                "X-API-Key": apiKey, // Auth Dependency
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                new_tier: requestedTier // ONLY 'pro' or 'enterprise'
            })
        });

        const responseData = await response.json();

        // 4. IF SUCCESSFUL: Redirect the user to the unique Paystack URL
        if (response.status === 200 && responseData.checkout_url) {
            statusMessage.innerText = "Connecting to Secure Paystack Checkout...";
            statusMessage.style.color = "white";
            
            // THIS LINE LAUNCHES THE PAYMENT WINDOW
            window.location.href = responseData.checkout_url;
            
        } else {
            // Handle expected failures (already Pro, invalid tier, etc.)
            statusMessage.innerText = `Upgrade Failed: ${responseData.detail || "Payment gateway error"}`;
            statusMessage.style.color = "red";
        }
    } catch (error) {
        console.error("❌ Critical Network error during payment:", error);
        statusMessage.innerText = "Internal Server Error. Please contact sales@shepherdai.co.";
        statusMessage.style.color = "red";
    }
}

// Function to check if the user just returned from a successful payment
// Our FastAPI backend appended 'billing=success' to the callback_url.
function checkPaymentStatus() {
    const urlParams = new URLSearchParams(window.location.search);
    const statusMessage = document.getElementById("status-message");

    if (urlParams.has('billing') && urlParams.get('billing') === 'success') {
        statusMessage.innerText = "✅ Upgrade successful! Thank you for subscribing to Shepherd AI.";
        statusMessage.classList.remove('hidden');
        statusMessage.style.color = "green";
        statusMessage.style.fontWeight = "bold";
        
        // Refresh the tier display to show the new subscription
        loadUserSettings();
    }
}


// --- Execute everything on Page Load ---
window.onload = function() {
    checkPaymentStatus();
    loadUserSettings();
};