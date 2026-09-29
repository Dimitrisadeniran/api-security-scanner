# config.py
import os

# ── Paystack ──────────────────────────────────
# Get your keys at https://dashboard.paystack.com/#/settings/developer
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "sk_test_your_key_here")
PAYSTACK_BASE_URL   = "https://api.paystack.co"

# Prices in kobo (Nigerian currency smallest unit — 100 kobo = ₦1)
# Starter = ₦49 equivalent, Pro = ₦149, Enterprise = ₦300
# config.py
TIER_PRICES = {
    "professional": 45000000,  # Paystack uses kobo (450,000 NGN)
    "business": 150000000,      # 1,500,000 NGN
    "enterprise": 350000000,    # 3,500,000 NGN
}
