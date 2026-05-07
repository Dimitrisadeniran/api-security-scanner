# config.py
import os

# ── Paystack ──────────────────────────────────
# Get your keys at https://dashboard.paystack.com/#/settings/developer
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "sk_test_your_key_here")
PAYSTACK_BASE_URL   = "https://api.paystack.co"

# Prices in kobo (Nigerian currency smallest unit — 100 kobo = ₦1)
# Starter = ₦49 equivalent, Pro = ₦149, Enterprise = ₦300
TIER_PRICES = {
    "starter":    360800 ,    # ₦360000/year (~$220 equivalent)
    "pro":        820000,   # ₦820000/year (~$500 equivalent)
    "enterprise": 2296000,   # ₦2296000/year (~$1400 equivalent)
}