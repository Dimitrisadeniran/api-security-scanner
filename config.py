# config.py
import os

# ── Paystack ──────────────────────────────────
# Get your keys at https://dashboard.paystack.com/#/settings/developer
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "sk_test_your_key_here")
PAYSTACK_BASE_URL   = "https://api.paystack.co"

# Prices in kobo (Nigerian currency smallest unit — 100 kobo = ₦1)
# Starter = ₦49 equivalent, Pro = ₦149, Enterprise = ₦300
TIER_PRICES = {
    "starter":    68000 ,    # ₦68000/month (~$49 equivalent)
    "pro":        205000,   # ₦205000/month (~$149 equivalent)
    "enterprise": 412000,   # ₦412,000/month (~$300 equivalent)
}