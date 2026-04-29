# config.py
import os

# 1. THE MOST IMPORTANT STEP: PASTE YOUR SECRET KEY HERE
# Never commit this file to GitHub or share this key.
PAYSTACK_SECRET_KEY = "sk_test_... (sk_test_cbfd95540b3dc9c4a67accd081a4f270ee24e43e)"

# Paystack API Base URL
PAYSTACK_BASE_URL = "https://api.paystack.co"

# Define the prices for your SaaS tiers.
# Prices are in KOBO (10,000 NGN = 1,000,000 kobo).
TIER_PRICES = {
    "free": 0,
    "Starter": 68000,
    "pro": 205000,         # NGN 10,000 / month
    "enterprise": 50000000  # NGN 50,000 / month (adjust as needed)
}