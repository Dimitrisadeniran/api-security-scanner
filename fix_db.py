import sqlite3

def patch_database():
    try:
        # Use your actual db filename here
        conn = sqlite3.connect("shepherd.db") 
        cursor = conn.cursor()

        print("Checking for missing columns...")
        
        # Add slack_webhook
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN slack_webhook TEXT;")
            print("✅ Added slack_webhook")
        except sqlite3.OperationalError:
            print("ℹ️ slack_webhook already exists.")

        # Add slack_alerts
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN slack_alerts INTEGER DEFAULT 0;")
            print("✅ Added slack_alerts")
        except sqlite3.OperationalError:
            print("ℹ️ slack_alerts already exists.")

        conn.commit()
        print("Done! Your database is now compatible with Shepherd AI v0.6.")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    patch_database()