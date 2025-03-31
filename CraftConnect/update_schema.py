import sqlite3

def update_schema():
    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()

    # Add the necessary columns to the orders table
    try:
        cursor.execute("ALTER TABLE orders ADD COLUMN address TEXT")
        cursor.execute("ALTER TABLE orders ADD COLUMN phone TEXT")
        cursor.execute("ALTER TABLE orders ADD COLUMN email TEXT")
        print("Added address, phone, and email columns to orders table.")
    except sqlite3.OperationalError as e:
        print("Error updating schema:", str(e))

    conn.commit()
    conn.close()

update_schema()