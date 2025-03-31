import sqlite3

conn = sqlite3.connect("craftconnect.db")
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE products ADD COLUMN approved INTEGER DEFAULT 0;")
    conn.commit()
    print("✅ 'approved' column added successfully!")
except sqlite3.OperationalError:
    print("⚠️ Column 'approved' already exists. No changes made.")

# Update existing products to ensure they are all set to pending (0)
cursor.execute("UPDATE products SET approved = 0 WHERE approved IS NULL;")
conn.commit()

conn.close()
