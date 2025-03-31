import sqlite3

def check_orders():
    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders")
    orders = cursor.fetchall()
    for order in orders:
        print(order)
    conn.close()

check_orders()