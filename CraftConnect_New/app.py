from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mail import Mail, Message

import os
import sqlite3
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
import json
import base64


# Store active chat rooms

app = Flask(__name__, static_folder='static')
app.secret_key = "your_secret_key_here"  # Change this to a strong secret key
socketio = SocketIO(app) # Enable WebSockets
active_chats = {}

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your-email-password'  # Replace with an app password
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

mail = Mail(app)


# Upload folder for profile pictures & product images
UPLOAD_FOLDER = "static/uploads"
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
db_path = os.path.abspath("craftconnect.db")  # Change to your actual database file
print("Using database file at:", db_path)
def init_db():
    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            user_type TEXT NOT NULL,
            profile_pic TEXT DEFAULT 'default_profile.jpg'
        )
    """)
    try:
      cursor.execute("ALTER TABLE users ADD COLUMN email TEXT;")
    except sqlite3.OperationalError:
      print("Column 'email' already exists, skipping...")
    try:
      cursor.execute("ALTER TABLE users ADD COLUMN username TEXT;")
      cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT;")
      cursor.execute("ALTER TABLE users ADD COLUMN whatsapp TEXT;")
      cursor.execute("ALTER TABLE users ADD COLUMN address TEXT;")
      cursor.execute("ALTER TABLE users ADD COLUMN description TEXT;")
    except sqlite3.OperationalError:
      print("Columns already exist, skipping...")
    try:
      conn = sqlite3.connect("craftconnect.db")
      cursor = conn.cursor()
      cursor.execute("ALTER TABLE users ADD COLUMN user_type TEXT;")
      conn.commit()
      conn.close()
    except sqlite3.OperationalError:
      print("Column 'user_type' already exists, skipping...")
    try:
      conn = sqlite3.connect("craftconnect.db")
      cursor = conn.cursor()
      cursor.execute("ALTER TABLE users ADD COLUMN whatsapp TEXT;")
      cursor.execute("ALTER TABLE users ADD COLUMN address TEXT;")
      conn.commit()
      conn.close()
    except sqlite3.OperationalError:
       print("Columns 'whatsapp' and 'address' already exist, skipping...")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER,
    manufacturer_id INTEGER,
    message TEXT,
    is_image INTEGER DEFAULT 0,  -- 0 for text, 1 for image
    image_url TEXT,              -- URL for the uploaded image
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        ) 
    ''')

    # Products table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL,
            image TEXT NOT NULL,
            manufacturer_id INTEGER,
            FOREIGN KEY (manufacturer_id) REFERENCES users (id)
        )
    """)
    try:
      cursor.execute("ALTER TABLE products ADD COLUMN category TEXT;")
    except sqlite3.OperationalError:
      print("Column 'category' already exists, skipping...")
    try:
        cursor.execute("ALTER TABLE products ADD COLUMN stock_limit INTEGER DEFAULT NULL;")
        print("✅ 'stock_limit' column added successfully!")
    except sqlite3.OperationalError:
        print("⚠️ 'stock_limit' column already exists, skipping...")
     # Add the size_chart column if it doesn't exist
    try:
        cursor.execute("ALTER TABLE products ADD COLUMN size_chart TEXT;")
        print("✅ 'size_chart' column added successfully!")
    except sqlite3.OperationalError:
        print("⚠️ 'size_chart' column already exists, skipping...")

    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        manufacturer_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,  -- 0 = Unread, 1 = Read
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (manufacturer_id) REFERENCES users(id)
        )
    """)

    # Cart table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    """)

    # Orders table (to store customer orders)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            total_price REAL NOT NULL,
            status TEXT DEFAULT 'Processing',
            payment_status TEXT NOT NULL DEFAULT 'COD',  -- "COD" or "Paid"
            refund_status TEXT DEFAULT 'Not Refunded',  -- "Refunded" or "Not Refunded"
            order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    """)


    # Create the product_reviews table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS product_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            rating INTEGER NOT NULL,
            feedback TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
   

    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
DB_PATH = "craftconnect.db"

# Function to connect to the database
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Function to initialize the database

# Initialize the database
def initialize_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Ensure admin table exists
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)
    cursor.execute("""DELETE FROM admin WHERE username = 'admin@gmail.com';
    """)
    # Check if the admin user exists
    cursor.execute("SELECT * FROM admin WHERE username = ?", ("admin@gmail.com",))
    existing_admin = cursor.fetchone()

    # If admin doesn't exist, insert it with a hashed password
    if not existing_admin:
        hashed_password = generate_password_hash("admin123")  # Hashing only once
        cursor.execute("INSERT INTO admin (username, password) VALUES (?, ?)", 
                       ("admin@gmail.com", hashed_password))
        conn.commit()
        print("✅ Admin user created successfully!")
    else:
        print("✅ Admin user already exists.")

    conn.close()

# Initialize the database
initialize_db()
# Admin Login Route
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('username')  
        password = request.form.get('password')

        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admin WHERE username = ?', (email,)).fetchone()
        conn.close()

        if admin:
            stored_password = admin['password']  # Ensure it's a string
            print(f"DEBUG: Stored Password Hash = {stored_password[:10]}... (Truncated)")  # Safer logging
            print(f"DEBUG: Checking password for {email}")

            if check_password_hash(stored_password, password):  
                session['admin_logged_in'] = True
                print("✅ Login successful!")
                return redirect('/admin/dashboard')
            else:
                print("⚠️ DEBUG: Password mismatch!")
                flash('Invalid credentials', 'danger')
        else:
            print("⚠️ DEBUG: No such user found!")
            flash('Invalid credentials', 'danger')

    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return render_template('/login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session:
        return redirect('/admin')
    conn = get_db_connection()
    users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    orders = conn.execute('SELECT COUNT(*) FROM orders').fetchone()[0]
    products = conn.execute('SELECT COUNT(*) FROM products').fetchone()[0]
    conn.close()
    return render_template('admin_dashboard.html', users=users, orders=orders, products=products)


@app.route('/admin/users')
def admin_users():
    if 'admin_logged_in' not in session:
        return redirect('/admin')
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    cursor = conn.cursor()

    try:
        cursor.execute("ALTER TABLE products ADD COLUMN approved INTEGER DEFAULT 0;")
        conn.commit()
        print("✅ 'approved' column added successfully!")
    except sqlite3.OperationalError:
        print("⚠️ Column 'approved' already exists. No changes made.")


    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/delete/<int:user_id>')
def delete_user(user_id):
    if 'admin_logged_in' not in session:
        return redirect('/admin')
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('User deleted successfully', 'success')
    return redirect('/admin/users')

@app.route('/admin/products')
def admin_products():
    if 'admin_logged_in' not in session:
        return redirect('/admin')
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products WHERE approved = 0').fetchall()
    conn.close()
    return render_template('admin_products.html', products=products)

@app.route('/admin/product/approve/<int:product_id>')
def approve_product(product_id):
    if 'admin_logged_in' not in session:
        return redirect('/admin')

    conn = get_db_connection()
    conn.execute('UPDATE products SET approved = 1 WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()

    flash('✅ Product approved successfully!', 'success')
    return redirect('/admin/products')

@app.route('/admin/product/reject/<int:product_id>')
def reject_product(product_id):
    if 'admin_logged_in' not in session:
        return redirect('/admin')

    conn = get_db_connection()
    conn.execute('UPDATE products SET approved = -1 WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()

    flash('❌ Product rejected!', 'danger')
    return redirect('/admin/products')


@app.route('/admin/orders')
def admin_orders():
    if 'admin_logged_in' not in session:
        return redirect('/admin')

    conn = get_db_connection()
    
    orders = conn.execute('''
        SELECT orders.id, orders.user_id, orders.quantity, orders.total_price, orders.status,
               products.name AS product_name, products.image
        FROM orders
        JOIN products ON orders.product_id = products.id
    ''').fetchall()
    
    conn.close()

    # Debugging: Print retrieved image paths
    for order in orders:
        print(f"Order ID {order['id']} - Image Path: {order['image']}")

    return render_template('admin_orders.html', orders=orders)

@app.route('/admin/enquiries')
def admin_enquiries():
    conn = sqlite3.connect('craftconnect.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, email, content, timestamp FROM contact_messages ORDER BY timestamp DESC')
    enquiries = cursor.fetchall()
    conn.close()
    return render_template('admin_enquiries.html', enquiries=enquiries)

# Create a table to store admin replies
def create_reply_table():
    conn = sqlite3.connect('craftconnect.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS enquiry_replies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enquiry_id INTEGER NOT NULL,
            reply TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (enquiry_id) REFERENCES contact_messages(id)
        )
    ''')
    conn.commit()
    conn.close()

# Call this function when starting the app
create_reply_table()

@app.route('/reply_enquiry/<int:enquiry_id>', methods=['POST'])
def reply_enquiry(enquiry_id):
    reply_message = request.form['reply_message']

    conn = sqlite3.connect('craftconnect.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO enquiry_replies (enquiry_id, reply) 
        VALUES (?, ?)
    ''', (enquiry_id, reply_message))
    conn.commit()
    conn.close()

    flash('Reply sent successfully!', 'success')
    return redirect(url_for('admin_enquiries'))

@app.route('/send_reply', methods=['POST'])
def send_reply():
    message_id = request.form['message_id']
    reply_content = request.form['reply_content']

    conn = sqlite3.connect('craftconnect.db')
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE contact_messages
        SET reply = ?, status = 'unread'
        WHERE id = ?
    ''', (reply_content, message_id))

    conn.commit()
    conn.close()

    flash('Reply sent successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


    def update_orders_table():
        conn = sqlite3.connect("craftconnect.db")
        cursor = conn.cursor()

        # Step 1: Add manufacturer_id column if not already present
        try:
            cursor.execute("ALTER TABLE orders ADD COLUMN manufacturer_id INTEGER;")
        except sqlite3.OperationalError:
            print("Column manufacturer_id already exists, skipping...")

        # Step 2: Update existing rows with manufacturer_id from products table
        cursor.execute("""
            UPDATE orders 
            SET manufacturer_id = (
                SELECT manufacturer_id FROM products WHERE products.id = orders.product_id
            )
        """)

        conn.commit()
        conn.close()

    update_orders_table()
    conn.commit()
    conn.close()

init_db()


# Home Page


from werkzeug.security import generate_password_hash
@app.route('/signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        phone = request.form['phone']
        whatsapp = request.form.get('whatsapp')  # Optional
        address = request.form['address']
        user_type = request.form['user_type']
        profile_pic = request.files["profile_pic"]

        if profile_pic:
            profile_pic_filename = profile_pic.filename
            profile_pic_path = os.path.join(app.config["UPLOAD_FOLDER"], profile_pic_filename)
            profile_pic.save(profile_pic_path)
        else:
            profile_pic_filename = "default_profile.jpg"

        hashed_password = generate_password_hash(password)

        try:
            with sqlite3.connect("craftconnect.db", timeout=10) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (name, email, password, user_type, profile_pic,phone,whatsapp,address) VALUES (?, ?, ?, ?, ?,?,?,?)",
                               (name, email, hashed_password, user_type, profile_pic_filename,phone,whatsapp,address))
                conn.commit()
                print("User added to database:", name, email, user_type, profile_pic_filename)
                flash("Signup successful!", "success")
                return redirect(url_for("login"))
        except sqlite3.IntegrityError as e:
            print("Database error:", str(e))
            flash(f"Signup failed: Email already exists.", "danger")
        except Exception as e:
            print("Error:", str(e))
            flash(f"Signup failed: {str(e)}", "danger")

    return render_template("signup.html")
from werkzeug.security import check_password_hash


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        print(f"Attempting login with email: {email}")

        try:
            with sqlite3.connect("craftconnect.db", timeout=10) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE email=?", (email,))
                user = cursor.fetchone()
                
                if user:
                    print(f"User found: {user}")
                else:
                    print("No user found with that email")

                if user and check_password_hash(user[3], password):
                    session["user_id"] = user[0]
                    session["user_name"] = user[1]
                    session["user_type"] = user[4]
                    session["profile_pic"] = user[5]
                    flash("Login successful!", "success")
                    print("Login successful!")

                    if user[4] == "manufacturer":
                        return redirect(url_for("manufacturer_dashboard"))
                    else:
                        return redirect(url_for("customer_dashboard"))
                else:
                    flash("Invalid email or password", "danger")
                    print("Invalid email or password")
        
        except sqlite3.OperationalError as e:
            print("Database error:", str(e))
            return jsonify({"error": str(e)}), 500
        except Exception as e:
            print("Error:", str(e))
            return jsonify({"error": str(e)}), 500

    return render_template("login.html")

@app.route('/submit_rating/<int:product_id>', methods=['POST'])
def submit_rating(product_id):
    if "user_id" not in session:
        flash("You must be logged in to rate and review products.", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    rating = int(request.form.get("rating"))
    feedback = request.form.get("feedback")

    try:
        with sqlite3.connect("craftconnect.db") as conn:
            cursor = conn.cursor()
            # Insert the rating and feedback into the database
            cursor.execute("""
                INSERT INTO product_reviews (product_id, user_id, rating, feedback, timestamp)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (product_id, user_id, rating, feedback))
            conn.commit()

        flash("Thank you for your feedback!", "success")
    except sqlite3.OperationalError as e:
        print("Database error:", str(e))
        flash("Failed to submit your feedback. Please try again later.", "danger")

    return redirect(url_for("product_details", product_id=product_id))
@app.route('/product_details/<int:product_id>')
def product_details(product_id):
    conn = sqlite3.connect("craftconnect.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Fetch product details, including manufacturer details
    cursor.execute("""
        SELECT p.id, p.name, p.description, p.price, p.image, p.category, p.stock_limit, p.size_chart,
               m.id AS manufacturer_id, m.name AS manufacturer_name, m.phone, m.whatsapp, m.address, 
               m.description AS manufacturer_description
        FROM products p
        JOIN users m ON p.manufacturer_id = m.id
        WHERE p.id = ?
    """, (product_id,))
    product = cursor.fetchone()

    if not product:
        conn.close()
        flash("Product not found.", "danger")
        return redirect(url_for("browse_products"))

    # Fetch similar products
    cursor.execute("""
        SELECT id, name, price, image 
        FROM products 
        WHERE category = ? AND id != ?
        LIMIT 4
    """, (product["category"], product_id))
    similar_products = cursor.fetchall()

    # Fetch reviews
    cursor.execute("""
        SELECT r.rating, r.feedback, r.timestamp, u.name AS user_name
        FROM product_reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.product_id = ?
        ORDER BY r.timestamp DESC
    """, (product_id,))
    reviews = cursor.fetchall()

    conn.close()

    return render_template("product_details.html", product=product, similar_products=similar_products, reviews=reviews)
@app.route('/order_page/<int:product_id>', methods=['POST', 'GET'])
def order_page(product_id):
    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()

    # Fetch product details
    cursor.execute("""
        SELECT id, name, description, price, image, stock_limit
        FROM products
        WHERE id = ?
    """, (product_id,))
    product = cursor.fetchone()

    conn.close()

    if not product:
        flash("Product not found.", "error")
        return redirect(url_for('customer_dashboard'))

    # Render the order page with product details
    return render_template("order_page.html", product=product)

@app.route('/confirm_order/<int:product_id>', methods=['POST'])
def confirm_order(product_id):
    quantity = int(request.form.get('quantity'))

    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()

    # Fetch product details
    cursor.execute("SELECT price, stock_limit FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found.", "error")
        return redirect(url_for('customer_dashboard'))

    price, stock_limit = product

    # Check stock availability
    if stock_limit is not None and quantity > stock_limit:
        flash("Insufficient stock available.", "error")
        return redirect(url_for('order_page', product_id=product_id))

    # Calculate total price
    total_price = price * quantity

    # Insert order into the database
    cursor.execute("""
        INSERT INTO orders (user_id, product_id, quantity, total_price, status)
        VALUES (?, ?, ?, ?, ?)
    """, (session['user_id'], product_id, quantity, total_price, 'Processing'))
    conn.commit()

    # Update stock limit
    if stock_limit is not None:
        cursor.execute("UPDATE products SET stock_limit = stock_limit - ? WHERE id = ?", (quantity, product_id))
        conn.commit()

    conn.close()

    flash("Order placed successfully!", "success")
    return redirect(url_for('customer_dashboard'))

# Browse Products
@app.route('/browse_products')
def browse_products():
    conn = sqlite3.connect("craftconnect.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Fetch products
    cursor.execute("""
        SELECT products.id, products.name, products.description, products.price, products.image, 
               users.name AS manufacturer_name, users.id AS manufacturer_id
        FROM products
        JOIN users ON products.manufacturer_id = users.id
    """)
    products = cursor.fetchall()

    # Fetch cart count for the logged-in user
    cart_count = 0
    if "user_id" in session:
        cursor.execute("SELECT SUM(quantity) FROM cart WHERE user_id = ?", (session["user_id"],))
        cart_count = cursor.fetchone()[0] or 0  # Default to 0 if no items in cart

    conn.close()
    return render_template("browse_products.html", products=products, cart_count=cart_count)
# Add to Cart
@app.route('/add_to_cart/<int:product_id>', methods=["POST"])
def add_to_cart(product_id):
    if "user_id" not in session:
        flash("You must be logged in to add items to the cart.", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]

    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()

    # Check if the product is already in the cart
    cursor.execute("SELECT * FROM cart WHERE user_id = ? AND product_id = ?", (user_id, product_id))
    item = cursor.fetchone()

    if item:
        # Update the quantity if the product is already in the cart
        cursor.execute("UPDATE cart SET quantity = quantity + 1 WHERE user_id = ? AND product_id = ?", (user_id, product_id))
    else:
        # Add the product to the cart
        cursor.execute("INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, 1)", (user_id, product_id))

    conn.commit()
    conn.close()

    flash("Product added to cart!", "success")
    return redirect(url_for("browse_products"))

@app.route('/manufacturer_profile')
def manufacturer_profile():
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    user_id = session["user_id"]

    # Fetch manufacturer details from the database
    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT username, phone, whatsapp, address, description 
        FROM users 
        WHERE id = ?
    """, (user_id,))
    result = cursor.fetchone()
    conn.close()
    print("Fetched Manufacturer Details:", result)
    if not result:
        flash("Manufacturer details not found.", "error")
        return redirect(url_for("manufacturer_dashboard"))

    # Map the data to variables
    manufacturer = {
        "username": result[0],
        "phone": result[1],
        "whatsapp": result[2],
        "address": result[3],
        "description": result[4]
    }

    return render_template("manufacturer_profile.html", manufacturer=manufacturer)
# View Cart
@app.route('/cart')
def cart():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT products.id, products.name, products.price, cart.quantity, products.image
        FROM cart 
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id=?
    """, (user_id,))
    cart_items = cursor.fetchall()
    conn.close()

    return render_template("cart.html", cart_items=cart_items)

# Remove from Cart
@app.route('/remove_from_cart/<int:product_id>', methods=["POST"])
def remove_from_cart(product_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cart WHERE user_id=? AND product_id=?", (user_id, product_id))
    conn.commit()
    conn.close()

    flash("Item removed from cart.", "info")
    return redirect(url_for("cart"))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route('/manufacturer_dashboard')
def manufacturer_dashboard():
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))
     
    # Pass the user_id (manufacturer ID) and other session details to the template
    return render_template("manufacturer_dashboard.html", 
                           user_name=session["user_name"], 
                           profile_pic=session["profile_pic"], 
                           manufacturer_id=session["user_id"])


@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if request.method == 'POST':
        product_name = request.form['product_name']
        description = request.form['description']
        category = request.form['category']
        price = float(request.form['price'])
        image = request.files['image']
        stock_limit = request.form.get('stock_limit')  # Optional field
        size_chart = request.files.get('size_chart')  # Optional size chart

        # Save the product image
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        image.save(image_path)

        # Save the size chart if provided
        # Save the size chart if provided
        size_chart_path = None
        if size_chart and size_chart.filename != "":
           size_chart_path = os.path.join(app.config['UPLOAD_FOLDER'], size_chart.filename)
           size_chart.save(size_chart_path)
        # Insert the product into the database
        conn = sqlite3.connect("craftconnect.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO products (name, description, price, image, category, manufacturer_id, stock_limit, size_chart)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (product_name, description, price, image.filename, category, session['user_id'], stock_limit, size_chart.filename if size_chart else None))
        conn.commit()
        conn.close()

        flash("Product added successfully!", "success")
        return redirect(url_for('manufacturer_dashboard'))
    
    return render_template('add_product.html')

@app.route('/manage_products')
def manage_products():
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    manufacturer_id = session["user_id"]

    conn = sqlite3.connect("craftconnect.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE manufacturer_id=?", (manufacturer_id,))
    products = cursor.fetchall()
    conn.close()

    return render_template("manage_products.html", products=products)

@app.route('/delete_product/<int:product_id>', methods=["POST"])
def delete_product(product_id):
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE id=? AND manufacturer_id=?", (product_id, session["user_id"]))
    conn.commit()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect(url_for("manage_products"))



@app.route('/manage_orders')
def manage_orders():
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    try:
        with sqlite3.connect("craftconnect.db", timeout=10) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    orders.id, 
                    users.name AS customer_name, 
                    products.name AS product_name, 
                    orders.quantity, 
                    orders.total_price, 
                    orders.status 
                FROM orders
                JOIN products ON orders.product_id = products.id
                JOIN users ON orders.user_id = users.id
                WHERE products.manufacturer_id = ?
            """, (session["user_id"],))

            orders = cursor.fetchall()
    except sqlite3.OperationalError as e:
        print("Database error:", str(e))
        flash("Failed to load orders due to database error.", "danger")
        orders = []

    return render_template("manage_orders.html", orders=orders)

@app.route('/view_order/<int:order_id>')
def view_order(order_id):
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    try:
        with sqlite3.connect("craftconnect.db", timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT orders.id, users.username, products.name, orders.quantity, orders.total_price, orders.status
                FROM orders
                JOIN products ON orders.product_id = products.id
                JOIN users ON orders.user_id = users.id  -- Ensure you use "users" table, not "customers"
                WHERE orders.manufacturer_id = ?
            """, (manufacturer_id,))
            order = cursor.fetchone()
    except sqlite3.OperationalError as e:
        print("Database error:", str(e))
        flash("Failed to load order details due to database error.", "danger")
        order = None

    return render_template("view_order.html", order=order)

@app.route('/track_order')
def track_order():
    if "user_id" not in session:
        flash("You must be logged in to track your orders.", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    orders = []

    try:
        with sqlite3.connect("craftconnect.db", timeout=10) as conn:
            conn.row_factory = sqlite3.Row  # Fetch rows as dictionaries
            cursor = conn.cursor()
            cursor.execute('''
                SELECT orders.id, products.name AS product_name, orders.quantity, 
                       orders.total_price, orders.payment_status, orders.address, 
                       orders.phone, orders.email, orders.status
                FROM orders
                JOIN products ON orders.product_id = products.id
                WHERE orders.user_id = ?
            ''', (user_id,))
            orders = cursor.fetchall()
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")  # Print error in console for debugging
        flash(f"Failed to load orders: {e}", "danger")

    return render_template("track_order.html", orders=orders)


@app.route('/update_order_status/<int:order_id>', methods=["POST"])
def update_order_status(order_id):
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    new_status = request.form["status"]

    try:
        with sqlite3.connect("craftconnect.db", timeout=10) as conn:
            cursor = conn.cursor()

            # Fetch the current status of the order
            cursor.execute("SELECT status FROM orders WHERE id = ?", (order_id,))
            current_status = cursor.fetchone()

            if not current_status:
                flash("Order not found.", "danger")
                return redirect(url_for("manage_orders"))

            current_status = current_status[0]

            # Prevent invalid status updates
            if current_status == "Cancelled" and new_status in ["Shipped", "Delivered"]:
                flash("Cannot update status to 'Shipped' or 'Delivered' for a cancelled order.", "danger")
                return redirect(url_for("manage_orders"))

            if current_status in ["Shipped", "Delivered"] and new_status == "Cancelled":
                flash("Cannot cancel an order that has already been shipped or delivered.", "danger")
                return redirect(url_for("manage_orders"))

            # Update the order status
            cursor.execute("""
                UPDATE orders
                SET status = ?
                WHERE id = ? AND product_id IN (SELECT id FROM products WHERE manufacturer_id = ?)
            """, (new_status, order_id, session["user_id"]))
            conn.commit()

        flash("Order status updated successfully!", "success")
        return redirect(url_for("manage_orders"))

    except sqlite3.OperationalError as e:
        print("Database error:", str(e))
        flash("Failed to update order status.", "danger")
        return redirect(url_for("manage_orders"))
@app.route('/customer_dashboard')
def customer_dashboard():
    if "user_id" not in session or session["user_type"] != "customer":
        return redirect(url_for("login"))

    user_email = session.get("user_email")
    unread_replies = 0

    if user_email:
        conn = sqlite3.connect('craftconnect.db')
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM contact_messages WHERE email = ? AND status = 'unread'", (user_email,))
        unread_replies = cursor.fetchone()[0]
        conn.close()

    return render_template("customer_dashboard.html", 
                           user_name=session["user_name"], 
                           profile_pic=session["profile_pic"], 
                           unread_replies=unread_replies)

@app.route('/checkout', methods=["GET", "POST"])
def checkout():
    if "user_id" not in session:
        flash("You must be logged in to checkout.", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]

    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT products.id, products.name, products.price, cart.quantity 
        FROM cart 
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id=?
    """, (user_id,))
    cart_items = cursor.fetchall()
    conn.close()

    grand_total = sum(item[2] * item[3] for item in cart_items)

    return render_template("checkout.html", cart_items=cart_items, grand_total=grand_total)

@app.route('/place_order', methods=["POST"])
def place_order():
    if "user_id" not in session:
        flash("You must be logged in to place an order.", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    address = request.form.get("address")
    phone = request.form.get("phone")
    email = request.form.get("email")
    payment_status = request.form.get("payment_status")

    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()

    # Fetch products from the cart along with manufacturer_id
    cursor.execute("""
        SELECT products.id, products.name, products.price, cart.quantity, products.manufacturer_id 
        FROM cart 
        JOIN products ON cart.product_id = products.id
        WHERE cart.user_id=?
    """, (user_id,))
    cart_items = cursor.fetchall()

    if not cart_items:
        flash("Your cart is empty!", "warning")
        return redirect(url_for("cart"))

    grand_total = 0
    for item in cart_items:
        product_id = item[0]
        product_name = item[1]
        price = item[2]
        quantity = item[3]
        manufacturer_id = item[4]  # Fetching manufacturer_id from products table
        total_price = price * quantity
        grand_total += total_price

        # Insert into orders table
        cursor.execute("""
            INSERT INTO orders (user_id, product_id, quantity, total_price, payment_status, address, phone, email, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, product_id, quantity, total_price, payment_status, address, phone, email, "Processing"))

        # Insert a notification for the manufacturer
        cursor.execute("""
            INSERT INTO notifications (manufacturer_id, message, is_read) 
            VALUES (?, ?, 0)
        """, (manufacturer_id, f"New order received for {product_name}",))

    # Clear the cart after placing the order
    cursor.execute("DELETE FROM cart WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()

    flash("Order placed successfully! A confirmation email has been sent.", "success")
    return redirect(url_for("customer_dashboard"))

@app.route('/orders')
def orders():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT orders.id, products.name, orders.quantity, orders.total_price, orders.status, orders.order_date 
        FROM orders 
        JOIN products ON orders.product_id = products.id
        WHERE orders.user_id=?
        ORDER BY orders.order_date DESC
    """, (user_id,))
    orders = cursor.fetchall()
    conn.close()

    return render_template("orders.html", orders=orders)

@app.route('/test')
def test():
    flash("This is a success message!", "success")
    flash("This is an error message!", "error")
    return redirect(url_for("home"))

@app.route('/products/<category>', methods=['GET', 'POST'])
def products_by_category(category):
    search_query = request.args.get('search', '').strip()  # Get the search query from the URL parameters
    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()

    if search_query:  # If a search query is provided
        cursor.execute("""
            SELECT * FROM products 
            WHERE category = ? AND (name LIKE ? OR description LIKE ?)
        """, (category, f'%{search_query}%', f'%{search_query}%'))
    else:  # If no search query, display all products in the category
        cursor.execute("SELECT * FROM products WHERE category = ?", (category,))
    
    products = cursor.fetchall()
    conn.close()

    return render_template('products.html', products=products, category=category, search_query=search_query)

@app.route('/')
def home():
    return render_template('index.html')  # Your homepage

@app.route('/about')
def about():
    return render_template('about.html')  # About Us page

@app.route('/faqs')
def faqs():
    return render_template('faqs.html')  # FAQs page

@app.route('/contact')
def contact():
    return render_template('contact.html')  # Contact Us page

@app.route('/terms')
def terms():
    return render_template('terms.html')  # Ensure this file exists in your templates folder

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

# Function to insert contact message into the database
# Function to insert contact message into the database
def insert_message(name, email, content):
    conn = sqlite3.connect('craftconnect.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO contact_messages (name, email, content) 
        VALUES (?, ?, ?)
    ''', (name, email, content))
    conn.commit()
    conn.close()


@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if "user_id" not in session or session["user_type"] != "manufacturer":
        flash("You must be logged in as a manufacturer to edit products.", "danger")
        return redirect(url_for("login"))

    with sqlite3.connect("craftconnect.db") as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE id=?", (product_id,))
        product = cursor.fetchone()

    if not product:
        flash("Product not found.", "danger")
        return redirect(url_for("manage_products"))

    if request.method == "POST":
        # Retrieve form data using the correct keys
        name = request.form.get("product_name")  # Match the `name` attribute in the form
        description = request.form.get("description")
        category = request.form.get("category")
        price = request.form.get("price")
        stock_limit = request.form.get("stock_limit")

        # Validate required fields
        if not name or not description or not category or not price:
            flash("All required fields must be filled out.", "danger")
            return render_template("edit_product.html", product=product)

        # Handle image upload
        if "image" in request.files:
            image = request.files["image"]
            if image.filename != "":  # Only update if a new image is provided
                image_path = f"static/uploads/{image.filename}"
                image.save(image_path)
            else:
                image_path = product["image"]  # Keep old image if no new file uploaded
        else:
            image_path = product["image"]  # Keep old image if no file uploaded

        # Update the product in the database
        with sqlite3.connect("craftconnect.db") as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE products
                SET name=?, description=?, category=?, price=?, stock_limit=?, image=?
                WHERE id=?
                """,
                (name, description, category, price, stock_limit, image_path, product_id),
            )
            conn.commit()

        flash("Product updated successfully.", "success")
        return redirect(url_for("manage_products"))

    return render_template("edit_product.html", product=product)

@app.route('/submit_contact_form', methods=['POST'])
def submit_contact_form():
    name = request.form['name']
    email = request.form['email']
    content = request.form['message']

    insert_message(name, email, content)  # Store the message in the database

    flash('Your message has been sent successfully!', 'success')
    return redirect(url_for('contact'))  # Redirect back to the contact page



@app.route("/cancel_order/<int:order_id>")
def cancel_order(order_id):
    return render_template("cancel.html", order_id=order_id)

@app.route('/confirm_cancel_order/<int:order_id>', methods=['POST'])
def confirm_cancel_order(order_id):
    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()

    # Check if the order exists
    cursor.execute("SELECT status FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()

    if order:
        # Update status to "Cancelled"
        cursor.execute("UPDATE orders SET status = 'Cancelled' WHERE id = ?", (order_id,))
        conn.commit()

    conn.close()
    flash("Order cancelled successfully!", "info")
    return redirect(url_for('track_order'))  # Return nothing, just update status

@app.route('/manufacturer_orders')
def manufacturer_orders():
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    manufacturer_id = session["user_id"]  # Get the logged-in manufacturer ID

    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()

    # Fetch orders where this manufacturer is involved
    cursor.execute("""
        SELECT orders.id, users.username, products.name, orders.quantity, orders.total_price, orders.status
        FROM orders
        JOIN products ON orders.product_id = products.id
        JOIN users ON orders.user_id = users.id
        WHERE orders.manufacturer_id = ?
    """, (manufacturer_id,))

    orders = cursor.fetchall()
    conn.close()

    return render_template("manufacturer_orders.html", orders=orders)


@app.route('/manufacturer_notifications')
def manufacturer_notifications():
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    manufacturer_id = session["user_id"]

    try:
        with sqlite3.connect("craftconnect.db", timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, message, created_at FROM notifications 
                WHERE manufacturer_id = ? AND is_read = 0
            """, (manufacturer_id,))
            notifications = cursor.fetchall()

        return render_template("manufacturer_notifications.html", notifications=notifications)

    except sqlite3.OperationalError as e:
        print("Database error:", str(e))
        flash("Error fetching notifications.", "danger")
        return redirect(url_for("manufacturer_dashboard"))

@app.route('/update_cart_quantity/<int:product_id>', methods=['POST'])
def update_cart_quantity(product_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    try:
        # Convert the quantity from the form to an integer
        new_quantity = int(request.form.get("quantity"))
    except ValueError:
        flash("Invalid quantity value.", "danger")
        return redirect(url_for("cart"))

    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()

    # Fetch the stock limit and product name for the product
    cursor.execute("SELECT stock_limit, name FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if product:
        stock_limit, product_name = product  # Get the stock limit and product name

        # Check if the stock limit is not NULL and the quantity exceeds the limit
        if stock_limit is not None and new_quantity > stock_limit:
            flash(f"Error: Quantity for '{product_name}' exceeds available stock (Max: {stock_limit}).", "danger")
            conn.close()
            return redirect(url_for("cart"))

        # Update the cart with the new quantity
        if new_quantity > 0:
            cursor.execute("""
                UPDATE cart
                SET quantity = ?
                WHERE user_id = ? AND product_id = ?
            """, (new_quantity, user_id, product_id))
        else:
            # If quantity is 0, remove the product from the cart
            cursor.execute("DELETE FROM cart WHERE user_id = ? AND product_id = ?", (user_id, product_id))

        conn.commit()

    conn.close()
    flash("Cart updated successfully!", "success")
    return redirect(url_for("cart"))
# Function to get database connection
def get_db_connection():
    conn = sqlite3.connect("craftconnect.db")
    conn.row_factory = sqlite3.Row
    return conn

# Route for manufacturer to view customer messages (unchanged)
@app.route('/view_messages/<int:manufacturer_id>')
def view_messages(manufacturer_id):
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all customers who have sent messages to this manufacturer
    cursor.execute("""
        SELECT DISTINCT customers.id, customers.name
        FROM chat_messages
        JOIN users AS customers ON chat_messages.customer_id = customers.id
        WHERE chat_messages.manufacturer_id = ?
    """, (manufacturer_id,))

    customers = cursor.fetchall()
    conn.close()

    # Pass both customers and manufacturer_id to the template
    return render_template("view_messages.html", customers=customers, manufacturer_id=manufacturer_id)

@app.route('/contact_manufacturer/<int:product_id>/<int:manufacturer_id>/<int:customer_id>', methods=["GET"])
def contact_manufacturer(product_id, manufacturer_id, customer_id):
    try:
        # Connect to the SQLite database
        with sqlite3.connect("craftconnect.db", timeout=10) as conn:
            cursor = conn.cursor()

            # Fetch the manufacturer and customer names
            cursor.execute("SELECT name FROM users WHERE id=?", (manufacturer_id,))
            manufacturer_name = cursor.fetchone()

            cursor.execute("SELECT name FROM users WHERE id=?", (customer_id,))
            customer_name = cursor.fetchone()

            # Fetch the chat history between this manufacturer and customer
            cursor.execute("""
                SELECT customer_id, manufacturer_id, message, timestamp
                FROM chat_messages
                WHERE manufacturer_id=? AND customer_id=?
                ORDER BY timestamp ASC
            """, (manufacturer_id, customer_id))
            chat_messages = cursor.fetchall()

            # Render the chat interface with manufacturer name and chat history
            return render_template(
                "chat_interface.html", 
                manufacturer_name=manufacturer_name[0] if manufacturer_name else "Manufacturer",
                customer_name=customer_name[0] if customer_name else "Customer",
                manufacturer_id=manufacturer_id,
                customer_id=customer_id,
                chat_messages=[
                    {
                        'sender': 'customer' if msg[0] == customer_id else 'manufacturer',  # Determine the sender based on customer_id
                        'message': msg[2],
                        'timestamp': msg[3]
                    } for msg in chat_messages
                ]
            )

    except sqlite3.OperationalError as e:
        print("Database error:", str(e))
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500


# New Route to view chat with a selected customer
@app.route('/view_customer_chat/<int:manufacturer_id>/<int:customer_id>')
def view_customer_chat(manufacturer_id, customer_id):
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    # Fetch chat history between the manufacturer and the specific customer
    conn = get_db_connection()
    cursor = conn.cursor()

    # Modify the query to ignore rows where both customer_id and manufacturer_id are NULL
    cursor.execute("""
        SELECT customer_id, manufacturer_id, message, timestamp
        FROM chat_messages
        WHERE customer_id = ? AND manufacturer_id = ? AND (customer_id IS NOT NULL OR manufacturer_id IS NOT NULL)
        ORDER BY timestamp ASC
    """, (customer_id, manufacturer_id))

    chat_messages = cursor.fetchall()
    conn.close()

    # Convert the fetched messages to include a 'sender' field
    formatted_messages = []
    for message in chat_messages:
        if message['customer_id'] == customer_id:
            sender = 'customer'
        else:
            sender = 'manufacturer'
        formatted_messages.append({
            'sender': sender,
            'message': message['message'],
            'timestamp': message['timestamp']
        })

    # Render the chat interface with chat messages, and pass customer_id and manufacturer_id
    return render_template("chat_interface.html", 
                           chat_messages=formatted_messages, 
                           customer_id=customer_id, 
                           manufacturer_id=manufacturer_id)


from datetime import datetime


UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER  

# ✅ Socket.IO: Join Room
@socketio.on('join_room')
def handle_join_room(room_id):
    join_room(room_id)
    print(f"[INFO] User joined room: {room_id}")

# ✅ Socket.IO: Handle Text Messages
@socketio.on('send_message')
def handle_send_message(data):

    
    sender_id = session.get("user_id")
    sender = session.get("user_type")  # Get sender dynamically
    message = data.get('message')
    manufacturer_id = data.get('manufacturer_id')
    customer_id = data.get('customer_id')
    is_image = data.get('is_image', False)

    print(f"🔍 [DEBUG] Sender ID: {sender_id}, Sender Type: {sender}") # Check what session has

    # Ensure sender is valid
    if sender not in ["customer", "manufacturer"]:
        print("[ERROR] Invalid sender:", sender)
        return

    # Determine receiver dynamically
    receiver_type = "manufacturer" if sender == "customer" else "customer"
    
    print(f"✅ Sender: {sender}, Receiver: {receiver_type}")  # Debug print

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO chat_messages (customer_id, manufacturer_id, message, is_image, image_url, sender_type, timestamp, reciever_type) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (customer_id, manufacturer_id, message, is_image, None, sender, timestamp, receiver_type))

        conn.commit()
        conn.close()

        print("[SUCCESS] Message inserted successfully!")

        room_id = f"{manufacturer_id}_{customer_id}"
        emit('receive_message', {
            'message': message,
            'sender': sender,
            'is_image': False,
            'image_url': None
        }, room=room_id, include_self=False)

    except Exception as e:
        print(f"[ERROR] Failed to insert message: {e}")



# ✅ Image Upload Route
@app.route('/upload_image', methods=['POST'])
def upload_image():
    try:
        image = request.files.get('image')
        message_data = json.loads(request.form.get('message_data', '{}'))  

        customer_id = message_data.get('customer_id')
        manufacturer_id = message_data.get('manufacturer_id')
        sender = session.get("user_type")  # Get sender dynamically

        if sender not in ["customer", "manufacturer"]:
            return jsonify({"error": "Invalid sender"}), 400  

        receiver_type = "manufacturer" if sender == "customer" else "customer"

        if not image:
            return jsonify({"error": "No image file provided"}), 400  

        image_filename = image.filename
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], image_filename)
        image.save(image_path)

        image_url = f"/static/uploads/{image_filename}"
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO chat_messages (customer_id, manufacturer_id, message, is_image, image_url, sender_type, timestamp, reciever_type) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (customer_id, manufacturer_id, None, 1, image_url, sender, timestamp, receiver_type))

        conn.commit()
        conn.close()

        room_id = f"{manufacturer_id}_{customer_id}"
        socketio.emit('receive_message', {
            "message": None,
            "image_url": image_url,
            "customer_id": customer_id,
            "manufacturer_id": manufacturer_id,
            "sender": sender,
            "is_image": True
        }, room=room_id)

        return jsonify({"image_url": image_url})

    except Exception as e:
        print(f"[ERROR] Failed to insert image message: {e}")
        return jsonify({"error": str(e)}), 500

# ✅ Fetch Chat Messages
@app.route("/get_messages", methods=["GET"])
def get_messages():
    customer_id = request.args.get("customer_id")
    manufacturer_id = request.args.get("manufacturer_id")
    current_user_type = session.get('user_type')  

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, message, is_image, image_url, sender_type AS sender_role, timestamp
        FROM chat_messages 
        WHERE (customer_id=? AND manufacturer_id=?)
        ORDER BY timestamp ASC
    ''', (customer_id, manufacturer_id))

    messages = []
    for msg in cursor.fetchall():
        messages.append({
            'id': msg[0],
            'message': msg[1],
            'is_image': msg[2],
            'image_url': msg[3],
            'sender_role': msg[4],
            'timestamp': msg[5],
            'is_sender': (msg[4] == current_user_type)
        })

    conn.close()
    return jsonify(messages)

if __name__ == '__main__':
    socketio.run(app, debug=True)

