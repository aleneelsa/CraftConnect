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

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Change this to a strong secret key
socketio = SocketIO(app, cors_allowed_origins="*")  # Enable WebSockets
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
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )
    ''')



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
        user_type = request.form["user_type"]
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
                cursor.execute("INSERT INTO users (name, email, password, user_type, profile_pic) VALUES (?, ?, ?, ?, ?)",
                               (name, email, hashed_password, user_type, profile_pic_filename))
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

# Browse Products
@app.route('/browse_products')
def browse_products():
    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    conn.close()
    
    return render_template("browse_products.html", products=products)

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
    cursor.execute("SELECT * FROM cart WHERE user_id=? AND product_id=?", (user_id, product_id))
    item = cursor.fetchone()

    if item:
        cursor.execute("UPDATE cart SET quantity = quantity + 1 WHERE user_id=? AND product_id=?", (user_id, product_id))
    else:
        cursor.execute("INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, 1)", (user_id, product_id))

    conn.commit()
    conn.close()

    flash("Product added to cart!", "success")
    return redirect(url_for("browse_products"))

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
    
    return render_template("manufacturer_dashboard.html", user_name=session["user_name"], profile_pic=session["profile_pic"])

@app.route('/add_product', methods=["GET", "POST"])
def add_product():
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))
    
    if request.method == "POST":
        # Log form data
        print("Form data received:", request.form)

        if 'product_name' not in request.form or 'description' not in request.form:
            return jsonify({"error": "Missing 'product_name' or 'description' in form data"}), 400

        name = request.form["product_name"]
        description = request.form["description"]
        price = float(request.form["price"])
        image = request.files["image"]

        if image:
            image_filename = image.filename
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], image_filename)
            image.save(image_path)
        else:
            image_filename = "default_product.jpg"

        try:
            with sqlite3.connect("craftconnect.db", timeout=10) as conn:
                cursor = conn.cursor()
                # Log SQL query
                print("Executing SQL query: INSERT INTO products (name, description, price, image, manufacturer_id) VALUES (?, ?, ?, ?, ?)")
                print("With values:", (name, description, price, image_filename, session["user_id"]))
                cursor.execute("INSERT INTO products (name, description, price, image, manufacturer_id) VALUES (?, ?, ?, ?, ?)", 
                               (name, description, price, image_filename, session["user_id"]))
                conn.commit()
                print("Product added to database:", name, description, price, image_filename, session["user_id"])
        except sqlite3.OperationalError as e:
            print("Database error:", str(e))
            return jsonify({"error": str(e)}), 500
        except Exception as e:
            print("Error:", str(e))
            return jsonify({"error": str(e)}), 500

        flash("Product added successfully!", "success")
        return redirect(url_for("manufacturer_dashboard"))

    return render_template("add_product.html")

@app.route('/manage_products')
def manage_products():
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    manufacturer_id = session["user_id"]

    conn = sqlite3.connect("craftconnect.db")
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
            cursor = conn.cursor()
            cursor.execute('''
                SELECT orders.id, customers.name AS customer_name, products.name AS product_name, orders.quantity, orders.status
                FROM orders
                JOIN customers ON orders.customer_id = customers.id
                JOIN products ON orders.product_id = products.id
                WHERE products.manufacturer_id = ?
            ''', (session["user_id"],))
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
            cursor.execute('''
                SELECT orders.id, customers.name AS customer_name, products.name AS product_name, orders.quantity, orders.status, orders.details
                FROM orders
                JOIN customers ON orders.customer_id = customers.id
                JOIN products ON orders.product_id = products.id
                WHERE orders.id = ? AND products.manufacturer_id = ?
            ''', (order_id, session["user_id"]))
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

    try:
        with sqlite3.connect("craftconnect.db", timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT orders.id, products.name AS product_name, orders.quantity, orders.total_price, orders.payment_status, orders.address, orders.phone, orders.email, orders.status
                FROM orders
                JOIN products ON orders.product_id = products.id
                WHERE orders.user_id = ?
            ''', (user_id,))
            orders = cursor.fetchall()
    except sqlite3.OperationalError as e:
        print("Database error:", str(e))
        flash("Failed to load orders due to database error.", "danger")
        orders = []

    return render_template("track_order.html", orders=orders)
@app.route('/check_messages/<int:order_id>')
def check_messages(order_id):
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    try:
        with sqlite3.connect("craftconnect.db", timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT messages.id, messages.content, messages.timestamp, customers.name AS customer_name
                FROM messages
                JOIN customers ON messages.customer_id = customers.id
                WHERE messages.order_id = ?
            ''', (order_id,))
            messages = cursor.fetchall()
    except sqlite3.OperationalError as e:
        print("Database error:", str(e))
        flash("Failed to load messages due to database error.", "danger")
        messages = []

    return render_template("check_messages.html", messages=messages)

@app.route('/update_order_status/<int:order_id>', methods=["POST"])
def update_order_status(order_id):
    if "user_id" not in session or session["user_type"] != "manufacturer":
        return redirect(url_for("login"))

    status = request.form["status"]

    try:
        with sqlite3.connect("craftconnect.db", timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE orders
                SET status = ?
                WHERE id = ? AND product_id IN (SELECT id FROM products WHERE manufacturer_id = ?)
            ''', (status, order_id, session["user_id"]))
            conn.commit()
            flash("Order status updated successfully!", "success")
    except sqlite3.OperationalError as e:
        print("Database error:", str(e))
        flash("Failed to update order status due to database error.", "danger")

    return redirect(url_for("manage_orders"))


@app.route('/customer_dashboard')
def customer_dashboard():
    if "user_id" not in session or session["user_type"] != "customer":
        return redirect(url_for("login"))

    return render_template("customer_dashboard.html", user_name=session["user_name"], profile_pic=session["profile_pic"])

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
    cursor.execute("""
        SELECT products.id, products.name, products.price, cart.quantity 
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
        total_price = price * quantity
        grand_total += total_price

        cursor.execute("""
            INSERT INTO orders (user_id, product_id, quantity, total_price, payment_status, address, phone, email) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, product_id, quantity, total_price, payment_status, address, phone, email))

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

@app.route('/cancel_order/<int:order_id>', methods=["POST"])
def cancel_order(order_id):
    if "user_id" not in session:
        flash("You must be logged in to cancel an order.", "danger")
        return redirect(url_for("login"))

    user_id = session["user_id"]

    # ✅ Connect to database
    conn = sqlite3.connect("craftconnect.db")
    cursor = conn.cursor()

    # ✅ Fetch order details
    cursor.execute("""
        SELECT status, payment_status, refund_status, products.name, users.email, products.manufacturer_id
        FROM orders
        JOIN products ON orders.product_id = products.id
        JOIN users ON orders.user_id = users.id
        WHERE orders.id=? AND orders.user_id=?
    """, (order_id, user_id))
    order = cursor.fetchone()

    if order and order[0] == "Processing":
        payment_status = order[1]
        refund_status = order[2]
        product_name = order[3]
        customer_email = order[4]
        manufacturer_id = order[5]

        cursor.execute("SELECT email FROM users WHERE id=?", (manufacturer_id,))
        manufacturer_email = cursor.fetchone()[0]

        if payment_status == "Paid":
            if refund_status == "Refunded":
                flash("This order has already been refunded.", "warning")
            else:
                cursor.execute("UPDATE orders SET refund_status='Refunded' WHERE id=?", (order_id,))
                flash("Your order has been canceled, and a refund has been issued.", "success")

                msg = Message("Refund Processed - CraftConnect", recipients=[customer_email])
                msg.body = f"Your order for '{product_name}' has been canceled, and a refund has been issued."
                mail.send(msg)
        else:
            cursor.execute("DELETE FROM orders WHERE id=? AND user_id=?", (order_id, user_id))
            flash("Your order has been canceled successfully.", "success")

        conn.commit()
        conn.close()

        msg = Message("Order Canceled - CraftConnect", recipients=[manufacturer_email])
        msg.body = f"A customer has canceled an order for '{product_name}'."
        mail.send(msg)
    else:
        flash("You cannot cancel this order.", "danger")

    return redirect(url_for("orders"))

@socketio.on("connect")
def handle_connect():
    print("A user connected.")

@socketio.on("disconnect")
def handle_disconnect():
    print("A user disconnected.")

@socketio.on("join_chat")
def join_chat(data):
    user_id = session.get("user_id")
    if not user_id:
        return

    chat_id = data["chat_id"]  # Unique chat ID (customer-manufacturer)
    join_room(chat_id)
    if chat_id not in active_chats:
        active_chats[chat_id] = []
    
    emit("chat_history", {"messages": active_chats[chat_id]}, room=chat_id)

@socketio.on("send_message")
def send_message(data):
    user_id = session.get("user_id")
    if not user_id:
        return

    chat_id = data["chat_id"]
    message = {
        "user": session["user_name"],
        "text": data["text"]
    }
    active_chats[chat_id].append(message)

    emit("receive_message", message, room=chat_id)
@app.route("/chat/<int:manufacturer_id>")
def chat(manufacturer_id):
    if "user_id" not in session:
        flash("You must be logged in to access chat.", "danger")
        return redirect(url_for("login"))

    customer_id = session["user_id"]

    # Create a unique chat room for the customer-manufacturer pair
    chat_room = f"chat_{customer_id}_{manufacturer_id}"

    return render_template("chat.html", chat_room=chat_room)


@socketio.on("join_chat")
def handle_join_chat(data):
    """Handles a user joining a chat room."""
    user_id = session.get("user_id")
    if not user_id:
        return  # Ignore if user is not logged in

    chat_room = data.get("chat_room")
    join_room(chat_room)
    emit("system_message", {"message": "User has joined the chat."}, room=chat_room)


@socketio.on("send_image")
def handle_send_image(data):
    """Handles image uploads in chat."""
    user_id = session.get("user_id")
    if not user_id:
        return

    chat_room = data.get("chat_room")
    image_data = data.get("image_data")

    if chat_room and image_data:
        # Decode the image
        image_bytes = base64.b64decode(image_data.split(",")[1])

        # Save image to static/uploads/chat_images
        image_filename = f"chat_{user_id}_{chat_room}.png"
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], "chat_images", image_filename)

        with open(image_path, "wb") as f:
            f.write(image_bytes)

        # Emit image URL to chat
        image_url = url_for("static", filename=f"uploads/chat_images/{image_filename}")
        emit("receive_image", {"user": session["user_name"], "image_url": image_url}, room=chat_room)

@socketio.on("leave_chat")
def handle_leave_chat(data):
    """Handles a user leaving a chat room."""
    chat_room = data.get("chat_room")
    leave_room(chat_room)
    emit("system_message", {"message": "User has left the chat."}, room=chat_room)

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


# Run Flask App
if __name__ == "__main__":
    app.run(debug=True)

