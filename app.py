from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'boxoffice_super_secret_key' # In production, use an environment variable

# Database Connection Helper
def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',         # Change to your MySQL username
        password='root', # Change to your MySQL password
        database='boxoffice',
        cursorclass=pymysql.cursors.DictCursor
    )

# --- SECURITY & RBAC MIDDLEWARE ---
# Decorator to restrict routes to logged-in users
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Decorator to restrict routes by specific role tiers
def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                flash('Access denied: Unauthorized role tier.', 'danger')
                return redirect('/')
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- AUTHENTICATION ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        # Hardcoding rule for demo deployment control: can set specific emails to Admins
        role = request.form.get('role', 'User') 

        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return redirect('/register')

        hashed_password = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)"
                cursor.execute(sql, (username, email, hashed_password, role))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect('/login')
        except pymysql.err.IntegrityError:
            flash('Username or Email already exists.', 'danger')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            # Establish session states
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f"Welcome back, {user['username']}!", 'success')
            return redirect('/')
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/login')


# --- USER HOMEPAGE (BROWSE MOVIES & SHOWS) ---
@app.route('/')
def index():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        # Retrieve all active movie schedules joining tables for rich metadata
        query = """
            SELECT s.schedule_id, m.title, m.genre, m.duration_minutes, t.name AS theater_name, s.show_time, s.ticket_price 
            FROM schedules s
            JOIN movies m ON s.movie_id = m.movie_id
            JOIN theaters t ON s.theater_id = t.theater_id
            WHERE s.show_time >= NOW()
            ORDER BY s.show_time ASC
        """
        cursor.execute(query)
        schedules = cursor.fetchall()
    conn.close()
    return render_template('index.html', schedules=schedules)

# --- ADMIN DASHBOARD ---
@app.route('/admin')
@login_required
@roles_required('Admin', 'Tech Admin')
def admin_dashboard():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM movies ORDER BY movie_id DESC")
        movies = cursor.fetchall()
        cursor.execute("SELECT * FROM theaters")
        theaters = cursor.fetchall()
    conn.close()
    return render_template('admin.html', movies=movies, theaters=theaters)

# --- CREATE MOVIE ENDPOINT ---
@app.route('/admin/add-movie', methods=['POST'])
@login_required
@roles_required('Admin', 'Tech Admin')
def add_movie():
    title = request.form['title'].strip()
    genre = request.form['genre'].strip()
    duration = request.form['duration_minutes']
    rating = request.form['rating']
    release_date = request.form['release_date']

    if not title or not duration:
        flash('Movie title and duration are required.', 'danger')
        return redirect('/admin')

    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO movies (title, genre, duration_minutes, rating, release_date) VALUES (%s, %s, %s, %s, %s)",
            (title, genre, duration, rating, release_date if release_date else None)
        )
    conn.commit()
    conn.close()
    flash(f"Successfully added movie: {title}", 'success')
    return redirect('/admin')

# --- CREATE SCHEDULE ENDPOINT ---
@app.route('/admin/add-schedule', methods=['POST'])
@login_required
@roles_required('Admin', 'Tech Admin')
def add_schedule():
    movie_id = request.form['movie_id']
    theater_id = request.form['theater_id']
    show_time = request.form['show_time']
    ticket_price = request.form['ticket_price']

    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO schedules (movie_id, theater_id, show_time, ticket_price) VALUES (%s, %s, %s, %s)",
            (movie_id, theater_id, show_time, ticket_price)
        )
    conn.commit()
    conn.close()
    flash("New showtime schedule published successfully.", 'success')
    return redirect('/admin')

@app.route('/book/<int:schedule_id>', methods=['GET', 'POST'])
@login_required
def book_ticket(schedule_id):
    conn = get_db_connection()
    
    # Fetch showtime metadata and calculate remaining seats
    with conn.cursor() as cursor:
        query = """
            SELECT s.*, m.title, t.name AS theater_name, t.total_seats,
                   COALESCE(SUM(b.seats_booked), 0) AS seats_taken
            FROM schedules s
            JOIN movies m ON s.movie_id = m.movie_id
            JOIN theaters t ON s.theater_id = t.theater_id
            LEFT JOIN bookings b ON s.schedule_id = b.schedule_id
            WHERE s.schedule_id = %s
            GROUP BY s.schedule_id
        """
        cursor.execute(query, (schedule_id,))
        show = cursor.fetchone()
    
    if not show:
        conn.close()
        flash('Showtime not found.', 'danger')
        return redirect('/')
        
    available_seats = show['total_seats'] - show['seats_taken']

    if request.method == 'POST':
        seats_requested = int(request.form['seats_booked'])
        
        if seats_requested <= 0:
            flash('Please enter a valid number of seats.', 'danger')
        elif seats_requested > available_seats:
            flash(f'Not enough seats available. Only {available_seats} remaining.', 'danger')
        else:
            # Calculate pricing transactionally
            total_amount = seats_requested * show['ticket_price']
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO bookings (user_id, schedule_id, seats_booked, total_amount) VALUES (%s, %s, %s, %s)",
                    (session['user_id'], schedule_id, seats_requested, total_amount)
                )
            conn.commit()
            conn.close()
            flash(f'Success! Booked {seats_requested} ticket(s) for {show["title"]}. Total: ₹{total_amount}', 'success')
            return redirect('/')
            
    conn.close()
    return render_template('book.html', show=show, available_seats=available_seats)

if __name__ == '__main__':
    app.run(debug=True)