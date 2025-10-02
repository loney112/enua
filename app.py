from flask import (
	Flask,
	render_template,
	request,
	redirect,
	url_for,
	flash,
	session,
)
import sqlite3
import os
import random
import datetime
from datetime import timezone
from PIL import Image, ImageDraw, ImageFont
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from functools import wraps
from flask import session, redirect, url_for, flash

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# If your templates folder is named 'templates' rename the folder or set template_folder accordingly.
app = Flask(__name__, template_folder="template")
app.secret_key = os.environ.get("RAFFLE_SECRET", "dev-secret-change-me")

DB_PATH = os.path.join(os.path.dirname(__file__), "raffle.db")

# Admin credentials (default to the requested easy-access pair). You can override via env.
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'enuamaka@gmail.com')
ADMIN_PLAIN = os.environ.get('ADMIN_PW_PLAIN', 'enuguamaka12')

# Bank account details shown to users for offline transfer (use env vars in production)
BANK_NAME = os.environ.get("BANK_NAME", "zenith BANK")
BANK_ACCOUNT = os.environ.get("BANK_ACCOUNT", "1310538700")
BANK_ACCOUNT_NAME = os.environ.get("BANK_ACCOUNT_NAME", "ENUGU AMAKA ESTATE LTD")


def get_db_connection():
	conn = sqlite3.connect(DB_PATH)
	conn.row_factory = sqlite3.Row
	return conn


def valid_email(email: str) -> bool:
	import re
	if not email:
		return False
	# very simple regex
	return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


def valid_phone(phone: str) -> bool:
	import re
	if not phone:
		return False
	# allow digits, spaces, + and - and require at least 7 digits
	digits = re.sub(r"\D", "", phone)
	return len(digits) >= 7


def init_db():
	conn = get_db_connection()
	cur = conn.cursor()
	# Create tables if they do not exist (this handles new installs)
	cur.execute(
		"""
	CREATE TABLE IF NOT EXISTS tickets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT,
		registered_at TEXT,
		created_at TEXT,
		paid INTEGER DEFAULT 0,
		payment_id TEXT
	);
	"""
	)
	cur.execute(
		"""
	CREATE TABLE IF NOT EXISTS winners (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ticket_id INTEGER,
		drawn_at TEXT NOT NULL,
		FOREIGN KEY(ticket_id) REFERENCES tickets(id)
	);
	"""
	)

	# Users table for site accounts
	cur.execute(
		"""
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		phone TEXT,
		created_at TEXT
	);
	"""
	)

	# Migration: if the tickets table existed but is missing columns (e.g. paid), add them.
	cols = [r[1] for r in conn.execute("PRAGMA table_info(tickets)").fetchall()]
	if "paid" not in cols:
		# safe to add a column in SQLite; existing rows will get the DEFAULT value
		conn.execute("ALTER TABLE tickets ADD COLUMN paid INTEGER DEFAULT 0")
	if "payment_id" not in cols:
		conn.execute("ALTER TABLE tickets ADD COLUMN payment_id TEXT")
	if "ticket_image" not in cols:
		conn.execute("ALTER TABLE tickets ADD COLUMN ticket_image TEXT")
	if "phone" not in cols:
		conn.execute("ALTER TABLE tickets ADD COLUMN phone TEXT")
	if "payer_name" not in cols:
		conn.execute("ALTER TABLE tickets ADD COLUMN payer_name TEXT")
	if "bank_account" not in cols:
		conn.execute("ALTER TABLE tickets ADD COLUMN bank_account TEXT")
	if "bank_name" not in cols:
		conn.execute("ALTER TABLE tickets ADD COLUMN bank_name TEXT")
	if "registered_at" not in cols:
		conn.execute("ALTER TABLE tickets ADD COLUMN registered_at TEXT")
	if "created_at" not in cols:
		conn.execute("ALTER TABLE tickets ADD COLUMN created_at TEXT")

	conn.commit()
	conn.close()


def startup():
	init_db()
	# Print admin quick-login info on startup (convenience)
	print(f"ADMIN quick-login -> email: {ADMIN_EMAIL} password: {ADMIN_PLAIN}")


# Provide helpers to templates
@app.context_processor
def inject_now():
	"""Make a now() helper available inside templates: {{ now().year }}"""
	return {"now": lambda: datetime.datetime.now()}


def generate_ticket_image(ticket_id: int) -> bool:
	"""Generate a ticket image for ticket_id and update the DB ticket_image field.
	Returns True on success, False otherwise.
	"""
	try:
		conn = get_db_connection()
		t = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
		conn.close()
		if not t:
			return False
		# prefer the ticket-style images included in template/static
		candidates = [
			os.path.join(os.path.dirname(__file__), 'template', 'static', 'IMG-20250930-WA0034.jpg'),
			os.path.join(os.path.dirname(__file__), 'template', 'static', 'IMG-20250930-WA0035.jpg'),
			os.path.join(os.path.dirname(__file__), 'template', 'ticket_template.png'),
			os.path.join(os.path.dirname(__file__), 'static', 'ticket_template.png'),
		]
		TEMPLATE_PATH = next((p for p in candidates if os.path.exists(p)), None)
		if not TEMPLATE_PATH:
			return False
		img = Image.open(TEMPLATE_PATH).convert('RGBA')
		draw = ImageDraw.Draw(img)
		# choose a font (fallback to default)
		try:
			font_path = os.path.join(os.path.dirname(__file__), 'template', 'fonts', 'arial.ttf')
			base_font = ImageFont.truetype(font_path, size=24)
		except Exception:
			base_font = ImageFont.load_default()
		w, h = img.size
		entry_font_size = max(20, int(h * 0.12))
		info_font_size = max(14, int(h * 0.06))
		try:
			entry_font = ImageFont.truetype(font_path, size=entry_font_size)
			info_font = ImageFont.truetype(font_path, size=info_font_size)
		except Exception:
			entry_font = base_font
			info_font = base_font
		# Draw Entry No at top-right
		entry_text = f"ENTRY NO: {ticket_id}"
		margin = int(w * 0.02)
		etw, eth = draw.textsize(entry_text, font=entry_font)
		draw.text((w - etw - margin, margin), entry_text, font=entry_font, fill=(227,27,35,255))
		# Draw user fields (name, email, phone) on right side area
		user_x = int(w * 0.62)
		y = int(h * 0.28)
		line_h = int(info_font_size * 1.6)
		name_text = f"NAME: {t['name']}"
		email_text = f"EMAIL: {t['email'] or '—'}"
		phone_text = f"PHONE: {t.get('phone') or '—'}"
		draw.text((user_x, y), name_text, font=info_font, fill=(80,80,80,255))
		y += line_h
		draw.text((user_x, y), email_text, font=info_font, fill=(80,80,80,255))
		y += line_h
		draw.text((user_x, y), phone_text, font=info_font, fill=(80,80,80,255))
		out_dir = os.path.join(os.path.dirname(__file__), 'static', 'tickets')
		os.makedirs(out_dir, exist_ok=True)
		out_path = os.path.join(out_dir, f'ticket-{ticket_id}.png')
		img.save(out_path)
		conn2 = get_db_connection()
		conn2.execute('UPDATE tickets SET ticket_image = ? WHERE id = ?', (f'static/tickets/ticket-{ticket_id}.png', ticket_id))
		conn2.commit()
		conn2.close()
		return True
	except Exception as e:
		print('generate_ticket_image error:', e)
		return False

# Initialize DB now (Flask 3.x removed before_first_request decorator)
startup()


@app.route("/")
def index():
	# Pop the show_clock flag if set during registration so clock shows once
	show_clock = bool(session.pop("show_clock", False))
	conn = get_db_connection()
	# only count paid tickets as sold
	total = conn.execute("SELECT COUNT(*) as c FROM tickets WHERE paid = 1").fetchone()["c"]
	winner = conn.execute(
		"SELECT t.id, t.name, t.email, w.drawn_at FROM winners w JOIN tickets t ON w.ticket_id = t.id ORDER BY w.drawn_at DESC LIMIT 1"
	).fetchone()
	conn.close()
	# include server time (UTC) so clients can sync their clocks to server
	server_time = datetime.datetime.now(timezone.utc).isoformat()
	return render_template("index.html", total=total, winner=winner, show_clock=show_clock, server_time=server_time)


def login_required(fn):
	from functools import wraps

	@wraps(fn)
	def wrapper(*args, **kwargs):
		if not session.get('user_id'):
			flash('Please login or register to continue', 'error')
			return redirect(url_for('login', next=request.path))
		return fn(*args, **kwargs)

	return wrapper


@app.route('/login', methods=('GET','POST'))
def login():
	if request.method == 'POST':
		email = (request.form.get('email') or '').strip()
		password = (request.form.get('password') or '').strip()
		if not email or not password:
			flash('Email and password required', 'error')
			return redirect(url_for('login'))
		conn = get_db_connection()
		u = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
		conn.close()
		if u and check_password_hash(u['password_hash'], password):
			session['user_id'] = u['id']
			session['user_name'] = u['name']
			flash('Logged in', 'success')
			nxt = request.args.get('next') or url_for('index')
			return redirect(nxt)
		# admin quick-login: exact email+plain password (override via env)
		if email.lower() == ADMIN_EMAIL.lower() and password == ADMIN_PLAIN:
			session['is_admin'] = True
			flash('Logged in as admin', 'success')
			return redirect(url_for('admin_dashboard'))
		flash('Invalid credentials', 'error')
	return render_template('user_login.html')


@app.route('/register_user', methods=('GET','POST'))
def register_user():
	if request.method == 'POST':
		name = (request.form.get('name') or '').strip()
		email = (request.form.get('email') or '').strip()
		phone = (request.form.get('phone') or '').strip()
		password = (request.form.get('password') or '').strip()
		if not name or not email or not password:
			flash('Name, email and password required', 'error')
			return redirect(url_for('register_user'))
		pw_hash = generate_password_hash(password)
		conn = get_db_connection()
		try:
			conn.execute('INSERT INTO users (name,email,password_hash,phone,created_at) VALUES (?,?,?,?,?)', (name,email,pw_hash,phone,datetime.datetime.now(timezone.utc).isoformat()))
			conn.commit()
		except Exception as e:
			flash('Registration failed (email may already exist)', 'error')
			conn.close()
			return redirect(url_for('register_user'))
		conn.close()
		flash('Account created, please login', 'success')
		return redirect(url_for('login'))
	return render_template('user_register.html')


@app.route('/logout')
def logout():
	session.clear()
	flash('Logged out', 'info')
	return redirect(url_for('index'))


@app.route("/buy", methods=("GET", "POST"))
@login_required
def buy():
	if request.method == "POST":
		name = (request.form.get("name") or "").strip()
		email = (request.form.get("email") or "").strip()
		phone = (request.form.get("phone") or "").strip()
		if not name:
			flash("Name is required", "error")
			return redirect(url_for("buy"))
		conn = get_db_connection()
		now_iso = datetime.datetime.now(timezone.utc).isoformat()
		cur = conn.execute(
			"INSERT INTO tickets (name, email, phone, registered_at, created_at, paid) VALUES (?, ?, ?, ?, ?, 1)",
			(name, email, phone, now_iso, now_iso),
		)
		conn.commit()
		ticket_id = cur.lastrowid
		conn.close()
		flash(f"Ticket purchased! Your ticket number is {ticket_id}", "success")
		return redirect(url_for("ticket", id=ticket_id))
	return render_template("buy.html")


@app.route('/register', methods=('GET', 'POST'))
@login_required
def register():
	if request.method == 'POST':
		name = (request.form.get('name') or '').strip()
		email = (request.form.get('email') or '').strip()
		amount = float(request.form.get('amount') or 0)
		if not name:
			flash('Name is required', 'error')
			return redirect(url_for('register'))
		# enforce minimum payment amount
		MIN_AMOUNT = 200000.0
		if amount < MIN_AMOUNT:
			flash(f"Minimum entry amount is {int(MIN_AMOUNT):,} Naira", 'error')
			return redirect(url_for('register'))

		# Create a pending registration. Some DBs have created_at NOT NULL; set created_at = registered_at for now.
		phone = (request.form.get('phone') or '').strip()
		conn = get_db_connection()
		reg_time = datetime.datetime.now(timezone.utc).isoformat()
		cur = conn.execute(
			"INSERT INTO tickets (name, email, phone, registered_at, paid, created_at) VALUES (?, ?, ?, ?, 0, ?)",
			(name, email, phone, reg_time, reg_time),
		)
		conn.commit()
		reg_id = cur.lastrowid
		conn.close()
		# Simulate payment by redirecting to a mock payment confirmation route
		return redirect(url_for('payment', reg_id=reg_id, amount=amount))
	return render_template('register.html')


@app.route('/payment')
def payment():
	# Mock payment page - in production you'd integrate a gateway
	reg_id = request.args.get('reg_id')
	amount = request.args.get('amount')
	return render_template('payment.html', reg_id=reg_id, amount=amount, bank_name=BANK_NAME, bank_account=BANK_ACCOUNT, bank_account_name=BANK_ACCOUNT_NAME)


@app.route('/payment/confirm', methods=('POST',))
@login_required
def payment_confirm():
	# Confirm payment and mark ticket as paid+created
	reg_id = request.form.get('reg_id')
	# Very simple verification: ensure reg exists
	payer_account = (request.form.get('payer_account') or '').strip()
	payer_name = (request.form.get('payer_name') or '').strip()
	conn = get_db_connection()
	t = conn.execute('SELECT * FROM tickets WHERE id = ?', (reg_id,)).fetchone()
	if not t:
		conn.close()
		flash('Registration not found', 'error')
		return redirect(url_for('register'))
	# Save payer info and keep as pending (paid=0). Admin will confirm later.
	conn.execute('UPDATE tickets SET bank_account = ?, payer_name = ? WHERE id = ?', (payer_account, payer_name, reg_id))
	conn.commit()
	conn.close()
	session['show_clock'] = False
	flash('Payment information submitted. Your registration is pending admin verification.', 'info')
	return redirect(url_for('index'))


@app.route('/admin/login', methods=('GET', 'POST'))
def admin_login():
	if request.method == 'POST':
		# admin signs in with email and password now
		email = (request.form.get('email') or '').strip()
		password = request.form.get('password')
		# check exact match against configured quick admin creds
		if email.lower() == ADMIN_EMAIL.lower() and password == ADMIN_PLAIN:
			session['is_admin'] = True
			flash('Logged in as admin', 'success')
			return redirect(url_for('admin_dashboard'))
		flash('Invalid admin credentials', 'error')
	return render_template('admin_login.html')


@app.route('/admin')
@admin_required
def admin_dashboard():
	conn = get_db_connection()
	total = conn.execute('SELECT COUNT(*) as c FROM tickets WHERE paid = 1').fetchone()['c']
	unpaid = conn.execute('SELECT COUNT(*) as c FROM tickets WHERE paid = 0').fetchone()['c']
	tickets = conn.execute('SELECT * FROM tickets ORDER BY id DESC LIMIT 20').fetchall()
	conn.close()
	return render_template('admin_dashboard.html', total=total, unpaid=unpaid, tickets=tickets)


@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('Logged out', 'info')
    return redirect(url_for('index'))


@app.route('/admin/confirm', methods=('POST',))
@admin_required
def admin_confirm():
	ticket_id = request.form.get('ticket_id')
	if not ticket_id:
		flash('No ticket id provided', 'error')
		return redirect(url_for('admin_dashboard'))
	conn = get_db_connection()
	t = conn.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
	if not t:
		conn.close()
		flash('Ticket not found', 'error')
		return redirect(url_for('admin_dashboard'))
	# mark as paid and set created_at
	conn.execute('UPDATE tickets SET paid = 1, created_at = ? WHERE id = ?', (datetime.datetime.now(timezone.utc).isoformat(), ticket_id))
	conn.commit()
	conn.close()
	# generate ticket image (best-effort)
	ok = generate_ticket_image(int(ticket_id))
	if ok:
		flash(f'Ticket {ticket_id} confirmed and issued.', 'success')
	else:
		flash(f'Ticket {ticket_id} confirmed but image generation failed.', 'warning')
	return redirect(url_for('admin_dashboard'))


@app.route("/ticket/<int:id>")
def ticket(id):
	conn = get_db_connection()
	t = conn.execute("SELECT * FROM tickets WHERE id = ?", (id,)).fetchone()
	conn.close()
	if not t:
		flash("Ticket not found", "error")
		return redirect(url_for("index"))
	return render_template("ticket.html", ticket=t)


@app.route("/tickets")
def tickets():
	conn = get_db_connection()
	rows = conn.execute("SELECT * FROM tickets ORDER BY id DESC").fetchall()
	conn.close()
	return render_template("tickets.html", tickets=rows)


@app.route('/draw', methods=['GET', 'POST'])
@admin_required
def draw():
    conn = get_db_connection()
    last = conn.execute("SELECT ticket_id FROM winners ORDER BY drawn_at DESC LIMIT 1").fetchone()
    if request.method == "POST" or request.args.get("force"):
        candidates = conn.execute("SELECT id FROM tickets WHERE paid = 1").fetchall()
        if not candidates:
            flash("No paid tickets available to draw from.", "error")
            conn.close()
            return redirect(url_for("admin_dashboard"))
        candidate_ids = [r["id"] for r in candidates]
        ticket_id = random.choice(candidate_ids)
        conn.execute(
            "INSERT INTO winners (ticket_id, drawn_at) VALUES (?, ?)",
            (ticket_id, datetime.datetime.utcnow().isoformat()),
        )
        conn.commit()
        t = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        conn.close()
        flash(f"Winner drawn: Ticket {ticket_id} — {t['name']}", "success")
        return redirect(url_for("admin_dashboard"))
    total = conn.execute("SELECT COUNT(*) as c FROM tickets").fetchone()["c"]
    conn.close()
    return render_template("draw.html", total=total, last=last)


@app.route("/reset", methods=("POST",))
@admin_required
def reset():
    # Development helper: wipe tickets and winners (admin only)
    conn = get_db_connection()
    conn.execute("DELETE FROM winners")
    conn.execute("DELETE FROM tickets")
    conn.commit()
    conn.close()
    flash("Database reset", "info")
    return redirect(url_for("index"))


# Admin action to clear tickets (used by admin dashboard POST form)
@app.route('/admin/clear_tickets', methods=['POST'])
@admin_required
def admin_clear_tickets():
    conn = get_db_connection()
    conn.execute("DELETE FROM winners")
    conn.execute("DELETE FROM tickets")
    conn.commit()
    conn.close()
    flash('All tickets and winners cleared.', 'success')
    return redirect(url_for('admin_dashboard'))


# debug endpoint removed


if __name__ == "__main__":
	app.run(debug=True)

