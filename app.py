from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,   # added
)
import sqlite3
import datetime
from datetime import timezone
from PIL import Image, ImageDraw, ImageFont
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from functools import wraps
from flask import session, redirect, url_for, flash
import os
import logging
import traceback
import sys

# configure simple error log
logging.basicConfig(filename='error.log', level=logging.ERROR, format='%(asctime)s %(levelname)s %(message)s')

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# If your templates folder is named 'templates' rename the folder or set template_folder accordingly.
app = Flask(__name__, static_folder='static', template_folder='template')
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
	"""Make helpers available inside templates."""
	return {
		"now": lambda: datetime.datetime.now(),
		"current_user": lambda: session.get("user_name"),
		"is_admin": lambda: bool(session.get("is_admin")),
		"enugu_description": "Enugu Amaka Building Materials Nig. Ltd. — trusted supplier of tiles, doors, cement and construction materials. Running a company raffle draw for staff and customers; buy tickets to participate.",
	}


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

    # pass description to template as well (templates may use it directly)
    enugu_description = "Enugu Amaka Building Materials Nig. Ltd. — trusted supplier of tiles, doors, cement and construction materials. Running a company raffle draw for staff and customers; buy tickets to participate."

    return render_template(
        "index.html",
        total=total,
        winner=winner,
        show_clock=show_clock,
        server_time=server_time,
        enugu_description=enugu_description
    )


def login_required(fn):
	from functools import wraps

	@wraps(fn)
	def wrapper(*args, **kwargs):
		if not session.get('user_id'):
			flash('Please login or register to continue', 'error')
			return redirect(url_for('login', next=request.path))
		return fn(*args, **kwargs)

	return wrapper


def get_user_by_email(email):
    """Return user as a plain dict (or None). Uses get_db_connection()."""
    if not email:
        return None
    email = email.strip().lower()
    conn = None
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT * FROM users WHERE lower(email)=?", (email,)).fetchone()
        if not row:
            return None
        # convert sqlite3.Row to plain dict so .get(...) works and no AttributeError occurs
        return dict(row)
    except Exception:
        return None
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass

@app.route('/login', methods=('GET','POST'))
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = (request.form.get('password') or '')
        # debug: log what arrived (mask password)
        app.logger.info("Login POST received. form_keys=%s email=%s password_len=%d",
                        list(request.form.keys()), email, len(password))

        # admin quick-login (env override allowed)
        admin_email = (os.environ.get('ADMIN_EMAIL') or 'enuamaka@gmail.com').strip().lower()
        admin_plain = (os.environ.get('ADMIN_PW_PLAIN') or 'enuguamaka12').strip()
        if email and password and email == admin_email and password == admin_plain:
            session.clear()
            session['user_id'] = 'admin'
            session['user_name'] = 'Administrator'
            session['is_admin'] = True
            app.logger.info("Admin login success for %s", email)
            return redirect(url_for('admin_dashboard'))

        # normal user flow
        try:
            user = get_user_by_email(email)
        except Exception as e:
            app.logger.exception("get_user_by_email failed")
            user = None

        if not user:
            app.logger.info("Login failed: user not found for %s", email)
            flash('Invalid credentials', 'danger')
            return render_template('user_login.html')

        # read stored password safely
        stored = None
        try:
            stored = user['password_hash']
        except Exception:
            try:
                stored = user['password']
            except Exception:
                stored = None

        app.logger.info("Found user id=%s stored_password_present=%s", user.get('id', 'unknown'), bool(stored))

        ok = False
        if stored:
            try:
                ok = check_password_hash(stored, password)
            except Exception:
                ok = (stored == password)

        if not ok:
            app.logger.info("Login failed: wrong password for %s", email)
            flash('Invalid credentials', 'danger')
            return render_template('user_login.html')

        # success
        session.clear()
        session['user_id'] = user['id']
        session['user_name'] = user.get('name') or email
        session['is_admin'] = bool(user.get('is_admin'))
        app.logger.info("Login success user_id=%s email=%s", session['user_id'], email)
        return redirect(url_for('index'))

    return render_template('user_login.html')


@app.route('/register_user', methods=('GET','POST'))
def register_user():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')

        if not email or not password:
            flash('Email and password are required', 'error')
            return redirect(url_for('register_user'))
        if password != password2:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register_user'))

        conn = get_db_connection()
        try:
            cur = conn.cursor()
            # check for existing email first to avoid UNIQUE error
            cur.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cur.fetchone():
                flash('Email already registered — please login', 'error')
                return redirect(url_for('login'))

            hashed = generate_password_hash(password)
            now_iso = datetime.datetime.utcnow().isoformat()

            cur.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, hashed, now_iso)
            )
            conn.commit()
            user_id = cur.lastrowid

        except sqlite3.IntegrityError:
            conn.rollback()
            flash('Email already registered — please login', 'error')
            return redirect(url_for('login'))
        except Exception:
            conn.rollback()
            app.logger.exception("Error creating user")
            flash('Unexpected error creating account', 'error')
            return redirect(url_for('register_user'))
        finally:
            conn.close()

        session['user_id'] = user_id
        session['user_name'] = name or email
        flash('Registration successful', 'success')
        return redirect(request.form.get('return') or url_for('index'))

    return render_template('user_register.html')


@app.route('/logout')
def logout():
	session.clear()
	flash('Logged out', 'info')
	return redirect(url_for('index'))


@app.route("/buy", methods=("GET", "POST"))
@login_required
def buy():
    TICKET_PRICE = 200000.0
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
            "INSERT INTO tickets (name, email, phone, registered_at, created_at, paid) VALUES (?, ?, ?, ?, ?, 0)",
            (name, email, phone, now_iso, now_iso),
        )
        conn.commit()
        ticket_id = cur.lastrowid
        conn.close()
        # Render payment page immediately so account/bank details are visible to the user
        flash(f"Registration submitted (ID: {ticket_id}). Please complete the payment instructions below.", "info")
        return render_template("payment.html", reg_id=ticket_id, amount=TICKET_PRICE, bank_name=BANK_NAME, bank_account=BANK_ACCOUNT, bank_account_name=BANK_ACCOUNT_NAME)
    return render_template("buy.html", price=200000)


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
    # if user is logged in, take them to the buy flow
    if session.get('user_id'):
        return redirect(url_for('buy'))
    # not logged in: ask them to sign in or register, preserve return target
    flash('Please sign in or register to proceed to payment', 'warning')
    return redirect(url_for('login', **{'return': url_for('buy')}))


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
        # normalize inputs
        email = (request.form.get('email') or '').strip().lower()
        password = (request.form.get('password') or '').strip()
        app.logger.info("Admin login attempt for email=%s", email)

        # configured admin creds (env overrides allowed)
        admin_email = (os.environ.get('ADMIN_EMAIL') or ADMIN_EMAIL or '').strip().lower()
        admin_plain = (os.environ.get('ADMIN_PW_PLAIN') or ADMIN_PLAIN or '').strip()

        if email == admin_email and password == admin_plain:
            # set full admin session
            session.clear()
            session['user_id'] = 'admin'
            session['user_name'] = 'Administrator'
            session['is_admin'] = True
            app.logger.info("Admin login success for %s", email)
            flash('Logged in as admin', 'success')
            return redirect(url_for('admin_dashboard'))

        app.logger.info("Admin login failed for %s", email)
        flash('Invalid admin credentials', 'error')
    return render_template('admin_login.html')


@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    # totals
    total = conn.execute("SELECT COUNT(*) as c FROM tickets").fetchone()["c"]
    unpaid = conn.execute("SELECT COUNT(*) as c FROM tickets WHERE paid = 0").fetchone()["c"]
    # list tickets with pending/unpaid first, then newest registrations
    tickets = conn.execute(
        "SELECT * FROM tickets ORDER BY paid ASC, registered_at DESC"
    ).fetchall()
    conn.close()
    return render_template('admin_dashboard.html', total=total, unpaid=unpaid, tickets=tickets)


@app.route('/admin/logout')
def admin_logout():
    # clear full session to avoid stale is_admin values
    session.clear()
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


# small JSON endpoint used by injected navbar script to get server-side auth state
@app.route("/_session.json")
def session_json():
    return jsonify(
        logged_in=bool(session.get("user_id")),
        user_name=session.get("user_name"),
        is_admin=bool(session.get("is_admin"))
    )


# Inject a small client-side script into HTML responses that have the SITE NAVBAR marker.
# The script will:
# - update the #auth-area to show Login/Register OR Hi <name> + Logout (Logout links to /logout)
# - hide any draw links for non-admin users (elements with hrefs containing "draw")
# - update an element with id="site-description" if present to the official description
@app.after_request
def inject_nav_script(response):
    try:
        content_type = response.headers.get("Content-Type", "")
        if "text/html" in content_type.lower():
            marker = b"<!-- SITE NAVBAR START -->"
            data = response.get_data()
            if marker in data:
                # decode once
                text = data.decode("utf-8", errors="ignore")
                # fix common static .html links inserted into templates -> map to Flask routes
                replacements = {
                    'href="index.html"': 'href="/"',
                    "href='index.html'": "href='/'",
                    'href="tickets.html"': 'href="/tickets"',
                    "href='tickets.html'": "href='/tickets'",
                    'href="buy.html"': 'href="/buy"',
                    "href='buy.html'": "href='/buy'",
                    'href="payment.html"': 'href="/payment"',
                    "href='payment.html'": "href='/payment'",
                    'href="draw.html"': 'href="/draw"',
                    "href='draw.html'": "href='/draw'",
                    'href="base.html"': 'href="/"',
                    "href='base.html'": "href='/'",
                    'href="user_login.html"': 'href="/login"',
                    "href='user_login.html'": "href='/login'",
                    'href="user_register.html"': 'href="/register_user"',
                    "href='user_register.html'": "href='/register_user'",
                    # replace any "Get started" button text/link to Register
                    'Get started': 'Register',
                    # If there was a button linking to a static page, ensure it goes to register
                    'href="/get_started"': 'href="/register_user"',
                    "href='/get_started'": "href='/register_user'",
                }
                for a, b in replacements.items():
                    text = text.replace(a, b)

                # small client-side script (unchanged) appended before </body>
                script = (
                    "<script>(async function(){"
                    "try{"
                    "  const r = await fetch('/_session.json'); if(!r.ok) return;"
                    "  const s = await r.json();"
                    "  const auth = document.getElementById('auth-area');"
                    "  if(auth){"
                    "    if(s.logged_in){"
                    "      auth.innerHTML = '<span style=\"margin-right:12px;color:#2f2a57;font-weight:600\">Hi, '+(s.user_name||'')+'</span>'"
                    "        +'<a id=\"logout-link\" href=\"/logout\" style=\"background:transparent;border:2px solid #d32b2b;color:#d32b2b;padding:8px 14px;border-radius:24px;text-decoration:none;font-weight:700\">Logout</a>';"
                    "    } else {"
                    "      auth.innerHTML = '<a id=\"login-link\" class=\"btn-outline\" href=\"/login\" style=\"background:transparent;border:2px solid #2f2a57;color:#2f2a57;padding:8px 14px;border-radius:24px;text-decoration:none;font-weight:700\">Login</a>'"
                    "        +'<a id=\"register-link\" class=\"btn\" href=\"/register_user\" style=\"background:#bfc6ff;border:2px solid rgba(47,42,87,0.15);padding:8px 14px;border-radius:24px;text-decoration:none;font-weight:700;color:#2f2a57\">Register</a>';"
                    "    }"
                    "  }"
                    "  if(!s.is_admin){ document.querySelectorAll('a[href*=\"draw\"]').forEach(a=>a.style.display='none'); }"
                    "  const desc = document.getElementById('site-description');"
                    "  if(desc) desc.textContent = 'Enugu Amaka Building Materials Nig. Ltd. — company raffle draw. Buy tickets to participate.';"
                    "}catch(e){console.error(e)}"
                    "})();</script>"
                )
                if "</body>" in text:
                    text = text.replace("</body>", script + "</body>")
                else:
                    text = text + script
                response.set_data(text.encode("utf-8"))
    except Exception as e:
        app.logger.exception("inject_nav_script failed")
    return response

if __name__ == "__main__":
    # Use PORT/HOST from environment (Render sets $PORT). Allow toggling debug via FLASK_DEBUG.
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)

# Create a test user account (for development convenience)
try:
	conn = sqlite3.connect('raffle.db')
	pw = generate_password_hash("testpass123")
	conn.execute("INSERT INTO users (name,email,password_hash) VALUES (?,?,?)", ("Test User","test@example.com",pw))
	conn.commit()
	conn.close()
	print("created test@example.com / testpass123")
except Exception as e:
	print("Error creating test user:", e)

import sqlite3, sys, os

DB = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('--') else os.path.join(os.path.dirname(__file__), 'database.db')
delete_email = None
if '--delete' in sys.argv:
    try:
        delete_email = sys.argv[sys.argv.index('--delete') + 1]
    except IndexError:
        print("Usage: inspect_db.py [path/to/db] [--delete email]")
        sys.exit(1)

if not os.path.exists(DB):
    print("Database not found:", DB)
    sys.exit(1)

conn = sqlite3.connect(DB)
cur = conn.cursor()

print("== users table info (PRAGMA table_info(users)) ==")
for row in cur.execute("PRAGMA table_info(users);"):
    print(row)

print("\n== users table schema ==")
row = cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users';").fetchone()
print(row[0] if row else "users table not found")

print("\n== duplicate emails (email, count) ==")
for r in cur.execute("SELECT email, COUNT(*) AS c FROM users GROUP BY email HAVING c>1 ORDER BY c DESC;"):
    print(r)

print("\n== latest 50 users (id, name, email) ==")
for r in cur.execute("SELECT id, name, email FROM users ORDER BY id DESC LIMIT 50;"):
    print(r)

if delete_email:
    print("\nDeleting duplicate rows for:", delete_email)
    # keep the smallest id, delete the rest
    ids = [r[0] for r in cur.execute("SELECT id FROM users WHERE email=? ORDER BY id ASC;", (delete_email,)).fetchall()]
    if len(ids) <= 1:
        print("No duplicates to delete for", delete_email)
    else:
        keep = ids[0]
        to_delete = ids[1:]
        print("Keeping id:", keep, "Deleting ids:", to_delete)
        cur.execute("DELETE FROM users WHERE id IN ({})".format(",".join("?"*len(to_delete))), to_delete)
        conn.commit()
        print("Deleted", cur.rowcount, "rows")
conn.close()
print("\nDone.")

