Raffle (ticket draw) Flask app

Quick start (PowerShell):

1. Create and activate a virtualenv:

python -m venv venv; .\venv\Scripts\Activate

2. Install dependencies:

pip install -r requirements.txt

3. Run the app:

python app.py

4. Open http://127.0.0.1:5000 in your browser.

Notes:
- The app stores data in `raffle.db` in the project folder.
- For development you can reset stored data by POSTing to `/reset` (for example via a small HTML form or curl).
- Set RAFFLE_SECRET env var in production to keep session secure.

Admin setup (single admin)
 - Create a password hash for the admin and set it in the environment as ADMIN_PW_HASH. Example (PowerShell):

```powershell
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your-strong-password'))" | Set-Clipboard
setx ADMIN_PW_HASH "<paste-the-copied-value-here>"
setx ADMIN_USER "admin"
```

Replace 'your-strong-password' with a secure password. On the first run the app will use the hashed value to validate the single admin user.
