from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, Response, flash, abort, session, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from bson import ObjectId
from apscheduler.schedulers.background import BackgroundScheduler
from emails import EmailSender
from dotenv import load_dotenv
import datetime, uuid, requests, json, socket
import os, time, io, pyotp, qrcode
from celery_worker import make_celery


app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for flash messages

client = MongoClient('mongodb://localhost:27017/')
db = client['uptime_robot']
collection = db['services']

app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

celery = make_celery(app)

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_PROTECTION'] = 'strong'


login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)
user_collection = db['users']

# Load environment variables from .env file
load_dotenv()

# Email sender setup
email_sender = EmailSender(
    smtp_server="smtp.gmail.com",
    smtp_port=587,
    username=os.getenv("EMAIL_USER"),
    password=os.getenv("EMAIL_PASS")
)


scheduler = BackgroundScheduler()

def check_service(service):
    url = service['url']
    port = service.get('port')  # Retrieve the port if it exists
    request_type = service['request_type']
    expected_response = service['response']
    
    result = None
    response_time = None

    try:
        if port:
            start_time = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                result = sock.connect_ex((url, port))
                status = "UP" if result == 0 else "DOWN"
                response = 'OPEN' if result == 0 else 'CLOSED'
            response_time = (time.time() - start_time) * 1000
        else:
            start_time = time.time()
            if request_type == 'GET':
                response = requests.get(url)
            elif request_type == 'POST':
                response = requests.post(url)
            response_time = (time.time() - start_time) * 1000

            if service['response_type'] == 'STATUS CODE':
                result = response.status_code
            elif service['response_type'] == 'JSON':
                result = response.json()
            else:
                result = response.text
    except Exception as e:
        print(f"Error checking service {service['name_of_service']}: {str(e)}")
    
    if not result:
        result = "UNKNOWN; URL could not be reached"
        
    status = "UP" if str(result) == str(expected_response) else "DOWN"

    next_check_time = datetime.datetime.now() + datetime.timedelta(minutes=service['frequency'])

    if status == "DOWN":
        service['consecutive_downs'] += 1
        if service['consecutive_downs'] % 3 == 0:
            send_downtime_alert.delay(service)  # Run in the background
    else:
        if service['consecutive_downs'] > 0:
            send_webhook.delay(service, status, response_time)  # Run in the background
        service['consecutive_downs'] = 0

        service['consecutive_downs'] = 0

    check_result = {
        "time": datetime.datetime.now(),
        "response": response if port else result,
        "url_pinged": f"{url}:{port}" if port else url,
        "status": status,
        "response_time": response_time,
        "next_check": next_check_time
    }

    collection.update_one(
        {"id": service['id']},
        {"$set": {
            "last_checked": datetime.datetime.now(),
            "consecutive_downs": service['consecutive_downs']
        },
            "$push": {"results": check_result}}
    )

    print(f"Service {service['name_of_service']} checked. Status: {status}, Response Time: {response_time}ms")

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.route('/qrcode')
@login_required
def generate_qrcode():
    # Ensure that the user is in the process of setting up 2FA
    if not current_user.two_factor_enabled:
        otp_secret = current_user.otp_secret
        if not otp_secret:
            otp_secret = pyotp.random_base32()
            user_collection.update_one(
                {"_id": ObjectId(current_user.id)}, 
                {"$set": {"otp_secret": otp_secret}}
            )

        totp = pyotp.TOTP(otp_secret)
        qr_uri = totp.provisioning_uri(name=current_user.email, issuer_name="YourAppName")

        # Generate the QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Serve the QR code directly as an image response
        buf = io.BytesIO()
        img.save(buf)
        buf.seek(0)
        return send_file(buf, mimetype='image/png')

    flash("2FA is already enabled or not in setup process.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/2fa_setup')
@login_required
def two_factor_setup():
    if current_user.two_factor_enabled:
        flash("2FA is already enabled.", "info")
        return redirect(url_for('dashboard'))

    # Generate a new OTP secret
    otp_secret = pyotp.random_base32()  # Always generate a new secret at this stage
    totp = pyotp.TOTP(otp_secret)
    qr_uri = totp.provisioning_uri(name=current_user.email, issuer_name="YourAppName")

    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)

    # Save QR code image in static files (or serve directly to the template)
    with open(f"static/{current_user.username}_qrcode.png", "wb") as f:
        img.save(f)
        print(f"QR code saved as static/{current_user.username}_qrcode.png")

    return render_template('2fa_setup.html', qr_code=f"/static/{current_user.username}_qrcode.png", otp_secret=otp_secret)

@app.route('/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    user_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$set": {"two_factor_enabled": False, "otp_secret": None}}
    )
    flash("Two-Factor Authentication has been disabled.", "success")
    return redirect(url_for('settings'))


@app.route('/enable_2fa', methods=['POST'])
@login_required
def enable_2fa():
    otp_secret = request.form.get('otp_secret')
    otp = request.form.get('otp')

    # Ensure the OTP is a 6-digit number
    if not otp.isdigit() or len(otp) != 6:
        flash("Invalid OTP format. Please enter a 6-digit code.", "danger")
        return redirect(url_for('two_factor_setup'))

    totp = pyotp.TOTP(otp_secret)

    # Verify the OTP entered by the user
    if 'otp_attempts' not in session:
        session['otp_attempts'] = 0
        session['otp_last_attempt'] = time.time()

    if session['otp_attempts'] >= 5 and time.time() - session['otp_last_attempt'] < 300:  # 5 attempts, 5-minute cooldown
        flash("Too many attempts. Please wait a few minutes and try again.", "danger")
        return redirect(url_for('two_factor_setup'))

    if totp.verify(otp):
        session.pop('otp_attempts', None)  # Reset the counter on success
        session.pop('otp_last_attempt', None)
        user_collection.update_one({"_id": ObjectId(current_user.id)}, {"$set": {"two_factor_enabled": True, "otp_secret": otp_secret}})
        flash("Two-Factor Authentication has been enabled.", "success")
        return redirect(url_for('dashboard'))
    else:
        session['otp_attempts'] += 1
        session['otp_last_attempt'] = time.time()
        flash("Invalid OTP. Please try again.", "danger")
        return redirect(url_for('two_factor_setup'))


class User(UserMixin):
    def __init__(self, user_id, username, email, password_hash, is_admin=False, otp_secret=None, two_factor_enabled=False, email_notifications=True, is_approved=False):
        self.id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_admin = is_admin
        self.otp_secret = otp_secret or pyotp.random_base32()  # Generate a new secret if not provided
        self.two_factor_enabled = two_factor_enabled
        self.email_notifications = email_notifications
        self.is_approved = is_approved

    @staticmethod
    def get_user_by_id(user_id):
        user_data = user_collection.find_one({"_id": ObjectId(user_id)})
        if user_data:
            return User(
                str(user_data['_id']),
                user_data['username'],
                user_data['email'],
                user_data['password_hash'],
                user_data.get('is_admin', False),
                user_data.get('otp_secret'),
                user_data.get('two_factor_enabled', False),
                user_data.get('email_notifications', True),
                user_data.get('is_approved', False)
            )
        return None


    @staticmethod
    def get_user_by_username(username):
        user_data = user_collection.find_one({"username": username})
        if user_data:
            return User(
                str(user_data['_id']), 
                user_data['username'], 
                user_data['email'], 
                user_data['password_hash'], 
                user_data.get('is_admin', False),
                user_data.get('otp_secret', None),
                user_data.get('two_factor_enabled', False),
                user_data.get('email_notifications', True),
                user_data.get('is_approved', False)
            )
        return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def non_admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.is_admin: 
            flash('Welcome Admin!', 'success')
            return redirect(url_for('admin'))  # Redirect admins to the dashboard or another page
        else:
            pass
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@admin_required
def admin():
    return redirect(url_for('admin_users'))


@app.route('/admin/users')
@admin_required
def admin_users():
    users = list(user_collection.find())
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/add', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user_data = {
            "username": username,
            "email": email,
            "password_hash": hashed_password,
            "is_admin": is_admin,
            "two_factor_enabled": False,
            "otp_secret": None,
            "email_notifications": True
        }
        user_collection.insert_one(user_data)
        flash('User added successfully!', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin_add_user.html')


@app.route('/admin/user/edit/<user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    if user_id == str(current_user.id):
        flash("You cannot edit your own account as an admin.", "danger")
        return redirect(url_for('admin_users'))
    
    user = user_collection.find_one({"_id": ObjectId(user_id)})

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        is_admin = 'is_admin' in request.form

        update_data = {
            "username": username,
            "email": email,
            "is_admin": is_admin
        }
        
        if 'password' in request.form and request.form['password']:
            password = request.form['password']
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            update_data["password_hash"] = hashed_password

        user_collection.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin_edit_user.html', user=user)

@app.route('/admin/user/<action>/<user_id>', methods=['POST'])
@admin_required
def admin_user_action(action, user_id):
    if user_id == str(current_user.id):
        flash("You cannot modify your own account as an admin.", "danger")
        return redirect(url_for('admin_users'))

    if action == 'approve':
        user = user_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            user_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"is_approved": True}})
            
            if user.get('email_notifications', True):
                subject = "Your Account Has Been Approved!"
                body = f"Hello {user['username']},\n\nYour account on Uptime Robot has been approved by an admin. You can now log in and access the platform.\n\nBest regards,\nUptime Robot Team"
                email_sender.send_email(
                    from_addr=os.getenv("EMAIL_USER"),
                    to_addrs=[user['email']],
                    subject=subject,
                    body=body
                )
            flash('User approved successfully!', 'success')
    
    elif action == 'delete':
        user_collection.delete_one({"_id": ObjectId(user_id)})
        flash('User deleted successfully!', 'success')

    else:
        flash('Invalid action.', 'danger')

    return redirect(url_for('admin_users'))



@app.route('/admin/server_settings', methods=['GET', 'POST'])
@admin_required
def server_settings():
    # Retrieve the current user's data, assuming the logged-in user is the admin
    user_data = user_collection.find_one({"_id": ObjectId(current_user.id)})

    # Load the server settings from the user's document
    server_settings = user_data.get('server_settings', {})
    server_name = server_settings.get('server_name', "Uptime Robot Server")
    server_ip = server_settings.get('server_ip', "192.168.1.1")
    server_port = server_settings.get('server_port', "5000")
    admin_email = server_settings.get('admin_email', user_data.get('email', "admin@example.com"))

    if request.method == 'POST':
        # Update the server settings with the form data
        server_name = request.form['server_name']
        server_ip = request.form['server_ip']
        server_port = request.form['server_port']
        admin_email = request.form['admin_email']

        # Update the settings in the database
        user_collection.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {
                "server_settings.server_name": server_name,
                "server_settings.server_ip": server_ip,
                "server_settings.server_port": server_port,
                "server_settings.admin_email": admin_email
            }}
        )

        flash('Server settings updated successfully!', 'success')
        return redirect(url_for('server_settings'))

    return render_template('admin_server_settings.html', 
                           server_name=server_name, 
                           server_ip=server_ip, 
                           server_port=server_port, 
                           admin_email=admin_email)



@login_manager.user_loader
def load_user(user_id):
    return User.get_user_by_id(user_id)


@app.route('/update_password', methods=['POST'])
@non_admin_required
def update_password():
    # Get the form data
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    # Validate the current password
    user = user_collection.find_one({"_id": ObjectId(current_user.id)})
    if not bcrypt.check_password_hash(user['password_hash'], current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('settings'))

    # Validate the new password and confirmation
    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('settings'))

    # Hash the new password
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    # Update the password in the database
    user_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$set": {"password_hash": hashed_password}}
    )

    flash('Password updated successfully!', 'success')
    return redirect(url_for('settings'))


@celery.task
def send_downtime_alert(service):
    user = User.get_user_by_id(service['user_id'])
    
    if user.email_notifications:
        subject = f"Alert: {service['name_of_service']} - {service['url']} is down!"
        body = f"The service {service['name_of_service']} ({service['url']}) has been down for the last 3 checks. Please investigate."

        email_sender.send_email(
            from_addr=os.getenv("EMAIL_USER"),
            to_addrs=[user.email],
            subject=subject,
            body=body
        )

    send_webhook.delay(service, "DOWN", None)  # Call the webhook to notify about the downtime


@celery.task
def send_webhook(service, status, response_time):
    if 'webhooks' in service and service['webhooks']:
        payload = {
            "service_name": service['name_of_service'],
            "url": service['url'],
            "status": status,
            "response_time": response_time,
            "checked_at": datetime.datetime.now().isoformat()
        }
        for webhook_url in service['webhooks']:
            try:
                response = requests.post(webhook_url, json=payload)
                if response.status_code != 200:
                    print(f"Failed to send webhook to {webhook_url} for {service['name_of_service']}: {response.status_code}")
                else:
                    print(f"Webhook sent to {webhook_url} for {service['name_of_service']}")
            except requests.exceptions.RequestException as e:
                print(f"Error sending webhook to {webhook_url} for {service['name_of_service']}: {e}")
    else:
        print(f"No webhooks configured for service {service['name_of_service']}")



def run_checks():
    services = collection.find()
    for service in services:
        check_service(service)

def schedule_checks():
    services = collection.find()
    for service in services:
        interval = service['frequency'] * 60  # Convert minutes to seconds
        scheduler.add_job(func=check_service, trigger="interval", args=[service], seconds=interval, id=service['id'])

@app.errorhandler(401)
def unauthorized_error(error):
    return redirect(url_for('index'))

@app.route('/')
def index():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin_users'))
    elif current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@non_admin_required
def dashboard():
    services = list(collection.find({"user_id": current_user.id}))  # Fetch only the services belonging to the logged-in user
    return render_template('dashboard.html', services=services)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        wants_2fa = 'enable_2fa' in request.form  # Check if the user wants to enable 2FA
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Check if username or email already exists
        existing_user = user_collection.find_one({"$or": [{"username": username}, {"email": email}]})
        if existing_user:
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('signup'))

        user_data = {
            "username": username,
            "email": email,
            "password_hash": hashed_password,
            "two_factor_enabled": False,  # 2FA is not enabled yet
            "otp_secret": None,  # Will be generated in 2FA setup
            "email_notifications": True,
            "is_approved": False,  # User must wait for approval
            "wants_2fa": wants_2fa  # Store the intent to enable 2FA
        }
        user_collection.insert_one(user_data)
        flash('Account created successfully! Please wait for admin approval.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if '@' in username:
            user_data = user_collection.find_one({"email": username})
        else:
            user_data = user_collection.find_one({"username": username})

        if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
            if not user_data.get('is_approved', False):
                flash("Your account is pending approval. Please wait for an admin to approve your account.", "warning")
                return redirect(url_for('login'))
            
            user = User(
                user_id=user_data['_id'], 
                username=user_data['username'], 
                email=user_data['email'], 
                password_hash=user_data['password_hash'], 
                is_admin=user_data.get('is_admin', False),
                otp_secret=user_data.get('otp_secret'),
                two_factor_enabled=user_data.get('two_factor_enabled', False)
            )

            login_user(user)
            if user.two_factor_enabled:
                return redirect(url_for('two_factor_verify'))
            elif user_data.get('wants_2fa', False):
                flash("Please complete your 2FA setup.", "info")
                return redirect(url_for('two_factor_setup'))
            else:
                flash("You are logged in. Consider enabling Two-Factor Authentication for added security.", "success")
                return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password.", "danger")
    
    return render_template('login.html')


@app.route('/2fa_verify', methods=['GET', 'POST'])
@login_required
def two_factor_verify():
    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(current_user.otp_secret)

        if totp.verify(otp):
            flash("2FA verification successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for('two_factor_verify'))

    return render_template('2fa_verify.html')


@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/settings', methods=['GET', 'POST'])
@non_admin_required
def settings():
    if request.method == 'POST':
        email_notifications = request.form.get('email_notifications') == 'on'
        
        user_collection.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {"email_notifications": email_notifications}}
        )
        
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('settings'))

    # Fetch current settings
    user = user_collection.find_one({"_id": ObjectId(current_user.id)})
    return render_template('settings.html', email_notifications=user.get('email_notifications', True))


@app.route('/events', methods=['GET', 'POST'])
@non_admin_required
def events():
    # Default time filter: show events from the last 24 hours
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(days=1)

    if request.method == 'POST':
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')

        # Parse the provided start and end times
        if start_time_str:
            start_time = datetime.datetime.fromisoformat(start_time_str)
        if end_time_str:
            end_time = datetime.datetime.fromisoformat(end_time_str)

    # Fetch all events from all services within the time range
    services = collection.find({
        "user_id": current_user.id,
        "results.time": {"$gte": start_time, "$lte": end_time}
    })

    # Flatten the results and sort them by time
    events = []
    for service in services:
        for result in service['results']:
            if start_time <= result['time'] <= end_time:
                event = {
                    "service_name": service['name_of_service'],
                    "url_pinged": result['url_pinged'],
                    "time": result['time'],
                    "status": result['status'],
                    "response": result['response']
                }
                events.append(event)

    # Sort the events by time
    events = sorted(events, key=lambda x: x['time'], reverse=True)

    return render_template('events.html', events=events, start_time=start_time, end_time=end_time)

@app.route('/manual_run_checks')
@non_admin_required
def manual_run_checks():
    run_checks()
    return redirect(url_for('index'))

@app.route('/manual_check/<service_id>', methods=['POST'])
@non_admin_required
def manual_check(service_id):
    service = collection.find_one({"id": service_id})
    if service:
        check_service(service)
    
    # Get the 'redirect_to' parameter from the query string
    redirect_to = request.args.get('redirect_to', 'index')
    
    # Redirect to the specified page
    return redirect(url_for(redirect_to, service_id=service_id) if redirect_to == 'service_info' else url_for(redirect_to))


@app.route('/add_service', methods=['GET', 'POST'])
@non_admin_required
def add_service():
    if request.method == 'POST':
        # Existing fields
        name = request.form.get('name')
        url = request.form.get('url')
        port = request.form.get('port')
        frequency = int(request.form.get('frequency'))
        request_type = request.form.get('request_type')
        response_type = request.form.get('response_type')
        response = request.form.get('response')
        webhooks = [wh for wh in request.form.getlist('webhooks') if wh.strip()]  # Get the list of webhook URLs

        service = {
            "id": str(uuid.uuid4()),
            "user_id": current_user.id,
            "date_added": datetime.datetime.now(),
            "frequency": frequency,
            "last_checked": None,
            "consecutive_downs": 0,
            "results": [],
            "name_of_service": name,
            "url": url,
            "port": int(port) if port else None,
            "request_type": request_type,
            "response_type": response_type,
            "response": response,
            "webhooks": webhooks  # Store the list of webhook URLs
        }
        collection.insert_one(service)
        scheduler.add_job(func=check_service, trigger="interval", args=[service], seconds=frequency * 60, id=service['id'])
        return redirect(url_for('index'))
    else:
        form_type = request.args.get('form_type', 'website')
        return render_template('add_service.html', form_type=form_type)



@app.route('/clear_history', methods=['POST'])
@non_admin_required
def clear_history():
    # Remove all results from all services
    collection.update_many({}, {"$set": {"results": []}})
    flash('Event history cleared successfully!', 'success')
    return redirect(url_for('events'))

@app.route('/info/<service_id>', methods=['GET', 'POST'])
@non_admin_required
def service_info(service_id):
    service = collection.find_one({"id": service_id})
    
    if request.method == 'POST':
        name = request.form.get('name')
        url = request.form.get('url')
        port = request.form.get('port')
        frequency = int(request.form.get('frequency'))
        request_type = request.form.get('request_type')
        response_type = request.form.get('response_type')
        response = request.form.get('response')
        webhooks = request.form.getlist('webhooks')  # Get the updated list of webhook URLs

        collection.update_one(
            {"id": service_id},
            {"$set": {
                "name_of_service": name,
                "url": url,
                "port": int(port) if port else None, 
                "frequency": frequency,
                "request_type": request_type,
                "response_type": response_type,
                "response": response,
                "webhooks": webhooks  # Update the list of webhook URLs
            }}
        )
        scheduler.reschedule_job(service_id, trigger="interval", seconds=frequency * 60)
        return redirect(url_for('service_info', service_id=service_id))

    statuses = [1 if result['status'] == "UP" else 0 for result in service['results']]
    timestamps = [result['time'].strftime('%Y-%m-%d %H:%M:%S') for result in service['results']]
    response_times = [result.get('response_time', 0) for result in service['results'] if result.get('response_time') is not None]

    # Calculate average response time
    if response_times:
        average_response_time = sum(response_times) / len(response_times)
    else:
        average_response_time = 0

    if not statuses:
        overall_status = "No data"
    else:
        overall_status = "Operational" if statuses[-1] == 1 else "Unoperational"

    total_checks = len(service.get('results', []))
    up_checks = sum(statuses)
    uptime_percentage = (up_checks / total_checks) * 100 if total_checks > 0 else 0

    return render_template('info.html', service=service, overall_status=overall_status, uptime_percentage=uptime_percentage, statuses=statuses, timestamps=timestamps, response_times=response_times, average_response_time=average_response_time)

@app.route('/delete/<service_id>', methods=['POST'])
@non_admin_required
def delete_service(service_id):
    collection.delete_one({"id": service_id})
    scheduler.remove_job(service_id)
    return redirect(url_for('index'))

@app.route('/dump_json')
@non_admin_required
def dump_json():
    # Fetch only the services belonging to the logged-in user
    services = list(collection.find({"user_id": current_user.id}, {'_id': False}))  # Exclude MongoDB's internal '_id' field
    return Response(
        json.dumps(services, default=str, indent=4), 
        mimetype='application/json',
        headers={"Content-Disposition": "attachment;filename=services.json"}
    )

def convert_dates(service):
    date_fields = ['date_added', 'last_checked']
    result_date_fields = ['time', 'next_check']

    for field in date_fields:
        if field in service:
            try:
                service[field] = datetime.datetime.fromisoformat(service[field])
            except ValueError:
                raise ValueError(f"Invalid date format for field {field}: {service[field]}")

    for result in service.get('results', []):
        for field in result_date_fields:
            if field in result:
                try:
                    result[field] = datetime.datetime.fromisoformat(result[field])
                except ValueError:
                    raise ValueError(f"Invalid date format for result field {field}: {result[field]}")

    return service


@app.route('/upload_json', methods=['POST'])
@non_admin_required
def upload_json():
    file = request.files['file']
    if file:
        try:
            services_json = json.load(file)
            if isinstance(services_json, list):
                services_with_user_id = []
                for service in services_json:
                    # Convert dates; if this fails, the whole process will be aborted
                    service = convert_dates(service)
                    
                    # Ensure the user cannot set or modify the user_id
                    service['user_id'] = current_user.id
                    services_with_user_id.append(service)

                # Clear the existing data only for the logged-in user
                collection.delete_many({"user_id": current_user.id})

                # Insert the new services associated with the logged-in user
                collection.insert_many(services_with_user_id)
                flash('JSON data uploaded successfully!', 'success')
            else:
                flash('Invalid JSON format! Expected a list of services.', 'error')
        except (ValueError, TypeError, KeyError) as e:
            flash('Failed to upload JSON: Invalid date format or data structure.', 'error')
            # Optionally log the exception for debugging
            print(f"Error during JSON upload: {e}")
    return redirect(url_for('settings'))



@app.route('/upload')
@non_admin_required
def upload_page():
    return render_template('upload.html')

if __name__ == "__main__":
    schedule_checks()
    scheduler.start()
    app.run(debug=True)
