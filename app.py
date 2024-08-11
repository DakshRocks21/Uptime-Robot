from flask import Flask, render_template, request, redirect, url_for, jsonify, Response, flash
from pymongo import MongoClient
import datetime
import uuid
import requests
import json
import socket
from apscheduler.schedulers.background import BackgroundScheduler
from emails import EmailSender
from dotenv import load_dotenv
import os
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from bson import ObjectId



app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for flash messages

client = MongoClient('mongodb://localhost:27017/')
db = client['uptime_robot']
collection = db['services']


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


# Scheduler
scheduler = BackgroundScheduler()

def check_service(service):
    url = service['url']
    port = service.get('port')  # Retrieve the port if it exists
    request_type = service['request_type']
    expected_response = service['response']
    
    result = None

    try:
        # Check if port is specified
        if port:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)  # Set timeout to 10 seconds
                result = sock.connect_ex((url, port))
                status = "UP" if result == 0 else "DOWN"
                response = 'OPEN' if result == 0 else 'CLOSED'
        else:
            # Normal URL check
            if request_type == 'GET':
                response = requests.get(url)
            elif request_type == 'POST':
                response = requests.post(url)

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

    # Track consecutive down counts
    if status == "DOWN":
        service['consecutive_downs'] += 1
        # Send email if 3 consecutive downs are detected
        if service['consecutive_downs'] % 3 == 0:
            send_downtime_alert(service)
    else:
        # Reset the failure counter if service is UP
        service['consecutive_downs'] = 0

    check_result = {
        "time": datetime.datetime.now(),
        "response": response if port else result,
        "url_pinged": f"{url}:{port}" if port else url,
        "status": status,
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

    print(f"Service {service['name_of_service']} checked. Status: {status}")

 
class User(UserMixin):
    def __init__(self, user_id, username, email, password_hash):
        self.id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash

    @staticmethod
    def get_user_by_id(user_id):
        user_data = user_collection.find_one({"_id": ObjectId(user_id)})
        if user_data:
            return User(str(user_data['_id']), user_data['username'], user_data['email'], user_data['password_hash'])
        return None

    @staticmethod
    def get_user_by_username(username):
        user_data = user_collection.find_one({"username": username})
        if user_data:
            return User(str(user_data['_id']), user_data['username'], user_data['email'], user_data['password_hash'])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get_user_by_id(user_id)



def send_downtime_alert(service):
    user = User.get_user_by_id(service['user_id'])
    subject = f"Alert: {service['name_of_service']} - {service['url']} is down!"
    body = f"The service {service['name_of_service']} ({service['url']}) has been down for the last 3 checks. Please investigate."

    email_sender.send_email(
        from_addr=os.getenv("EMAIL_USER"),
        to_addrs=[user.email],  # Send email to the user's email
        subject=subject,
        body=body
    )

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
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    services = list(collection.find({"user_id": current_user.id}))  # Fetch only the services belonging to the logged-in user
    return render_template('dashboard.html', services=services)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Check if username or email already exists
        existing_user = user_collection.find_one({"$or": [{"username": username}, {"email": email}]})
        if existing_user:
            flash('Username or email already exists!', 'danger')
            return redirect(url_for('signup'))

        user_data = {
            "username": username,
            "email": email,
            "password_hash": hashed_password
        }
        user_collection.insert_one(user_data)
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        print(request.form)
        username = request.form['username']
        password = request.form['password']
        user = User.get_user_by_username(username)

        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            print('Invalid username or password!')
            flash('Invalid username or password!', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


@app.route('/events', methods=['GET', 'POST'])
@login_required
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
@login_required
def manual_run_checks():
    run_checks()
    return redirect(url_for('index'))

@app.route('/manual_check/<service_id>', methods=['POST'])
@login_required
def manual_check(service_id):
    service = collection.find_one({"id": service_id})
    if service:
        check_service(service)
    return redirect(url_for('index'))

@app.route('/add_service', methods=['GET', 'POST'])
@login_required
def add_service():
    if request.method == 'POST':
        name = request.form.get('name')
        url = request.form.get('url')
        port = request.form.get('port')
        frequency = int(request.form.get('frequency'))
        request_type = request.form.get('request_type')
        response_type = request.form.get('response_type')
        response = request.form.get('response')

        service = {
            "id": str(uuid.uuid4()),
            "user_id": current_user.id,  # Associate with the logged-in user
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
            "response": response
        }
        collection.insert_one(service)
        scheduler.add_job(func=check_service, trigger="interval", args=[service], seconds=frequency * 60, id=service['id'])
        return redirect(url_for('index'))
    else:
        form_type = request.args.get('form_type', 'website')
        return render_template('add_service.html', form_type=form_type)


@app.route('/clear_history', methods=['POST'])
@login_required
def clear_history():
    # Remove all results from all services
    collection.update_many({}, {"$set": {"results": []}})
    flash('Event history cleared successfully!', 'success')
    return redirect(url_for('events'))

@app.route('/edit/<service_id>', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    service = collection.find_one({"id": service_id})
    if request.method == 'POST':
        name = request.form.get('name')
        url = request.form.get('url')
        port = request.form.get('port')  # Get the port from the form
        frequency = int(request.form.get('frequency'))
        request_type = request.form.get('request_type')
        response_type = request.form.get('response_type')
        response = request.form.get('response')

        collection.update_one(
            {"id": service_id},
            {"$set": {
                "name_of_service": name,
                "url": url,
                "port": int(port) if port else None,  # Store the port as an integer if provided
                "frequency": frequency,
                "request_type": request_type,
                "response_type": response_type,
                "response": response
            }}
        )
        scheduler.reschedule_job(service_id, trigger="interval", seconds=frequency * 60)
        return redirect(url_for('index'))
    return render_template('edit.html', service=service)

@app.route('/delete/<service_id>', methods=['POST'])
@login_required
def delete_service(service_id):
    collection.delete_one({"id": service_id})
    scheduler.remove_job(service_id)
    return redirect(url_for('index'))

@app.route('/dump_json')
@login_required
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
@login_required
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
@login_required
def upload_page():
    return render_template('upload.html')

if __name__ == "__main__":
    schedule_checks()
    scheduler.start()
    app.run(debug=True)
