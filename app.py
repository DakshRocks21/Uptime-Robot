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
import random, string

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for flash messages

client = MongoClient('mongodb://localhost:27017/')
db = client['uptime_robot']
collection = db['services']

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

 

def send_downtime_alert(service):
    subject = f"Alert: {service['name_of_service']} - {service['url']} is down!"
    body = f"The service {service['name_of_service']} ({service['url']}) has been down for the last 3 checks. Please investigate."

    email_sender.send_email(
        from_addr=os.getenv("EMAIL_USER"),
        to_addrs=["daksh@dakshthapar.com"],  # Replace with actual recipient(s)
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

@app.route('/')
def index():
    services = list(collection.find())
    return render_template('index.html', services=services)

@app.route('/events', methods=['GET', 'POST'])
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
def manual_run_checks():
    run_checks()
    return redirect(url_for('index'))

@app.route('/manual_check/<service_id>', methods=['POST'])
def manual_check(service_id):
    service = collection.find_one({"id": service_id})
    if service:
        check_service(service)
    return redirect(url_for('index'))

@app.route('/add_service', methods=['GET', 'POST'])
def add_service():
    if request.method == 'POST':
        name = request.form.get('name')
        url = request.form.get('url')
        port = request.form.get('port')  # Get the port from the form
        frequency = int(request.form.get('frequency'))
        request_type = request.form.get('request_type')
        response_type = request.form.get('response_type')
        response = request.form.get('response')

        service = {
            "id": str(uuid.uuid4()),
            "date_added": datetime.datetime.now(),
            "frequency": frequency,
            "last_checked": None,
            "consecutive_downs": 0,  # Initialize consecutive downs counter
            "results": [],
            "name_of_service": name,
            "url": url,
            "port": int(port) if port else None,  # Store the port as an integer if provided
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
def clear_history():
    # Remove all results from all services
    collection.update_many({}, {"$set": {"results": []}})
    flash('Event history cleared successfully!', 'success')
    return redirect(url_for('events'))

@app.route('/edit/<service_id>', methods=['GET', 'POST'])
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
def delete_service(service_id):
    collection.delete_one({"id": service_id})
    scheduler.remove_job(service_id)
    return redirect(url_for('index'))

@app.route('/dump_json')
def dump_json():
    services = list(collection.find({}, {'_id': False}))  # Exclude MongoDB's internal '_id' field
    return Response(
        json.dumps(services, default=str, indent=4), 
        mimetype='application/json',
        headers={"Content-Disposition": "attachment;filename=services.json"}
    )
def convert_dates(service):
    date_fields = ['date_added', 'last_checked']
    result_date_fields = ['time', 'next_check']

    for field in date_fields:
        if field in service and isinstance(service[field], str):
            service[field] = datetime.datetime.fromisoformat(service[field])

    for result in service.get('results', []):
        for field in result_date_fields:
            if field in result and isinstance(result[field], str):
                result[field] = datetime.datetime.fromisoformat(result[field])

    return service

@app.route('/upload_json', methods=['POST'])
def upload_json():
    file = request.files['file']
    if file:
        services_json = json.load(file)
        if isinstance(services_json, list):
            services_json = [convert_dates(service) for service in services_json]

            collection.delete_many({})  # Clear the existing data
            collection.insert_many(services_json)
            flash('JSON data uploaded successfully!', 'success')
        else:
            flash('Invalid JSON format! Expected a list of services.', 'error')
    return redirect(url_for('index'))

@app.route('/upload')
def upload_page():
    return render_template('upload.html')

if __name__ == "__main__":
    schedule_checks()
    scheduler.start()
    app.run(debug=True)
