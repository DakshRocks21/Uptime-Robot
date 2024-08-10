from flask import Flask, render_template, request, redirect, url_for, jsonify, Response, flash
from pymongo import MongoClient
import datetime
import uuid
import requests
import json
import socket
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for flash messages

client = MongoClient('mongodb://localhost:27017/')
db = client['uptime_robot']
collection = db['services']

# Scheduler
scheduler = BackgroundScheduler()

def check_service(service):
    url = service['url']
    port = service.get('port')  # Retrieve the port if it exists
    request_type = service['request_type']
    expected_response = service['response']

    try:
        # Check if port is specified
        if port:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)  # Set timeout to 10 seconds
                result = sock.connect_ex((url, port))
                status = "UP" if result == 0 else "DOWN"
                response = f"Port {port} is {'open' if result == 0 else 'closed'}"
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

            status = "UP" if str(result) == str(expected_response) else "DOWN"

        next_check_time = datetime.datetime.now() + datetime.timedelta(minutes=service['frequency'])

        check_result = {
            "time": datetime.datetime.now(),
            "response": response if port else result,
            "url_pinged": f"{url}:{port}" if port else url,
            "status": status,
            "next_check": next_check_time  # Ensure next_check is set
        }

        collection.update_one(
            {"id": service['id']},
            {"$set": {"last_checked": datetime.datetime.now()},
             "$push": {"results": check_result}}
        )
        print(f"Service {service['name_of_service']} checked. Status: {status}")

    except Exception as e:
        print(f"Error checking service {service['name_of_service']}: {str(e)}")

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

@app.route('/events')
def events():
    services = list(collection.find())
    return render_template('events.html', services=services)

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

@app.route('/add', methods=['POST'])
def add_service():
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

@app.route('/edit/<service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    service = collection.find_one({"id": service_id})
    print("Clicked")
    if request.method == 'POST':
        name = request.form.get('name')
        url = request.form.get('url')
        port = request.form.get('port')
        frequency = int(request.form.get('frequency'))
        service_type = request.form.get('service_type')
        print(f"Submitted data: name={name}, url={url}, port={port}, frequency={frequency}, service_type={service_type}")

        update_fields = {
            "name_of_service": name,
            "url": url,
            "frequency": frequency,
        }

        if service_type == 'port':
            update_fields['port'] = int(port) if port else None
            update_fields['request_type'] = None
            update_fields['response_type'] = None
            update_fields['response'] = None
        else:
            update_fields['port'] = None
            update_fields['request_type'] = request.form.get('request_type')
            update_fields['response_type'] = request.form.get('response_type')
            update_fields['response'] = request.form.get('response')

        collection.update_one(
            {"id": service_id},
            {"$set": update_fields}
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

@app.route('/upload_json', methods=['POST'])
def upload_json():
    file = request.files['file']
    if file:
        services_json = json.load(file)
        if isinstance(services_json, list):
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
