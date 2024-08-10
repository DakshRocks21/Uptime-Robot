from flask import Flask, render_template, request, redirect, url_for, jsonify, Response, flash
from pymongo import MongoClient
import datetime
import uuid
import requests
import json

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for flash messages

client = MongoClient('mongodb://localhost:27017/')
db = client['uptime_robot']
collection = db['services']

@app.route('/')
def index():
    services = list(collection.find())
    return render_template('index.html', services=services)

@app.route('/add', methods=['POST'])
def add_service():
    name = request.form.get('name')
    url = request.form.get('url')
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
        "request_type": request_type,
        "response_type": response_type,
        "response": response
    }
    collection.insert_one(service)
    return redirect(url_for('index'))

@app.route('/edit/<service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    service = collection.find_one({"id": service_id})
    if request.method == 'POST':
        name = request.form.get('name')
        url = request.form.get('url')
        frequency = int(request.form.get('frequency'))
        request_type = request.form.get('request_type')
        response_type = request.form.get('response_type')
        response = request.form.get('response')

        collection.update_one(
            {"id": service_id},
            {"$set": {
                "name_of_service": name,
                "url": url,
                "frequency": frequency,
                "request_type": request_type,
                "response_type": response_type,
                "response": response
            }}
        )
        return redirect(url_for('index'))
    return render_template('edit.html', service=service)

@app.route('/delete/<service_id>', methods=['POST'])
def delete_service(service_id):
    collection.delete_one({"id": service_id})
    return redirect(url_for('index'))

@app.route('/run_checks')
def run_checks():
    services = collection.find()
    for service in services:
        check_service(service)
    return redirect(url_for('index'))

@app.route('/dump_json')
def dump_json():
    services = list(collection.find({}, {'_id': False}))  # Exclude MongoDB's internal '_id' field
    return Response(
        json.dumps(services, default=str, indent=4), 
        mimetype='application/json',
        headers={"Content-Disposition": "attachment;filename=services.json"}
    )

@app.route('/upload_json', methods=['GET', 'POST'])
def upload_json():
    if request.method == 'POST':
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
    return render_template('upload.html')

def check_service(service):
    url = service['url']
    request_type = service['request_type']
    expected_response = service['response']

    try:
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

        check_result = {
            "time": datetime.datetime.now(),
            "response": result,
            "url_pinged": url,
            "status": status
        }

        collection.update_one(
            {"id": service['id']},
            {"$set": {"last_checked": datetime.datetime.now()},
             "$push": {"results": check_result}}
        )
        print(f"Service {service['name_of_service']} checked. Status: {status}")

    except Exception as e:
        print(f"Error checking service {service['name_of_service']}: {str(e)}")

if __name__ == "__main__":
    app.run(debug=True)
