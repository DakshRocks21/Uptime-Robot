from flask import Flask, render_template, request, redirect, url_for
from pymongo import MongoClient
import datetime
import uuid
import requests

app = Flask(__name__)


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

@app.route('/run_checks')
def run_checks():
    services = collection.find()
    for service in services:
        check_service(service)
    return redirect(url_for('index'))

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
