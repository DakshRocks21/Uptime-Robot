from pymongo import MongoClient
import datetime
import requests
import uuid

client = MongoClient('mongodb://localhost:27017/') 
db = client['uptime_robot']
collection = db['services']

def add_service(name, url, frequency, request_type='GET', response_type='STATUS CODE', response=None):
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
    print(f"Service {name} added successfully.")

def check_service(service):
    url = service['url']
    request_type = service['request_type']
    expected_response = service['response']

    if request_type == 'GET':
        response = requests.get(url)
    elif request_type == 'POST':
        response = requests.post(url)
    else:
        print("Invalid request type.", service['request_type'])
        return
    
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
    


def run_checks():
    services = collection.find()
    for service in services:
        check_service(service)

def menu():
    while True:
        print("1. Add Service")
        print("2. Run Checks")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            name = input("Enter service name: ")
            url = input("Enter service URL: ")
            frequency = int(input("Enter frequency (in minutes): "))
            request_type = input("Enter request type (GET/POST): ")
            response_type = input("Enter response type (STATUS CODE/JSON/other): ")
            response = input("Enter expected response: ")

            add_service(name, url, frequency, request_type, response_type, response)
        elif choice == "2":
            run_checks()
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()
