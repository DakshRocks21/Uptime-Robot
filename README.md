# Uptime Robot Clone - Flask Application

> Powers uptime.dakshthapar.com

This project is a custom Uptime Robot clone built using Flask, MongoDB, Celery, Redis, and Flask-Login.

## Features

- **User Authentication and Management:**
  - Sign up, login, and logout functionality with email/password.
  - Two-Factor Authentication (2FA) setup using Google Authenticator.
  - User roles: Admin and Regular users.
  - Admin features: Approve, delete, or edit users; manage server settings.
  
- **Service Monitoring:**
  - Monitor uptime for websites and services using HTTP/HTTPS GET/POST requests.
  - Support for custom response types (Status Code, JSON, Text).
  - Set up monitoring intervals and webhooks for alerts.
  - Manual checks and viewing service history and statistics.
  - Export and import service configurations via JSON.

- **Notifications:**
  - Email notifications for service downtimes.
  - Webhook support for custom alert integrations.

- **Security Features:**
  - Session protection and secure cookies.
  - Rate limiting and cooldown periods for 2FA attempts.

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/uptime-robot-clone.git
   cd uptime-robot-clone
   ```
2. **Set Up a Virtual Environment:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate  # On Windows use `venv\Scripts\activate`
  ```
3. **Install Dependencies:**
  ```bash
  pip install -r requirements.txt
  ```
4. **Set Up MongoDB:**
  - Make sure you have MongoDB installed and running on your local machine or on a cloud service like MongoDB Atlas.
  - Update the MongoDB connection string in the app.
5. **Set Up Redis:**
  - Install Redis on your system or use a cloud Redis service.
  - Update the Redis connection string in the app.
6. **Configure Environment Variables:**
  - Create a .env file in the root directory. (use `.example.env`)
7. **Set Up Celery:**
  - Start a Celery worker in a separate terminal:
  ```bash
    celery -A celery_worker.celery worker --loglevel=info
  ```
8. **Run the Flask Application:**
