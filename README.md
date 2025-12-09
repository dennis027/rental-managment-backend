# Rental Management Backend

Django backend for a rental management system.

## Project Overview

This project provides backend APIs for managing properties, tenants, rent, and payments.

## Screenshots

### System Architecture
![architecture](./images/architecture.png)

### API Flow
![api-flow](./images/api-flow.png)

### Database Diagram
![database-diagram](./images/database-diagram.png)

(Add your actual images in an /images/ folder)

## Installation

Clone the repository:
```
git clone https://github.com/dennis027/rental-managment-backend.git
cd rental-managment-backend
```

Create a virtual environment:
```
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:
```
pip install -r requirements.txt
```

Run migrations:
```
python manage.py migrate
```

Start server:
```
python manage.py runserver
```

## Environment Variables

Create a .env file for database credentials and other settings.

## Project Structure

```
manage.py
requirements.txt
app/
projects/
images/
```

## Usage

Default local API URL:
```
http://127.0.0.1:8000/
```

## Notes

Update settings before running the project.
