from flask import Flask, request
import subprocess
import hashlib

app = Flask(__name__)

# Intentional vulnerability 1: hardcoded secret
SECRET_KEY = "supersecretpassword123"
DB_PASSWORD = "admin123"

@app.route('/')
def index():
    return "Hello from DevSecOps lab!"

# Intentional vulnerability 2: command injection
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()

# Intentional vulnerability 3: weak hashing
@app.route('/hash')
def hash_password():
    password = request.args.get('password', '')
    return hashlib.md5(password.encode()).hexdigest()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
