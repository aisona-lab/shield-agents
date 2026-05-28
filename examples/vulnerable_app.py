"""
Vulnerable Example Application for Shield Agents.

This file contains intentional security vulnerabilities for testing.
DO NOT use this code in production!
"""

import os
import pickle
import hashlib
import random
import subprocess
import sqlite3
import ssl
import yaml
from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)

# --- Hardcoded Secrets ---
DB_PASSWORD = "SuperSecret123!"
API_KEY = "PLACEHOLDER_STRIPE_KEY_FOR_TESTING_ONLY"
AWS_ACCESS_KEY = "PLACEHOLDER_AWS_KEY_FOR_TESTING_ONLY"
AWS_SECRET_KEY = "PLACEHOLDER_AWS_SECRET_FOR_TESTING_ONLY"


# --- SQL Injection ---
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def search_products(term):
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return cursor.fetchall()


# --- Command Injection ---
def ping_host(host):
    os.system(f"ping -c 4 {host}")


def convert_image(input_file):
    subprocess.call(f"convert {input_file} output.png", shell=True)


# --- Insecure Deserialization ---
def load_session(data):
    return pickle.loads(data)


def load_config(content):
    return yaml.load(content)


# --- Weak Cryptography ---
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def generate_token():
    return str(random.randint(100000, 999999))


# --- SSL Verification Disabled ---
def fetch_data(url):
    import requests
    return requests.get(url, verify=False)


# --- Path Traversal ---
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    with open('/var/files/' + filename, 'r') as f:
        return f.read()


# --- XSS / SSTI ---
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)


# --- SSRF ---
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    import requests
    return requests.get(url).text


if __name__ == "__main__":
    context = ssl._create_unverified_context()
    app.run(debug=True, ssl_context=context)
