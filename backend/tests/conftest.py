"""Pytest configuration and fixtures."""

import pytest
import tempfile
from pathlib import Path


@pytest.fixture
def temp_repo():
    """Create a temporary repository for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)
        # Create basic structure
        (repo_path / "src").mkdir(exist_ok=True)
        yield repo_path


@pytest.fixture
def vulnerable_python_code():
    """Sample vulnerable Python code with multiple issues."""
    return '''
import hashlib
from flask import Flask, request

app = Flask(__name__)

# Issue 1: Hardcoded secret
API_KEY = "sk_live_51234567890abcdef"
DATABASE_URL = "postgres://admin:secretpassword@db.example.com:5432/mydb"

@app.route("/search")
def search():
    # Issue 2: SQL Injection
    query_param = request.args.get('q')
    query = f"SELECT * FROM users WHERE name = '{query_param}'"
    db.execute(query)
    
    # Issue 3: Weak cryptography
    password_hash = hashlib.md5(request.form.get('password').encode()).hexdigest()
    
    return "OK"

def unsafe_concat():
    user_id = request.args.get('id')
    # Another SQL injection variant
    query = "SELECT * FROM products WHERE id = " + user_id
    db.query(query)
'''


@pytest.fixture
def vulnerable_js_code():
    """Sample vulnerable JavaScript code."""
    return '''
const express = require('express');
const crypto = require('crypto');
const app = express();

// Hardcoded secrets
const stripe_key = "sk_test_abcdef1234567890";
const github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";

app.get('/api/users', (req, res) => {
    // SQL Injection
    const userId = req.query.id;
    const sql = `SELECT * FROM users WHERE id = ${userId}`;
    db.query(sql);
    
    // Weak crypto
    const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
    
    res.send('OK');
});

function buildQuery(input) {
    // Another SQL injection
    return "SELECT * FROM table WHERE id = '" + input + "'";
}
'''


@pytest.fixture
def clean_code():
    """Sample safe code with no vulnerabilities."""
    return '''
import os
from flask import Flask
from werkzeug.security import generate_password_hash
import hashlib

app = Flask(__name__)

# Secrets from environment - good practice
API_KEY = os.environ.get('API_KEY')
DATABASE_URL = os.environ.get('DATABASE_URL')

@app.route("/search")
def search(q):
    # Using parameterized query - safe
    query = "SELECT * FROM users WHERE name = %s"
    user_id = request.args.get('id')
    db.execute(query, [user_id])
    
    # Using bcrypt - good practice
    password_hash = generate_password_hash(request.form.get('password'))
    
    return "OK"
'''
