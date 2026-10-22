#!/usr/bin/env python3
"""
Intentionally Vulnerable Test Server for CORS & Header Audits.
Run locally to test and demonstrate scanner functionality.
"""

from flask import Flask, jsonify, request, make_response

app = Flask(__name__)

@app.route("/")
def home():
    origin = request.headers.get("Origin")
    resp = make_response(jsonify({
        "status": "success",
        "message": "Welcome to the Vulnerable Lab API",
        "user_balance": 15000
    }))

    # Vulnerability 1: Leaking server runtime version
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    resp.headers["X-Powered-By"] = "Express/NodeJS-Mock"

    # Vulnerability 2: Reflective CORS misconfiguration (trusts any incoming origin)
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"

    # Notice: Security headers (HSTS, CSP, X-Frame-Options) are intentionally omitted!
    return resp

if __name__ == "__main__":
    print("[*] Starting test server on http://127.0.0.1:5000")
    app.run(port=5000, debug=True)
