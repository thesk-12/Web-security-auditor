#!/usr/bin/env python3
"""
Automated Web Security Auditor
Audits web applications for missing/insecure HTTP headers and CORS vulnerabilities.
"""

import argparse
import json
import sys
from urllib.parse import urlparse
import requests
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Recommended security headers and their security rationale
RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections to prevent man-in-the-middle attacks.",
        "severity": "HIGH",
    },
    "Content-Security-Policy": {
        "description": "Prevents Cross-Site Scripting (XSS) and code injection attacks.",
        "severity": "HIGH",
    },
    "X-Frame-Options": {
        "description": "Prevents Clickjacking attacks by controlling framing.",
        "severity": "MEDIUM",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing (should be 'nosniff').",
        "severity": "LOW",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is included with requests.",
        "severity": "LOW",
    },
    "Permissions-Policy": {
        "description": "Controls browser features/APIs (camera, microphone, geolocation).",
        "severity": "LOW",
    },
}

SENSITIVE_INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]


class WebSecurityScanner:
    def __init__(self, target_url: str, timeout: int = 10):
        if not target_url.startswith(("http://", "https://")):
            self.target_url = "https://" + target_url
        else:
            self.target_url = target_url
        self.timeout = timeout
        self.results = {
            "target": self.target_url,
            "security_headers": {"missing": [], "present": []},
            "information_disclosure": [],
            "cors_issues": [],
        }

    def log(self, level: str, message: str):
        if level == "INFO":
            print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")
        elif level == "SUCCESS":
            print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")
        elif level == "WARNING":
            print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
        elif level == "VULN":
            print(f"{Fore.RED}[CRITICAL/HIGH] {message}{Style.RESET_ALL}")

    def audit_headers(self, response_headers: dict):
        self.log("INFO", "Auditing HTTP response headers...")
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        for header, meta in RECOMMENDED_HEADERS.items():
            h_key = header.lower()
            if h_key in headers_lower:
                val = headers_lower[h_key]
                self.results["security_headers"]["present"].append(
                    {"header": header, "value": val}
                )
                self.log("SUCCESS", f"Header Present: {header} = {val}")
            else:
                self.results["security_headers"]["missing"].append(
                    {"header": header, "severity": meta["severity"], "description": meta["description"]}
                )
                self.log("WARNING", f"Missing Security Header: {header} [{meta['severity']}]")

        for info_header in SENSITIVE_INFO_HEADERS:
            h_key = info_header.lower()
            if h_key in headers_lower:
                val = headers_lower[h_key]
                self.results["information_disclosure"].append(
                    {"header": info_header, "value": val}
                )
                self.log("WARNING", f"Information Disclosure: {info_header}: {val}")

    def audit_cors(self):
        self.log("INFO", "Testing for CORS misconfigurations...")
        test_origins = [
            ("Arbitrary Origin Reflection", "https://attacker-domain.evil"),
            ("Null Origin Reflection", "null"),
            ("Pre-Domain Bypass", f"https://{urlparse(self.target_url).netloc}.evil.com"),
        ]

        for test_name, test_origin in test_origins:
            headers = {"Origin": test_origin, "User-Agent": "SecurityScanner/1.0"}
            try:
                res = requests.get(self.target_url, headers=headers, timeout=self.timeout)
                acao = res.headers.get("Access-Control-Allow-Origin")
                acac = res.headers.get("Access-Control-Allow-Credentials")

                if acao:
                    # Check wildcard with credentials
                    if acao == "*" and acac and acac.lower() == "true":
                        vuln = {
                            "type": "CORS Misconfiguration",
                            "severity": "CRITICAL",
                            "details": "Wildcard '*' origin with Allow-Credentials enabled.",
                            "origin_sent": test_origin,
                            "acao": acao,
                            "acac": acac,
                        }
                        self.results["cors_issues"].append(vuln)
                        self.log("VULN", f"CORS Flaw: Wildcard with credentials allowed!")

                    # Check arbitrary origin reflection
                    elif acao == test_origin:
                        severity = "CRITICAL" if acac and acac.lower() == "true" else "HIGH"
                        vuln = {
                            "type": f"CORS Flaw: {test_name}",
                            "severity": severity,
                            "details": f"Server reflected arbitrary origin '{test_origin}' (Credentials: {acac}).",
                            "origin_sent": test_origin,
                            "acao": acao,
                            "acac": acac,
                        }
                        self.results["cors_issues"].append(vuln)
                        self.log("VULN", f"{test_name} detected! Origin: {test_origin} | Credentials: {acac}")
            except requests.RequestException as e:
                self.log("WARNING", f"Failed CORS probe for '{test_origin}': {e}")

    def run(self, output_file: str = None):
        print(f"\n{Fore.MAGENTA}=== Running Web Security Auditor on {self.target_url} ==={Style.RESET_ALL}\n")
        try:
            resp = requests.get(
                self.target_url,
                timeout=self.timeout,
                headers={"User-Agent": "SecurityScanner/1.0"},
                allow_redirects=True,
            )
            self.audit_headers(resp.headers)
            print()
            self.audit_cors()

            if output_file:
                with open(output_file, "w") as f:
                    json.dump(self.results, f, indent=4)
                print(f"\n{Fore.GREEN}[✔] Scan complete. Report saved to {output_file}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.GREEN}[✔] Scan completed successfully.{Style.RESET_ALL}")

        except requests.exceptions.RequestException as e:
            self.log("VULN", f"Failed to connect to target: {e}")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Audit web endpoints for missing security headers and CORS misconfigurations."
    )
    parser.add_argument("url", help="Target URL (e.g., https://example.com or http://localhost:5000)")
    parser.add_argument("-o", "--output", help="Output results to a JSON file", default="report.json")
    parser.add_argument("-t", "--timeout", help="HTTP timeout in seconds", type=int, default=10)

    args = parser.parse_args()
    scanner = WebSecurityScanner(args.url, timeout=args.timeout)
    scanner.run(output_file=args.output)


if __name__ == "__main__":
    main()
