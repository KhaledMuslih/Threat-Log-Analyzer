import re
import json
import requests
from collections import defaultdict

# Function to get IP information from ip-api.com
def get_ip_info(ip):
    try:
        # Skip private IP addresses
        if ip.startswith("192.168") or ip.startswith("10."):
            return {"ip": ip, "note": "Private IP - no lookup"}
        
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        return {
            "ip": ip,
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org")
        }
    except:
        return {"ip": ip, "error": "Lookup failed"}

# Log file paths
LOG_FILE = 'log.txt'
OUTPUT_FILE = 'results.json'

# Patterns for SSH login events
failed_login_pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
successful_login_pattern = re.compile(r"Accepted password for .* from (\d+\.\d+\.\d+\.\d+)")

# Data collectors
failed_logins = defaultdict(int)
successful_logins = defaultdict(int)

# Read and analyze the log file
with open(LOG_FILE, 'r') as f:
    for line in f:
        if match := failed_login_pattern.search(line):
            ip = match.group(1)
            failed_logins[ip] += 1
        elif match := successful_login_pattern.search(line):
            ip = match.group(1)
            successful_logins[ip] += 1

# Identify suspicious IPs and get their details
raw_suspicious_ips = [ip for ip, count in failed_logins.items() if count >= 3]
suspicious_ips_info = [get_ip_info(ip) for ip in raw_suspicious_ips]

# Build the final report
report = {
    "failed_login_attempts": dict(failed_logins),
    "successful_logins": dict(successful_logins),
    "suspicious_ips": suspicious_ips_info
}

# Save the report as JSON
with open(OUTPUT_FILE, 'w') as f:
    json.dump(report, f, indent=4)

print("Log analysis complete. Results saved to:", OUTPUT_FILE)
