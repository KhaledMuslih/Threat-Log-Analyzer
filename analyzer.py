import re
import json
from collections import defaultdict

# Log files
LOG_FILE = 'log.txt'
OUTPUT_FILE = 'results.json'

# Suspicious patterns
failed_login_pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
successful_login_pattern = re.compile(r"Accepted password for .* from (\d+\.\d+\.\d+\.\d+)")

# Statistics per IP
failed_logins = defaultdict(int)
successful_logins = defaultdict(int)

with open(LOG_FILE, 'r') as f:
    for line in f:
        if match := failed_login_pattern.search(line):
            ip = match.group(1)
            failed_logins[ip] += 1
        elif match := successful_login_pattern.search(line):
            ip = match.group(1)
            successful_logins[ip] += 1

# Extract IPs with 3 or more failed attempts (brute-force suspect)
suspicious_ips = [ip for ip, count in failed_logins.items() if count >= 3]

# Build report
report = {
    "failed_login_attempts": dict(failed_logins),
    "successful_logins": dict(successful_logins),
    "suspicious_ips": suspicious_ips
}

# Save result
with open(OUTPUT_FILE, 'w') as f:
    json.dump(report, f, indent=4)

print("✅ Log analysis complete. Results saved to:", OUTPUT_FILE)

