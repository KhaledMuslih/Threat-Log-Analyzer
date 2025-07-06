#  Threat Log Analyzer

A Python-based tool for analyzing SSH log files and detecting suspicious login behavior, such as multiple failed login attempts and brute-force indicators.

---

# Features

- Parses standard Linux SSH logs
- Detects failed and successful login attempts
- Flags suspicious IPs based on number of failed attempts
- Generates structured JSON report of findings

---

#  Sample Log Input (`log.txt`)

Jul  6 10:15:32 server sshd[1999]: Failed password for invalid user admin from 192.168.1.5 port 55874 ssh2
Jul  6 10:15:36 server sshd[2001]: Failed password for root from 10.10.10.1 port 55901 ssh2
Jul  6 10:15:40 server sshd[2002]: Failed password for root from 10.10.10.1 port 55902 ssh2
Jul  6 10:15:42 server sshd[2003]: Failed password for root from 10.10.10.1 port 55903 ssh2
Jul  6 10:15:35 server sshd[2000]: Accepted password for root from 192.168.1.10 port 55900 ssh2

----

{
  "failed_login_attempts": {
    "192.168.1.5": 1,
    "10.10.10.1": 3,
    "8.8.8.8": 3
  },
  "successful_logins": {
    "192.168.1.10": 1,
    "192.168.1.15": 1
  },
  "suspicious_ips": [
    "10.10.10.1",
    "8.8.8.8"
  ]
}

-----
# How to Run
1.Place your SSH log file as log.txt in the project root directory.
2.Run the analyzer script with Python 3:
python3 analyzer.py
The script will create results.json file with the summary.

-----
# Requirements
Python 3.6 or higher
No external libraries required

----
#  Developed By
Khaled Muslih
Cybersecurity Enthusiast | Interested in Offensive and Defensive Security
khaledmuslih711@gmail.com
🌍 Parrot OS | Linux | Python | Security



