# TraceFox - Domain Intelligence Gathering

![TraceFox Logo](https://github.com/user-attachments/assets/cab6b2b8-c962-4f0d-a28d-1a61675f1a28)

## 📌 About
TraceFox is a **OSINT (Open Source Intelligence) Tool** that automates domain information gathering by fetching WHOIS data, subdomains, DNS records, technology stack, breached credentials, and more. It is optimized for **Linux** and runs multiple scans in parallel for efficiency.

---

## 🚀 Features
- **WHOIS Lookup** - Get domain registration details.
- **IP Address Resolution** - Fetch the IP address of the domain.
- **SSL Certificate Info** - Extract SSL/TLS certificate details.
- **DNS Records** - Retrieve `A`, `MX`, `CNAME`, `TXT`, and other DNS records.
- **Technology Stack Detection** - Identify web technologies used by the domain.
- **Wayback Machine History** - Fetch historical snapshots from the Internet Archive.
- **Breached Credentials Check** - Check if the domain has been exposed in data breaches.
- **Subdomain Enumeration** - Find subdomains using `crt.sh`.
- **Blacklist Check** - Verify if the domain is flagged as malicious.
- **Robots.txt & Sitemap.xml** - Retrieve these files if available.
- **Port Scanning** - Check open ports and running services.
- **Hosting & ASN Info** - Identify the hosting provider and ASN details.
- **Server Headers** - Extract server response headers.

---

## 🛠 Installation

### **Prerequisites**
- **Linux OS** (Ubuntu, Debian, Kali, etc.)
- Python 3 installed (`python3 --version` to check)

### **Step 1: Clone the Repository**
```bash
git clone https://github.com/kundandhupkar/TraceFox.git
cd TraceFox
```

### **Step 2: Install Dependencies**
Run the setup script to install all required packages and system dependencies:
```bash
python3 install.py
```
This will:
- Install Python dependencies (`requests`, `colorama`).
- Install required Linux tools (`whois`, `openssl`, `dig`, `nmap`).
- Make the tool globally accessible as `tracefox`.

### **API Key Setup**
Before using the tool, you need to add API keys for **VirusTotal** and **BuiltWith**. 

1. **VirusTotal API Key**:
   - Sign up at [VirusTotal](https://www.virustotal.com/)
   - Go to your account settings and copy your API key.
   - Add it to `config.py`:
     ```python
     VIRUS_TOTAL_API_KEY = "your_api_key_here"
     ```

2. **BuiltWith API Key**:
   - Sign up at [BuiltWith](https://builtwith.com/)
   - Retrieve your API key.
   - Add it to `config.py`:
     ```python
     BUILT_WITH_API_KEY = "your_api_key_here"
     ```

Ensure these keys are correctly set before running the tool.

---

## 🎯 Usage
### **Help Menu**
To view all available options and commands:
```bash
usage: tracefox [-h] [-d DOMAIN] [-f FILE] [-o OUTPUT] [-a] [-e EXCEPT_LIST] [--whois] [--ip] [--ssl] [--dns] [--tech] [--wayback] [--breaches] [--subdomains]
               [--blacklist] [--robomap] [--ports] [--hosting] [--headers]

Domain OSINT Tool

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain
  -f FILE, --file FILE  File containing list of domains
  -o OUTPUT, --output OUTPUT
                        Output filename (default: auto-generated)
  -a, --all             Run all functions
  -e EXCEPT_LIST, --except_list EXCEPT_LIST
                        Comma-separated list of functions to exclude when using -a
  --whois               Run whois lookup
  --ip                  Run ip lookup
  --ssl                 Run ssl lookup
  --dns                 Run dns lookup
  --tech                Run tech lookup
  --wayback             Run wayback lookup
  --breaches            Run breaches lookup
  --subdomains          Run subdomains lookup
  --blacklist           Run blacklist lookup
  --robomap             Run robomap lookup
  --ports               Run ports lookup
  --hosting             Run hosting lookup
  --headers             Run headers lookup
```


### **Run All Available Scans on a Domain**
```bash
tracefox -d example.com -a
```

### **Run Specific Information Gathering Modules**
Run WHOIS, DNS, and Subdomain enumeration:
```bash
tracefox -d example.com --whois --dns --subdomains
```

### **Exclude Specific Modules When Running All Scans**
Example: Run all scans except `wayback` and `breaches`:
```bash
tracefox -d example.com -a -e wayback,breaches
```

### **Run OSINT on Multiple Domains from a File**
```bash
tracefox -f domains.txt -a
```
(Ensure `domains.txt` contains one domain per line.)

### **Save Output to a File**
```bash
tracefox -d example.com -o report.txt
```

---

## 📂 Output Format
The tool generates structured reports in **TXT format** with organized sections for each scanned domain.

---

## ⚠️ Disclaimer
This tool is intended for **ethical security research and reconnaissance**. Use only on domains you have permission to scan. Misuse may violate laws and terms of service.

---

## 📜 License
This project is licensed under the **MIT License**.

---

## 🌟 Contributions
Contributions are welcome! Feel free to submit pull requests or report issues.

---

## 📞 Contact
For suggestions or issues, open a GitHub issue or contact me at **dhupkarkundan@gmail.com**.
