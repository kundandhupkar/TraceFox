import argparse
import json
import requests
import subprocess
import socket
import xml.dom.minidom
import config
import concurrent.futures
from colorama import Fore, Style
from datetime import datetime

# Function to validate the domain
def validate_domain(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

# Function to fetch WHOIS information
def get_whois_lookup(domain):
    print(Fore.YELLOW + f"[INFO] Fetching WHOIS information for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        result = subprocess.check_output(["whois", domain]).decode("utf-8")
        print(Fore.GREEN + f"[INFO] Completed: Fetching WHOIS information for {domain}.\n" + Style.RESET_ALL)
        return result

    except Exception as e:
        return Fore.RED + f"Error: {e}" + Style.RESET_ALL

# Function to get IP address of the domain
def get_ip(domain):
    print(Fore.YELLOW + f"[INFO] Fetching IP address for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        result = socket.gethostbyname(domain)
        print(Fore.GREEN + f"[INFO] Completed: Fetching IP address for {domain}.\n" + Style.RESET_ALL)
        return result

    except Exception as e:
        return Fore.RED + str(e) + Style.RESET_ALL

# Function to fetch SSL certificate details
def get_ssl_info(domain):
    print(Fore.YELLOW + f"[INFO] Fetching SSL certificate details for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        # Run OpenSSL with timeout
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{domain}:443", "-servername", domain, "-showcerts"],
            capture_output=True,
            text=True,
            timeout=30  # Set a timeout of 30 seconds
        )
        print(Fore.GREEN + f"[INFO] Completed: Fetching SSL certificate details for {domain}.\n" + Style.RESET_ALL)
        return result.stdout
    except subprocess.TimeoutExpired:
        return Fore.RED + f"Error: SSL scan timed out for {domain}" + Style.RESET_ALL
    except Exception as e:
        return Fore.RED + f"Error: {e}" + Style.RESET_ALL

# Function to fetch DNS records
def get_dns_records(domain):
    print(Fore.YELLOW + f"[INFO] Fetching DNS records for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        result = subprocess.run(["dig", domain, "ANY"], capture_output=True, text=True)
        print(Fore.GREEN + f"[INFO] Completed: Fetching DNS records for {domain}.\n" + Style.RESET_ALL)
        return result.stdout
    except Exception as e:
        return Fore.RED + str(e) + Style.RESET_ALL

# Function to fetch tech stack
def get_technology_stack(domain):
    print(Fore.YELLOW + f"[INFO] Fetching technology stack used for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        url = f"https://api.builtwith.com/free1/api.json?KEY={config.BUILT_WITH_API_KEY}&LOOKUP={domain}"
        response = requests.get(url)

        if response.status_code == 200:
            try:
                raw_data = response.json()
                cleaned_data = {}

                # Extract technologies from the response
                if "groups" in raw_data:
                    for group in raw_data["groups"]:
                        tech_category = group.get("name")  # Main category like 'javascript', 'hosting', etc.
                        tech_names = [
                            category["name"] for category in group.get("categories", []) if "name" in category
                        ]

                        if tech_names:  # Only add if there are technologies
                            cleaned_data[tech_category] = tech_names
                print(Fore.GREEN + f"[INFO] Completed: Fetching technology stack used for {domain}.\n" + Style.RESET_ALL)
                return cleaned_data if cleaned_data else {"Error": "No technology data found"}

            except ValueError:
                return Fore.RED + {"Error": "Failed to parse JSON response"} + Style.RESET_ALL

        return Fore.RED + {"Error": f"API request failed with status code {response.status_code}"} + Style.RESET_ALL

    except requests.exceptions.RequestException as e:
        return Fore.RED + {"Error": str(e)} + Style.RESET_ALL

# Function to fetch Wayback Machine history
def get_wayback_history(domain):
    print(Fore.YELLOW + f"[INFO] Fetching wayback machine history for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        # Make the request to the Wayback Machine API
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json"
        response = requests.get(url)

        # Check if the response was successful (HTTP status code 200)
        if response.status_code == 200:
            try:
                # Parse and return the JSON response
                result = response.json()
                print(Fore.GREEN + f"[INFO] Completed: Fetching wayback history for {domain}.\n" + Style.RESET_ALL)
                return result

            except ValueError:
                return Fore.RED + "Error: Failed to parse JSON response" + Style.RESET_ALL
        else:
            return Fore.RED + f"Error: API request failed with status code {response.status_code}" + Style.RESET_ALL

    except requests.exceptions.RequestException as e:
        # Handle any network-related errors or issues with the request
        return Fore.RED + f"Error: {e}" + Style.RESET_ALL

# Function to check breached credentials
def check_breaches(domain):
    print(Fore.YELLOW + f"[INFO] Fetching breached data for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        # Send request to Have I Been Pwned API
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
        response = requests.get(url)

        # Check if the response was successful (HTTP status code 200)
        if response.status_code == 200:
            try:
                # Parse and return the JSON response
                result = response.json()
                print(Fore.GREEN + f"[INFO] Completed: Fetching breached data for {domain}.\n" + Style.RESET_ALL)
                return result

            except ValueError:
                return Fore.RED + "Error: Failed to parse JSON response" + Style.RESET_ALL
        elif response.status_code == 404:
            return Fore.RED + f"Error: No breaches found for domain {domain}." + Style.RESET_ALL
        elif response.status_code == 403:
            return Fore.RED + "Error: Access forbidden. You may need an API key." + Style.RESET_ALL
        else:
            return Fore.RED + f"Error: API request failed with status code {response.status_code}" + Style.RESET_ALL

    except requests.exceptions.RequestException as e:
        # Handle network-related errors (e.g., timeout, connection errors)
        return Fore.RED + f"Error: {e}" + Style.RESET_ALL

# Function to find subdomains
def get_subdomains(domain):
    print(Fore.YELLOW + f"[INFO] Fetching subdomains for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        # Send a GET request to the crt.sh API
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url)

        # Check if the response was successful (HTTP status code 200)
        if response.status_code == 200:
            try:
                # Parse the JSON response and extract subdomains
                subdomains = set()
                for entry in response.json():
                    subdomains.add(entry['name_value'])
                print(Fore.GREEN + f"[INFO] Completed: Fetching subdomains for {domain}.\n" + Style.RESET_ALL)
                return list(subdomains)
            except ValueError:
                return Fore.RED + "Error: Failed to parse JSON response" + Style.RESET_ALL
        else:
            return Fore.RED + f"Error: API request failed with status code {response.status_code}" + Style.RESET_ALL

    except requests.exceptions.RequestException as e:
        # Handle network-related errors (e.g., timeout, connection issues)
        return Fore.RED + f"Error: {e}" + Style.RESET_ALL

# Function to check domain blacklist status
def check_blacklist(domain):
    print(Fore.YELLOW + f"[INFO] Fetching domain blacklist status for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        # Get the API key from config.py
        api_key = config.VIRUS_TOTAL_API_KEY
        headers = {
            'x-apikey': api_key  # Include the API key in the headers
        }

        # Send the GET request to the VirusTotal API
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=headers)

        # Check if the response was successful (HTTP status code 200)
        if response.status_code == 200:
            try:
                # Return the JSON response if successful
                result = response.json()
                print(Fore.GREEN + f"[INFO] Completed: Fetching blacklist status for {domain}.\n" + Style.RESET_ALL)
                return result

            except ValueError:
                return Fore.RED + "Error: Failed to parse JSON response" + Style.RESET_ALL
        elif response.status_code == 403:
            return Fore.RED + "Error: Forbidden, you may need an API key or permission." + Style.RESET_ALL
        elif response.status_code == 404:
            return Fore.RED + f"Error: Domain {domain} not found in VirusTotal's database." + Style.RESET_ALL
        else:
            return Fore.RED + f"Error: API request failed with status code {response.status_code}" + Style.RESET_ALL

    except requests.exceptions.RequestException as e:
        # Handle any network-related errors (timeouts, connection issues, etc.)
        return Fore.RED + f"Error: {e}" + Style.RESET_ALL

#Function to fetch robots.txt and sitemap.xml
def get_robots_sitemap(domain):
    print(Fore.YELLOW + f"[INFO] Fetching robots.txt and sitemap.xml for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        robots_url = f"https://{domain}/robots.txt"
        sitemap_url = f"https://{domain}/sitemap.xml"

        robots_response = requests.get(robots_url)
        sitemap_response = requests.get(sitemap_url)

        # Process robots.txt with proper formatting
        if robots_response.status_code == 200:
            robots = robots_response.text.strip().splitlines()  # Convert to list
        else:
            robots = [f"Error: robots.txt not found (status code: {robots_response.status_code})"]

        # Process sitemap.xml with proper XML formatting
        if sitemap_response.status_code == 200:
            try:
                parsed_xml = xml.dom.minidom.parseString(sitemap_response.text)
                sitemap = parsed_xml.toprettyxml(indent="  ").splitlines()  # Convert to list
            except Exception:
                sitemap = sitemap_response.text.strip().splitlines()  # If not valid XML, return raw content as list
        else:
            sitemap = [f"Error: sitemap.xml not found (status code: {sitemap_response.status_code})"]

        print(Fore.GREEN + f"[INFO] Completed: Fetching robots.txt and sitemap.xml for {domain}.\n" + Style.RESET_ALL)
        return {
            "robots.txt": robots,
            "sitemap.xml": sitemap
        }

    except requests.exceptions.RequestException as e:
        return Fore.RED + {"Error": str(e)} + Style.RESET_ALL


# Function to check open ports and running services
def scan_ports(domain):
    print(Fore.YELLOW + f"[INFO] Checking open ports & services for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        result = subprocess.run(["nmap", "-Pn", "--top-ports 1000", domain], capture_output=True, text=True)
        print(Fore.GREEN + f"[INFO] Completed: Checking open ports & services for {domain}.\n" + Style.RESET_ALL)
        return result.stdout
    except Exception as e:
        return Fore.RED + str(e) + Style.RESET_ALL

# Function to fetch hosting provider and ASN
def get_hosting_asn_info(domain):
    print(Fore.YELLOW + f"[INFO] Fetching hosting information for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        # Step 1: Resolve the domain to an IP address
        ip_address = socket.gethostbyname(domain)

        # Step 2: Use IPinfo.io to fetch ASN and hosting info
        ipinfo_url = f"https://ipinfo.io/{ip_address}/json"
        response = requests.get(ipinfo_url)

        # Step 3: Check if the response was successful
        if response.status_code == 200:
            data = response.json()

            # Extract ASN from the "org" field
            org = data.get("org", "N/A")  # Example: "AS15169 Google LLC"
            asn = org.split()[0] if org.startswith("AS") else "N/A"  # Extract "AS15169"
            hosting_provider = " ".join(org.split()[1:]) if org.startswith("AS") else org  # Remove AS part

            # Cleaned-up hosting info
            hosting_info = {
                "ip": data.get("ip", "N/A"),
                "hostname": data.get("hostname", "N/A"),
                "city": data.get("city", "N/A"),
                "region": data.get("region", "N/A"),
                "country": data.get("country", "N/A"),
                "asn": asn,  # Now correctly extracted
                "org": hosting_provider  # Hosting provider without ASN
            }
            print(Fore.GREEN + f"[INFO] Completed: Fetching hosting information for {domain}.\n" + Style.RESET_ALL)
            return hosting_info
        else:
            return Fore.RED + {"Error": f"Failed to fetch data from IPinfo (status code: {response.status_code})"} + Style.RESET_ALL

    except socket.gaierror:
        return Fore.RED + {"Error": f"Could not resolve domain {domain} to an IP address."} + Style.RESET_ALL

    except requests.exceptions.RequestException as e:
        return Fore.RED + {"Error": str(e)} + Style.RESET_ALL

# Function to fetch server headers
def get_server_headers(domain):
    print(Fore.YELLOW + f"[INFO] Fetching server headers for {domain}..." + Style.RESET_ALL, flush=True)
    try:
        headers_info = {}

        # Try HTTPS first
        https_url = f"https://{domain}"
        https_response = requests.get(https_url, timeout=10)

        if https_response.status_code == 200:
            headers_info["Protocol"] = "HTTPS"
            headers_info["Headers"] = dict(https_response.headers)
        else:
            # Try HTTP if HTTPS fails
            http_url = f"http://{domain}"
            http_response = requests.get(http_url, timeout=10)

            if http_response.status_code == 200:
                headers_info["Protocol"] = "HTTP"
                headers_info["Headers"] = dict(http_response.headers)
            else:
                return Fore.RED + {"Error": f"Unable to fetch headers (status code: {https_response.status_code if https_response else http_response.status_code})"} + Style.RESET_ALL

        print(Fore.GREEN + f"[INFO] Completed: Fetching server headers for {domain}.\n" + Style.RESET_ALL)
        return headers_info

    except requests.exceptions.RequestException as e:
        return Fore.RED + {"Error": str(e)} + Style.RESET_ALL

# Function for Report Generation
def report_generation(domain, data, output_filename=None):
    print(Fore.YELLOW + f"[INFO] Creating a report for {domain}..." + Style.RESET_ALL, flush=True)
    filename = output_filename if output_filename else f"osint_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, "a") as f:
        max_width = max(len(section) for section in data.keys()) + 6  # Adjust padding
        for section, content in data.items():
            box_width = max_width + 10  # Extra padding for uniformity
            border_line = "█" * box_width
            section_line = f"█  {section.upper().center(box_width - 6)}  █"

            f.write("\n" + "=" * (box_width + 4) + "\n")  # Top separator
            f.write(border_line + "\n")
            f.write(section_line + "\n")
            f.write(border_line + "\n")
            f.write("=" * (box_width + 4) + "\n\n")  # Bottom separator

            if isinstance(content, dict) or isinstance(content, list):
                f.write(json.dumps(content, indent=4) + "\n")  # Pretty-print JSON data
            else:
                f.write(f"{content}\n")

    print(f"Report saved as {filename}")

# Function for processing domains
def process_domains(domains, args):
    all_functions = {
        "whois": get_whois_lookup,
        "ip": get_ip,
        "ssl": get_ssl_info,
        "dns": get_dns_records,
        "tech": get_technology_stack,
        "wayback": get_wayback_history,
        "breaches": check_breaches,
        "subdomains": get_subdomains,
        "blacklist": check_blacklist,
        "robomap": get_robots_sitemap,
        "ports": scan_ports,
        "hosting": get_hosting_asn_info,
        "headers": get_server_headers
    }

    selected_functions = list(all_functions.keys()) if args.all else [
        key for key in all_functions.keys() if getattr(args, key, False)
    ]

    if args.except_list:
        excluded_functions = args.except_list.split(',')
        selected_functions = [func for func in selected_functions if func in all_functions and func not in excluded_functions]

    # Limit the number of concurrent domains
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.MAX_DOMAINS) as domain_executor:
        future_to_domain = {
            domain_executor.submit(process_single_domain, domain, selected_functions, all_functions, args.output): domain
            for domain in domains
        }

        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                future.result()  # Ensure any exceptions are raised here
            except Exception as e:
                print(Fore.RED + f"[ERROR] Failed processing {domain}: {e}" + Style.RESET_ALL)

def process_single_domain(domain, selected_functions, all_functions, output_filename):
    if not validate_domain(domain):
        print(Fore.RED + f"Invalid domain: {domain}" + Style.RESET_ALL)
        return

    data = {"Domain": domain}
    print(Fore.CYAN + f"\n[INFO] Starting information gathering for {domain}...\n" + Style.RESET_ALL)

    # Limit the number of concurrent functions per domain
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.MAX_FUNCTIONS) as executor:
        future_to_func = {executor.submit(all_functions[func], domain): func for func in selected_functions}

        for future in concurrent.futures.as_completed(future_to_func):
            func_name = future_to_func[future]
            try:
                data[func_name.replace("_", " ").title()] = future.result()
            except Exception as e:
                data[func_name.replace("_", " ").title()] = Fore.RED + f"Error: {e}" + Style.RESET_ALL

    print(Fore.CYAN + f"\n[INFO] Completed information gathering for {domain}.\n" + Style.RESET_ALL)
    report_generation(domain, data, output_filename)

def main():
    parser = argparse.ArgumentParser(description="TraceFox - Domain OSINT Tool")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-f", "--file", help="File containing list of domains")
    parser.add_argument("-o", "--output", help="Output filename (default: auto-generated)")
    parser.add_argument("-a", "--all", action="store_true", help="Run all functions")
    parser.add_argument("-e", "--except_list", help="Comma-separated list of functions to exclude when using -a")

    for func in ["whois", "ip", "ssl", "dns", "tech", "wayback", "breaches", "subdomains", "blacklist", "robomap", "ports", "hosting", "headers"]:
        parser.add_argument(f"--{func}", action="store_true", help=f"Run {func} lookup")

    args = parser.parse_args()

    if args.domain or args.file:
        print(Fore.CYAN + "\n[TraceFox] Starting information gathering...\n" + Style.RESET_ALL)

    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.file:
        try:
            with open(args.file, "r") as f:
                domains.extend([line.strip() for line in f.readlines()])
        except Exception as e:
            print(Fore.RED + f"Error reading file: {e}" + Style.RESET_ALL)
            return

    if not domains:
        print(Fore.RED + "No valid domain provided!" + Style.RESET_ALL)
        return

    process_domains(domains, args)
    print(Fore.GREEN + "\n[ ✔ ] All tasks completed successfully." + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Process interrupted by user. Exiting gracefully." + Style.RESET_ALL)
