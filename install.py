import os
import sys
import subprocess

# Define required Python modules and system dependencies
PYTHON_PACKAGES = ["requests", "colorama"]
SYSTEM_DEPENDENCIES = ["whois", "openssl", "dig", "nmap"]

# Function to install Python dependencies
def install_python_packages():
    print("[+] Installing required Python packages...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
    print("[✔] Python packages installed successfully.\n")

# Function to check if a system dependency is installed
def is_installed(command):
    try:
        subprocess.run([command, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

# Function to install missing system dependencies (Linux/macOS only)
def install_system_dependencies():
    if sys.platform.startswith("linux") or sys.platform == "darwin":  # Linux or macOS
        missing_tools = [tool for tool in SYSTEM_DEPENDENCIES if not is_installed(tool)]
        
        if missing_tools:
            print(f"[!] Missing tools detected: {', '.join(missing_tools)}")
            print("[+] Attempting to install missing tools...")
            subprocess.run(["sudo", "apt", "install", "-y"] + missing_tools, check=False)
            print("[✔] System dependencies installed (if supported).")
        else:
            print("[✔] All system dependencies are already installed.")
    else:
        print("[!] System dependency check not supported on Windows. Please install manually.")

# Function to create a global command for the tool
def make_tool_global():
    script_path = os.path.abspath("tracefox.py")
    bin_path = "/usr/local/bin/tracefox"

    if sys.platform.startswith("linux") or sys.platform == "darwin":  # Linux/macOS
        try:
            with open(bin_path, "w") as f:
                f.write(f"#!/bin/bash\npython3 {script_path} \"$@\"\n")
            subprocess.run(["chmod", "+x", bin_path])
            print("[✔] Tool is now globally accessible as 'osint-tool'")
        except Exception as e:
            print(f"[!] Failed to make tool global: {e}")
    else:
        print("[!] Global command setup not supported on Windows. Add the script to PATH manually.")

# Run the installation process
if __name__ == "__main__":
    try:
        install_python_packages()
        install_system_dependencies()
        make_tool_global()
        print("\n[✔] Installation complete! You can now use 'TraceFox'!!.")
    except Exception as e:
        print(f"[X] Installation failed: {e}")
