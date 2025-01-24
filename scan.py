import os
import argparse
import subprocess

# Set up argument parser
parser = argparse.ArgumentParser(description="Run scans on a target IP.")
parser.add_argument("ip_address", help="Target IP address to scan")

# Parse arguments
args = parser.parse_args()

# Trim spaces from the input argument
ip_address = args.ip_address.strip()

# Directory to store scan results
output_dir = f"scan_results/{ip_address}"

# Ensure directory exists and handle permissions
try:
    os.makedirs(output_dir, exist_ok=True)
    print(f"Output directory: {output_dir} created or already exists.")
except PermissionError as e:
    print(f"Permission error: {e}")
    exit(1)
except Exception as e:
    print(f"Error creating directory: {e}")
    exit(1)

# Run Nmap Scan
try:
    nmap_command = "nmap -sV -oX scan_result/nmap_output.xml -Pn 192.168.1.14 43.205.151.144"
    os.system(nmap_command)
except Exception as e:
    print(f"Error running Nmap: {e}")

# Run Nikto Scan
#try:
    nikto_command = f"nikto -h http://{ip_address} -o {output_dir}/nikto_output.xml"
    os.system(nikto_command)
#except Exception as e:
    print(f"Error running Nikto: {e}")

# Execute generate_report.py
 #try:
    generate_report_command = f"python3 generate_report.py {output_dir}"
    subprocess.run(generate_report_command, shell=True, check=True)
    print("Report generation completed.")
#except subprocess.CalledProcessError as e:
 #   print(f"Error running generate_report.py: {e}")