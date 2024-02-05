import subprocess
import os
from pathlib import Path
import argparse
import sys
import requests
import time
import platform
import re
import pandas as pd
import concurrent.futures
sys.path.append('src/')
import domain_relations
import waymore_install
import nmap_install

sys.path.append('bin/')
import go_packages

import threading
import socket
import nmap3
from pathlib import Path


# global vars
# --- update later

# Grab the apex domains
def apex_domains(url, d_name, output_dir):
    print("Entering apex_domains function")
    try:
        domain_regex = r'^(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$'
        output_file = output_dir / f"{d_name}.txt"
        print(f"Output file path: {output_file}")

        check_mdi_cmd = ["python3", "src/check_mdi-main/check_mdi.py", "-d", url]
        # print(f"Executing command: {check_mdi_cmd}")
        check_mdi = subprocess.run(check_mdi_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # print(f"Subprocess output: {check_mdi.stdout}")
        # print(f"Subprocess error: {check_mdi.stderr}")

        data_results = []
        with open(output_file, "w+", encoding='utf-8') as file:
            for line in check_mdi.stdout.splitlines():
                line = line.strip()
                if re.match(domain_regex, line):
                    file.write(line + '\n')
                    data_results.append(line)
        
        return data_results

    except Exception as e:
        print(f"Error in apex_domains: {e}")
    print("Exiting apex_domains function")

# Grab the ASNs
def asn_grab(url, d_name, output_dir):
    print("Entering asn_grab function")
    try:
        link = f"https://api.bgpview.io/search?query_term={d_name}" # ---> bgp_view uses syntax like search=example, instead of search=example.com
        response = requests.get(link)
    
        if response.status_code == 200:
            data = response.json()
            ipv4_prefixes = data.get('data', {}).get('ipv4_prefixes', [])
        
            asn_findings_file = Path(output_dir) / 'asn_findings.txt'
            # print(f"ASN findings file path: {asn_findings_file}")

            with open(asn_findings_file, 'w', encoding='utf-8') as file:
                for prefix in ipv4_prefixes:
                    file.write(f"{prefix['ip']} - {prefix['name']}\n")
        else:
            print(f"Failed to fetch data: HTTP {response.status_code}")
    except Exception as e:
        print(f"Error in asn_grab: {e}")
    print("Exiting asn_grab function")


# commend to run subprocess (do not do async to not run up RAM)
    
def run_command(domain, command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        stdout, stderr = process.communicate(timeout=300)
        return domain, stdout, stderr
    except subprocess.TimeoutExpired:
        process.kill()
        return domain, "", f"Command timed out for domain {domain}"
    except Exception as e:
        return domain, "", str(e)

# subdomain enum
def passive_subenum(url, d_name, output_dir):
    domain_regex = re.compile(r'^(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}(?::\d+)?$')

    def is_valid_subdomain(subdomain):
        # You can customize this function to determine whether a line represents a valid subdomain
        # For example, you can use regex or other rules to match valid subdomains
        # Here, we'll consider any non-empty line as a valid subdomain
        return bool(subdomain)

    data_results = []

    domains_file = Path(output_dir) / f"{d_name}.txt"  
    pass_sub_file = Path(output_dir) / f"{d_name}_subdomains.txt"
    waymore_path = Path('src') / 'waymore' / f"waymore.py"

    # Check if the domains file exists (for apex domain flag)
    if domains_file.exists():
        with open(domains_file, 'r') as file:
            domains = [line.strip() for line in file if domain_regex.match(line.strip())]
    else:
        domains = [url] if domain_regex.match(url) else []

    for domain in domains:

        # subfinder
        try:
            print(f"Running subfinder for {domain}...")
            subfinder_cmd = ["subfinder", "-d", domain, "-v"]
            subfinder_output = subprocess.check_output(subfinder_cmd, stderr=subprocess.STDOUT, text=True)
            
            # Filter out lines that do not represent subdomains
            subdomains = [line.strip() for line in subfinder_output.splitlines() if is_valid_subdomain(line.strip())]
            
            for subdomain in subdomains:
                if domain_regex.match(subdomain):
                    data_results.append(subdomain)

        except subprocess.CalledProcessError as e:
            print(f"Error running subfinder for {domain}: {e.output}")
    
        ############# Gotta fix this section
        # # amass
        # try:
        #     print("running amass")
        #     amass_cmd = ["amass", "enum", "-d", domain]
        #     amass_output = subprocess.check_output(amass_cmd, stderr=subprocess.STDOUT, text=True)
        #     print(amass_output)
            
        #     amass_subdomains = [line.strip() for line in amass_output.splitlines() if is_valid_subdomain(line.strip())]
            
        #     for amass_subdomain in amass_subdomains:
        #          if domain_regex.match(amass_subdomains):
        #             data_results.append(amass_subdomains)

        # except subprocess.CalledProcessError as e:
        #     print(f"Error running amass for {domain}: {e.output}")

        # # waymore
        # try:
        #     print("running waymore")
        #     waymore_cmd = ["python3", waymore_path, "-i", url]
        #     waymore_output = subprocess.check_output(amass_cmd, stderr=subprocess.STDOUT, text=True)
            
        #     waymore_subdomains = [line.strip() for line in waymore_output.splitlines() if is_valid_subdomain(line.strip())]
            
        #     for waymore_subdomain in waymore_subdomains:
        #          if domain_regex.match(waymore_subdomains):
        #             data_results.append(waymore_subdomains)

        # except subprocess.CalledProcessError as e:
        #     print(f"Error running waymore for {domain}: {e.output}")

        print(f"{data_results}")

        with open(pass_sub_file, "w+") as file:
            for result in data_results:
                file.write(f"{result}\n")

    return data_results

# This block is to clean results from httpx since it adds special chars
def clean_ansi_sequences(input_string):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', input_string)

# httpx running 

def tech_used(d_name, output_dir):
    tech_data = []
    subdomain_file = Path(output_dir) / f"{d_name}_subdomains.txt"
    tech_file = Path(output_dir) / f"{d_name}_tech_used.txt"

    if subdomain_file.exists():
        with open(subdomain_file, 'r') as file:
            subdomains = [line.strip() for line in file.readlines()]
    else:
        print(f"Subdomain file {subdomain_file} not found.")
        return []

    for subdomain in subdomains:
        try:
            command = ["httpx", "-sc", "-td", "-ip", "-method", "-title", "-cl", "-server", "-l", subdomain_file]
            httpx_output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
            output_cleaned = clean_ansi_sequences(httpx_output)

            parts = re.findall(r'\[([^]]+)]', output_cleaned)
            # Standardize the length of parts to 8 elements, filling missing values with 'NULL'
            standardized_parts = [p if p else ' ' for p in parts] + [' '] * (8 - len(parts))
            tech_data.append([subdomain] + standardized_parts)
        except Exception as e:
            print(f"Error running httpx for {subdomain}: {e}")
            tech_data.append([subdomain] + [' '] + [' '] * 7)  # Indicate an error occurred

    with open(tech_file, "w") as file:
        for result in tech_data:
            file.write(','.join(result) + '\n')  # Using comma as a separator for clarity

    return tech_data


def main(): 
    parser = argparse.ArgumentParser(description="Bug bounty tool")
    parser.add_argument("--domain", "-d", required=True, help="Enter the domain name for the target")
    parser.add_argument("--subdomains", "-s", action='store_true', help="enumerate subdomains only (excludes everything else)")
    parser.add_argument("--apex", "-ax", action='store_true', help="Grab apex domains only")
    parser.add_argument("--tech-detection", "-td", action='store_true', help="Only run subdomains enumeration, and tech details")
    parser.add_argument("--vulnscan", "-v", action='store_true', help="basic port scan on subdomains")
    parser.add_argument("--all", "-a", action='store_true', help="Run all checks default if only -d is selected with nothing else.")

    args = parser.parse_args()

    url = args.domain
    sub = args.subdomains
    apex = args.apex
    tech = args.tech_detection
    port = args.vulnscan
    all_ = args.all #-- use _ to avoid conflict with the all var

    try:
        current_os = platform.system()
        if not go_packages.is_go_installed():
            print(f"Go is not detected. Attempting installation for {current_os}...")
            current_os = platform.system()
            if current_os == "Windows":
                go_packages.install_go_windows()
            elif current_os == "Linux":
                go_packages.install_go_linux()
            elif current_os == "Darwin":  # macOS is recognized as 'Darwin'
                go_packages.install_go_mac()
            else:
                print("Unsupported operating system.")
                return  # Exit the script if the OS is not supported

        print("Setting up Go environment and installing packages")
        go_packages.set_go_path()
        go_packages.install_go_packages()

        # nmap install check
        if not nmap_install.is_nmap_installed():
            print("Nmap is not installed. Installing...")
            if sys.platform.startswith("linux"):
                nmap_install.install_nmap_linux()
            elif sys.platform.startswith("darwin"):
                nmap_install.install_nmap_macos()
            elif sys.platform.startswith("win"):
                nmap_install.install_nmap_windows()
            else:
                print("Unsupported operating system.")
                sys.exit(1)
        else:
            print("Nmap is already installed.")

        print("Please ensure Nmap is added to your PATH if it's not already configured.")

    except Exception as e:
        print(e)


    d_name = url.split(".")[0]
    output_dir = Path("output") / d_name
    output_dir.mkdir(parents=True, exist_ok=True)


    if all_:
        try:

            print("Processing domain relations")
            domain_relations.process_domain(url)

            print("Running apex domains")
            apex_domains_data = apex_domains(url, d_name, output_dir)

            print("Running ASN grab")
            asn_grab_data = asn_grab(url, d_name, output_dir)

            if not waymore_install.check_waymore():
                waymore_install.install_waymore()
            print("Running passive subdomain enumeration")
            subdomain_data = passive_subenum(url, d_name, output_dir)

            print("Running Tech Detection with HTTPX...")
            tech_used_data = tech_used(d_name, output_dir)


            print("Writing and organizing results to Excel")
            excel_file = Path(output_dir) / f"{d_name}_spreadsheet.xlsx"
            with pd.ExcelWriter(excel_file, engine='xlsxwriter') as writer:

                # Create DataFrame for each data type
                df_apex_domains = pd.DataFrame(apex_domains_data, columns=['Apex Domain'])
                df_asn_grab = pd.DataFrame(asn_grab_data, columns=['IP Range', 'Organization'])
                df_subdomains = pd.DataFrame(subdomain_data, columns=['Subdomains'])
                df_tech_used = pd.DataFrame(tech_used_data, columns=['Subdomain', 'Status Code', 'HTTP Method', 'Content-Size', 'Title', 'IP Address', 'Tech Detection', 'Server Name', ''])

                # Write to Excel
                df_apex_domains.to_excel(writer, sheet_name='Apex_Domains')
                df_asn_grab.to_excel(writer, sheet_name='ASN_Findings')
                df_subdomains.to_excel(writer, sheet_name='Subdomains')
                df_tech_used.to_excel(writer, sheet_name='Tech_Detection')


        except Exception as e:
            print(e)

    else:
        if sub:
            if not waymore_install.check_waymore():
                waymore_install.install_waymore()
            print("Running passive subdomain enumeration")
            subdomain_data = passive_subenum(url, d_name, output_dir)

            print("Writing and organizing results to Excel")
            excel_file = Path(output_dir) / f"{d_name}_spreadsheet.xlsx"
            with pd.ExcelWriter(excel_file, engine='xlsxwriter') as writer:

                # Create DataFrame for each data type
                df_subdomains = pd.DataFrame(subdomain_data, columns=['Subdomains'])
                
                print(f"processed data: processed_data") # -- for testing...

                # Write to Excel
                df_subdomains.to_excel(writer, sheet_name='Subdomains')
        
        if apex:
            print("Running apex domains")
            apex_domains_data = apex_domains(url, d_name, output_dir)

            print("Writing and organizing results to Excel")
            excel_file = Path(output_dir) / f"{d_name}_spreadsheet.xlsx"
            with pd.ExcelWriter(excel_file, engine='xlsxwriter') as writer:

                # Create DataFrame for each data type
                df_apex_domains = pd.DataFrame(apex_domains_data, columns=['Apex Domain'])

                # Write to Excel
                df_apex_domains.to_excel(writer, sheet_name='Apex_Domains')

        if tech:
            print("grabbing subdomains for tech detection")
            passive_subenum(url, d_name, output_dir)
            
            print("Running Tech Detection with HTTPX...")
            tech_used_data = tech_used(d_name, output_dir)

            print("Writing and organizing results to Excel")
            excel_file = Path(output_dir) / f"{d_name}_spreadsheet.xlsx"
            with pd.ExcelWriter(excel_file, engine='xlsxwriter') as writer:

                # Create DataFrame for each data type
                df_tech_used = pd.DataFrame(tech_used_data, columns=['Subdomain', 'NULL', 'Status Code', 'HTTP Method', 'Content-Size', 'Title', 'IP Address', 'Tech Detection', 'Server Name'])
            
                # Write to Excel
                df_tech_used.to_excel(writer, sheet_name='Tech_Detection')
        
        if port:
            pass


if __name__ == "__main__":
    main()


