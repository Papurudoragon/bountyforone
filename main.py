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
sys.path.append('bin/')
import go_packages
import threading
import socket


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



# used to run commands in subprocess
def run_command_async(domain, command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    return domain, process

def passive_subenum(url, d_name, output_dir):
    # print("Entering passive_subenum function")
    domain_regex = re.compile(r'^(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$')
    data_results = []

    domains_file = Path(output_dir) / f"{d_name}.txt"  
    pass_sub_file = Path(output_dir) / f"{d_name}_subdomains.txt"
    waymore_path = Path('src') / 'waymore' / f"waymore.py" # --> user reports timeout issues with this

    # Check if the domains file exists (for apex domain flag)
    if domains_file.exists():
        with open(domains_file, 'r') as file:
            domains = [line.strip() for line in file if domain_regex.match(line.strip())]
    else:
        # If file does not exist, use the url variable directly
        domains = [url] if domain_regex.match(url) else []

    batch_size = 10  # Process a batch of 10 domains at a time - this saves on processing power
    for i in range(0, len(domains), batch_size):
        batch_domains = domains[i:i + batch_size]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = {}
            for domain in batch_domains:
                futures[executor.submit(run_command_async, domain, ["subfinder", "-d", domain, "-v"])] = domain
                futures[executor.submit(run_command_async, domain, ["amass", "enum", "-d", domain, "-v"])] = domain
                futures[executor.submit(run_command_async, domain, ["python3", waymore_path, "-i", url])] = domain ## --> apparently gives issues - need to check this


            for future in concurrent.futures.as_completed(futures):
                domain = futures[future]
                try:
                    _, process = future.result()
                    output, _ = process.communicate(timeout=300)  # Setting a timeout so the script doesn't hang indefinitely if there are errors
                    print(f"Results for {domain}: {output}")
                    for line in output.splitlines():
                        line = line.strip()
                        if domain_regex.match(line):
                            print(line)
                            data_results.append(line)
                except subprocess.TimeoutExpired:
                    process.kill()
                    print(f"Command for domain {domain} timed out.")

    # Write results
    with open(pass_sub_file, "w") as file:
        for result in data_results:
            file.write(result + '\n')

    print("Exiting passive_subenum function")
    return data_results

# This block is to clean results from httpx since it adds special chars
def clean_ansi_sequences(input_string):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', input_string)


def tech_used(d_name, output_dir):
    tech_data = []
    subdomain_file = Path(output_dir) / f"{d_name}_subdomains.txt"
    tech_file = Path(output_dir) / f"{d_name}_tech_used.txt"

    with open(subdomain_file, 'r') as file:
        subdomains = [line.strip() for line in file.readlines()]

    batch_size = 10
    for i in range(0, len(subdomains), batch_size):
        batch_subdomains = subdomains[i:i + batch_size]
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            futures = {executor.submit(run_command_async, subdomain, ["httpx", "-sc", "-td", "-ip", "-method", "-title", "-cl", "-server", "-u", subdomain]) for subdomain in batch_subdomains}

            for future in concurrent.futures.as_completed(futures):
                subdomain, process = future.result()
                output, _ = process.communicate(timeout=300)
                output_cleaned = clean_ansi_sequences(output)

                parts = re.findall(r'\[([^]]+)]', output_cleaned)
                # Ensure the list has the correct number of elements for the DataFrame columns
                while len(parts) < 7:
                    parts.append(' ')  # Add whitespace for missing parts
                # Prepend the subdomain to the parts
                tech_data.append([subdomain] + parts)

    with open(tech_file, "w") as file:
        for result in tech_data:
            file.write(' '.join(result) + '\n')

    return tech_data

def port_scan(url, d_name, output_dir): # add in a port scan
    pass





def main():
    print("Starting main function")
    parser = argparse.ArgumentParser(description="Bug bounty tool")
    parser.add_argument("--domain", "-d", required=True, help="Enter the domain name for the target")
    parser.add_argument("--subdomains", "-s", action='store_true', help="enumerate subdomains only (excludes everything else)")
    parser.add_argument("--apex", "-ax", action='store_true', help="Grab apex domains only")
    parser.add_argument("--tech-detection", "-td", action='store_true', help="Only run subdomains enumeration and tech detection")
    parser.add_argument("--portscan", "-p", action='store_true', help="basic port scan on subdomains")
    parser.add_argument("--all", "-a", action='store_true', help="Run all checks default if only -d is selected with nothing else.")

    args = parser.parse_args()

    url = args.domain
    sub = args.subdomains
    apex = args.apex
    tech = args.tech_detection
    port = args.portscan
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

        d_name = url.split(".")[0]
        output_dir = Path("output") / d_name
        output_dir.mkdir(parents=True, exist_ok=True)

    except Exception as e:
        print(e)

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
                df_tech_used = pd.DataFrame(tech_used_data, columns=['Subdomain', 'Status Code', 'HTTP Method', 'Content-Size', 'Title', 'IP Address', 'Tech Detection', 'Server Name'])
            
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

            print("Running Tech Detection with HTTPX...")
            tech_used_data = tech_used(d_name, output_dir)


            print("Writing and organizing results to Excel")
            excel_file = Path(output_dir) / f"{d_name}_spreadsheet.xlsx"
            with pd.ExcelWriter(excel_file, engine='xlsxwriter') as writer:

                # Create DataFrame for each data type
                df_tech_used = pd.DataFrame(tech_used_data, columns=['Subdomain', 'Status Code', 'HTTP Method', 'Content-Size', 'Title', 'IP Address', 'Tech Detection', 'Server Name'])
            
                # Write to Excel
                df_tech_used.to_excel(writer, sheet_name='Tech_Detection')
        
        if port:
            print("portscan coming soon...")
            return

        



if __name__ == "__main__":
    main()


