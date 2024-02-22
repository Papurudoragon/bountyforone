"""Bountyforone, by Papv2, is a continuous project that is aimed to organize Recon results into an easily readable excel document.
usage: python3 bountyforone.py -h/--help"""

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
sys.path.append('bin/')
import check_mdi
from pathlib import Path
import random
from colorama import Fore
import pyfiglet
import io
from contextlib import redirect_stdout
import tldextract



# define our class for domain handling and output
class DomainName:
    
    # strips tld and subdoamin, so example.com would return example
    def __init__(self, domain, output):
        extracted = tldextract.extract(domain)

        self.domain = extracted.domain.lower()
        self.output = output

    # return just the domain not tld or subdoamin
    def get_dname(self): 
        return self.domain

    # define to output files to output folders
    def get_output(self):
        return self.output


# python banner text
banner_text = pyfiglet.figlet_format("BountyforOne")
author_text = "by Papv2"
desc_text = "One base, for all tools."

# arguments to add for url or file use
parser = argparse.ArgumentParser(description="Bounty for one - Bug bounty tool")
parser.add_argument("-u", "--url", help="Enter the domain name for a single target (e.g example.com)")
parser.add_argument("-l", "--list", help="runs command(s) on a list of targets [specify a file path]")

# args to run scripts
parser.add_argument("-s", "--subdomains", action='store_true', help="grab subdomains for a given domain")
parser.add_argument("-ls", "--live-subdomains", action='store_true', help="verify the status of a domain or file of doamins")
parser.add_argument("-ax", "--apex", action='store_true', help="Grab apex domains of a domain for file of domains")
# parser.add_argument("-st", "--subdomain-takeover", action='store_true', help="provide a list of subdomains for subdomain takeover checks")
parser.add_argument("-td", "--tech-detection", action='store_true', help="run technnology detection against a single url or list of domains")
parser.add_argument("-p", "--port", action='store_true', help="basic port scan on url or list of domains")
parser.add_argument("-vs", "--vulnscan", action='store_true', help="basic vuln scan on url or list of domains")
parser.add_argument("-sp", "--spider", action='store_true', help="basic spider on url or list of domains")
parser.add_argument("-as", "--asn",  action='store_true', help="grab asn information for url or list of domains",)

# output args
parser.add_argument("-o", "--output", required=True, help="output results to a .txt file")

# # flag for all checks
# parser.add_argument("-a", "--all", action='store_true', help="Run all checks default if only -u is selected with nothing else.")

args = parser.parse_args()

_url = args.url
_list = args.list
_subdomains = args.subdomains
_livesubs = args.live_subdomains
_apex = args.apex
# _subtakeover = args.subdomain_takeover
_tech_detection = args.tech_detection
_ports = args.port
_vulnscan = args.vulnscan
_spider = args.spider
_asn = args.asn

# for the scripts
output_flag = "-o "

# for instantiate our DomainName class
with open(_list, 'r') as f5:
    first_line = f5.readline().strip()
    
if _url is not None:
    url_output = DomainName(_url, args.output).get_output()
else:
    first_line  # Assigns the stripped first line to _url
    url_output = DomainName(first_line, args.output).get_output()

# need one for -l


# flags for any, and all_flags for all flags or no flags
# _flags = any([_subdomains, _livesubs, _apex, _tech_detection, _ports, _vulnscan, _spider, _asn,])
_all_flags = (_subdomains, _livesubs, _apex, _tech_detection, _ports, _vulnscan, _spider, _asn,)

# selected args vars for later mapping and parsing with file handling
selected_args = []
if _subdomains: selected_args.append('subdomains')
if _apex: selected_args.append('apex')
if _tech_detection: selected_args.append('tech_detection')
# if _subtakeover: selected_args.append('subdomain_takeover')
if _ports: selected_args.append('ports')
if _vulnscan: selected_args.append('vulnscan')
if _spider: selected_args.append('spider')
if _asn: selected_args.append('asn')
if _livesubs: selected_args.append('live_subs')

# string format
selected_args_str = ", ".join(selected_args)


# set tool install paths for commands
os_arch = platform.machine().lower()
os_type = platform.system().lower()

if os_type == "windows":
        if os_arch in ["x86_64", "amd64"]:
            subfinder_ = "subfinder.exe"
            nuclei_ = "nuclei.exe"
            httpx_ = "httpx.exe"
            naabu_ = "naabu.exe"
            katana_ = "katana.exe"

else:
    subfinder_ = "./subfinder"
    nuclei_ = "./nuclei"
    httpx_ = "./httpx"
    naabu_ = "./naabu"
    katana_ = "./katana"



## Global vars for url and list domain without the .com >> this extracts the domain only
# if _url:
#     dom = DomainName(_url, output=None)
#     domain_name = dom.get_dname()
# if _list:
#     DomainName(domain=None, output=None).get_dname_list(_list)

selected_args = [] # this is for existing args
existing_files = [] # this is for existing files
# base_dir = Path('output') / domain_name
max_memory = 0 # we gotta limit memory usage to handle processing with less RAM
curr_memory = 0 # we gotta limit memory usage to handle processing with less RAM

# xlsx dataframes
apex_xlsx = []
asn_xlsx = []
subdomain_xlsx = []
live_subdomains_xlsx = []
tech_xlsx = []
port_scan_xlsx = []
vuln_scan_xlsx = []
dir_search_xlsx = []
spider_xlsx = []
js_spider_xlsx = []

## User agents for request making
user_agent = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/99.0.1150.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
]

# set the user-agent header at random
headers = {'User-Agent': random.choice(user_agent)}

# set the script timeout
timeout = 800

# this is for the excel file url location and list location
excel_file =  Path(f"{os.path.dirname(args.output)}") / "bountyforone_spreadsheet.xlsx"

# Command flags
# apex location flag
apex_mdi = Path("bin") / "check_mdi.py"

# dL for list of apex, -d for single url
subfinder_flag_all = "-dL"
subfinder_flag_url = "-d"

# for single and subdomains
httpx_flag_all = "-l" 
httpx_flag_url = "-u"

naabu_flag_all = "-list" 
naabu_flag_url = "-host"
naabu_ports = "21,22,25,53,80,389,443,8080,3306,5432"

nuclei_flag_all = "-l" 
nuclei_flag_url = "-u"

katana_flag_all = "-list"
katana_flag_url = "-u"


# commands:
commands = {

    "subdomains_list_output": [
        f"{Path('bin') / 'subfinder' / subfinder_} {subfinder_flag_all} {_list} -v {output_flag}{url_output}_subdomains.txt"
        # f"amass enum -d {apex}",
    ],
    
    "subdomains_no_list_output": [
        f"{Path('bin') / 'subfinder' / subfinder_} {subfinder_flag_url} {_url} -v {output_flag}{url_output}_subdomains.txt"
        # f"amass enum -d {_url}",
    ],

    "live_subs_output": [
        f"{Path('bin') / 'httpx' / httpx_} {httpx_flag_all} {_list} {output_flag}{url_output}_livesubs.txt"
    ],

    "live_subs_url_output": [
        f"{Path('bin') / 'httpx' / httpx_} {httpx_flag_url} {_url} {output_flag}{url_output}_livesubs.txt"
    ],

    "tech_detection_output": [
        f"{Path('bin') / 'httpx' / httpx_} -sc -td -ip -method -cl {httpx_flag_all} {_list} {output_flag}{url_output}_techdetection.txt"
    ],

    "tech_detection_url_only_output": [
        f"{Path('bin') / 'httpx' / httpx_} -sc -td -ip -method -cl {httpx_flag_url} {_url} {output_flag}{url_output}_techdetection.txt"
    ],

    "portscan_output": [
        f"{Path('bin') / 'naabu' / naabu_} {naabu_flag_all} {_list} -v -p {naabu_ports} {output_flag}{url_output}_portscan.txt"
    ],

    "portscan_url_only_output": [
        f"{Path('bin') / 'naabu' / naabu_} {naabu_flag_url} {_url} -v -p {naabu_ports} {output_flag}{url_output}_portscan.txt"
    ],

    "vulnscan_output": [
         f"{Path('bin') / 'nuclei' / nuclei_} {nuclei_flag_all} {_list} -t http/ -v {output_flag}{url_output}_nuclei.txt"
    ],

    "vulnscan_url_only_output": [
        f"{Path('bin') / 'nuclei' / nuclei_} {nuclei_flag_url} {_url} -t http/ -v {output_flag}{url_output}_nuclei.txt"
    ],

    "spider_output": [
        f"{Path('bin') / 'katana' / katana_} {katana_flag_all} {_list} -jc -kf {output_flag}{url_output}_spider.txt"
    ],

    "spider_url_only_output":[
        f"{Path('bin') / 'katana' / katana_} {katana_flag_url} https://{_url} -jc -kf -jsl {output_flag}{url_output}_spider.txt"
    ]
}



"""The section below is to run commands"""


def run_apex(url):
    
    # handle for single url
    if _url:
        # IO can help us to temporarily redirect stdout to capture the output of get_domains
        f = io.StringIO()
        
        # This prints the mdi domain information
        with redirect_stdout(f):
            check_mdi.get_domains(url)  

        # Get the captured output
        sorted_output = f.getvalue()

        # Only extract domains, we can use regex for this
        domain_pattern = re.compile(r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        domains = set(domain_pattern.findall(sorted_output))
        
        # Write cleaned results to a file
        with open(args.output, 'w+') as file:
            for domain in sorted(domains):
                file.write(f"{domain}\n")

        # Close the StringIO object
        f.close()

    # handle for list
    if _list:
        # open file for parsing and also file for writing to
        with open(_list, 'r') as file1, open(args.output, 'a+') as file2:
            for line in file1:
                u = line.strip()
        
        
                # IO can help us to temporarily redirect stdout to capture the output of get_domains
                f = io.StringIO()
                
                # This prints the mdi domain information
                with redirect_stdout(f):
                    check_mdi.get_domains(u)  

                # Get the captured output
                sorted_output = f.getvalue()

                # Only extract domains, we can use regex for this
                domain_pattern = re.compile(r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
                domains = set(domain_pattern.findall(sorted_output))

                # write results to apex file
                for domain in sorted(domains):
                    file2.write(f"{domain}\n")

                # Close the StringIO object
                f.close()


        return



# this is to run all of the commands above (-a or --all flags
def run_commands(command):
    try:
        # iterate through the commands and run each of them
        i = 0
        for i in range(len(command)):

            # # logic here can be if _output then subprocess to output, else then just run
            print("running command(s), please be patient...\n\n")
            output = subprocess.check_output(
                command[i], 
                stderr=subprocess.STDOUT, 
                shell=True, 
                timeout=timeout,
                encoding='utf-8'
                )
            
            print(output)
            time.sleep(1)
            i += 1

    except subprocess.CalledProcessError as e:
        #print(f'Command {command} failed with error: {e.stderr}')
        if _list:
            print(f"command failed, please check the specified file [some commands require https:// for lines in the file and others dont.\n If this is the case, run -ls for live subdomains, or just -s for subdomains.]")
        if _url:
            print(f"command failed, please check the specified url")
    except subprocess.TimeoutExpired:
        print(f'Command timed out')
    
    return


# grab ASNs for given domain
def asn_grab(url):
    
    # handle input for url
    if _url:

        response = requests.get (f"https://api.bgpview.io/search?query_term={url}", headers=headers) # randomize user agents
        print(response)
        print("test")
        if response.status_code == 200:
            data = response.json()

            with open(f"{url_output}_asn.txt", "w+") as file1:
                if 'data' in data and 'ipv4_prefixes' in data['data']:
                    for prefix in data['data']['ipv4_prefixes']:
                        file1.write(f"{prefix['ip']}, {prefix['name']}\n")
                        print(f"{prefix['ip']}, {prefix['name']}")

                else:
                    print("no ASNs found")
        
        else:
            print(f"failed to fetch asn data: {response.status_code}")
        
        return
    
    # handle input for list
    if _list:
        with open(_list, 'r') as file1, open(f"{url_output}_asn.txt", 'w+') as file2:
            for line in file1:
                u = line.strip()
                response = requests.get (f"https://api.bgpview.io/search?query_term={u}", headers=headers) # randomize user agents
                if response.status_code == 200:
                    data = response.json()

                    if 'data' in data and 'ipv4_prefixes' in data['data']:
                        for prefix in data['data']['ipv4_prefixes']:
                            file2.write(f"{prefix['ip']}, {prefix['name']}\n")
                            print(f"{prefix['ip']}, {prefix['name']}")

                        else:
                            print("no ASNs found")
                
                else:
                    print(f"failed to fetch asn data: {response.status_code}")
        return

# handle the existing files and fail if the user specifies a file that already exists ---> to remove later
def handle_existing_files():
    pass


def output_to_excel():

    # read several files and format for excel
    
    directory = os.path.dirname(args.output)

    try:
        # first list all files in the directory
        for filename in os.listdir(directory):
            # check if 'apex' is in the filename
            if "apex" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as file:
                    apex_content = file.read().splitlines()
                    apex_xlsx = [f"{line}\n" for line in apex_content]
                    # Process apex_content or apex_xlsx as needed
    except FileNotFoundError:
        pass


    try:
        # first list all files in the directory
        for filename in os.listdir(directory):
            # check if 'apex' is in the filename
            if "asn" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as asn_file:
                    asn_content = asn_file.read().splitlines()
                    for line in asn_content:
                        ip, domain = line.strip().split(',')
                        asn_xlsx.append((ip, domain))
    except FileNotFoundError:
        pass

    try:
        # first list all files in the directory
        for filename in os.listdir(directory):
            # check if 'apex' is in the filename
            if "subdomain" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as subdomains_file:
                    sub_content = subdomains_file.read().splitlines()
                    for line in sub_content:
                        subdomain_xlsx.append(f"{line}\n")
    except FileNotFoundError:
        pass

    try:
        # first list all files in the directory
        for filename in os.listdir(directory):
            # check if 'apex' is in the filename
            if "livesub" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as live_file:
                    live_content = live_file.read().splitlines()
                    for line in live_content:
                        live_subdomains_xlsx.append(f"{line}\n")
    except FileNotFoundError:
        pass

    # httpx results need a but more cleaning and formatting
    try:
        # first list all files in the directory
        for filename in os.listdir(directory):
            # check if 'apex' is in the filename
            if "techdetect" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as tech_file:
                    for line in tech_file:
                        clean_pattern = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
                        cleaned_line = re.sub(clean_pattern, '', line)
                        tech_parts = cleaned_line.strip().split('[')
                        tech_content = [part.replace(']', '').strip() for part in tech_parts]
                        tech_xlsx.append(tech_content)
    except FileNotFoundError:
        pass

    # naabu needs a bit of cleaning and formatting
    try:
        # first list all files in the directory
        for filename in os.listdir(directory):
            # check if 'apex' is in the filename
            if "portscan" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as port_file:
                        for line in port_file:
                            host, port = line.strip().split(':')
                            port_scan_xlsx.append((host, port))
    except FileNotFoundError:
        pass

    # nuclei needs a bit of formatting
    try:
        # first list all files in the directory
        for filename in os.listdir(directory):
            # check if 'apex' is in the filename
            if "nuclei" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as vuln_file:
                    pattern = re.compile(r'\[(.*?)\]')

                    # position [3] is a url but not a list in nuclei, wierd format but we can fix that
                    url_pattern = re.compile(r'https?://[^\s\[\]]+')
                    for line in vuln_file:
                        parts = pattern.findall(line)
                        url_ = url_pattern.findall(line) 
                        if url_:
                            host_ = url_[0]
                        else:
                            host_ = ""
                        if len(parts) >=3:
                            vuln_check_, method_, severity_, = parts[:3]   
                        if len(parts) > 3:
                            findings_ = ''.join(parts[3:])
                        else:
                            findings_ = ""
                        vuln_scan_xlsx.append([vuln_check_, method_, severity_, host_, findings_])
    except FileNotFoundError:
        pass

    try:
        # first list all files in the directory
        for filename in os.listdir(directory):
            # check if 'apex' is in the filename
            if "spider" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as spider_file:
                    spider_content = spider_file.read().splitlines()
                    for line in spider_content:
                        spider_xlsx.append(f"{line}\n")
    except FileNotFoundError:
        pass

    # lets define our excel file:
    with pd.ExcelWriter(excel_file, engine="xlsxwriter") as writer:

        # create dataframs for the posted results
        df_apex = pd.DataFrame(apex_xlsx, columns=['Apex Domains'])
        df_asn = pd.DataFrame(asn_xlsx, columns=['ASN IP', 'Domain'])
        df_subdomains = pd.DataFrame(subdomain_xlsx, columns=['Subdomains'])
        df_live = pd.DataFrame(live_subdomains_xlsx, columns=['Live Subdomains'])
        df_tech = pd.DataFrame(tech_xlsx, columns=['Subdomains', 'Status Code', 'HTTP Method', 'Content-Size', 'IP Address', 'Tech Stack'])
        df_port = pd.DataFrame(port_scan_xlsx, columns=['Domain', 'Port'])
        df_vuln = pd.DataFrame(vuln_scan_xlsx, columns=['Vuln Check', 'Method', 'Severity', 'Domains', 'Findings'])
        df_spider = pd.DataFrame(spider_xlsx, columns=['Spider Directories'])

        # export dataframes to xlsx
        df_apex.to_excel(writer, sheet_name='apex_domains')
        df_asn.to_excel(writer, sheet_name='asn_findings')
        df_subdomains.to_excel(writer, sheet_name='subdomains')
        df_live.to_excel(writer, sheet_name='live_subdomains')
        df_tech.to_excel(writer, sheet_name='tech_stack')
        df_port.to_excel(writer, sheet_name='port_scan')
        df_vuln.to_excel(writer, sheet_name='vuln_findings')
        df_spider.to_excel(writer, sheet_name='spider_findings')

    return

def banner():

    # banner shoes usage if implemented without flags
    print(f"{Fore.GREEN}{banner_text}")
    print(f"{Fore.YELLOW}{author_text}")
    print(f"{Fore.YELLOW}{desc_text}")
    print(f"{Fore.CYAN}usage: python3 bountyforone.py -h/--help")
    time.sleep(3)
    
    return

# this is where the args will be defined
def run_checks():
    
    if _url:
        if _asn:
            asn_grab(_url)
        if _apex:
            run_apex(_url)
        if _subdomains: 
            run_commands(commands["subdomains_no_list_output"])
        if _livesubs:
            run_commands(commands['live_subs_url_output'])
        if _ports:
            run_commands(commands["portscan_url_only_output"]) 
        if _spider:
            run_commands(commands["spider_url_only_output"])         
        if _tech_detection: 
            run_commands(commands["tech_detection_url_only_output"])
        if _vulnscan: 
            run_commands(commands["vulnscan_url_only_output"])
    
    if _list:
        if _asn:
            asn_grab(_list)
        if _apex:
            run_apex(_list)
        if _subdomains: 
            run_commands(commands["subdomains_list_output"])
        if _livesubs:
            run_commands(commands['live_subs_output'])           
        if _ports:
            run_commands(commands["portscan_output"])
        if _spider:
            run_commands(commands["spider_output"])
        if _tech_detection: 
            run_commands(commands["tech_detection_output"])
        if _vulnscan: 
            run_commands(commands["vulnscan_output"])
    
    return

def output_prompt_for_excel():

    # prompt user if they want to update the excel file
    if not excel_file.exists():
        output_to_excel()
    else:
        if excel_file.exists():
            prompt_ = input(f"{excel_file} already exists, would you like to overwrite the worksheets for {selected_args_str}? (y/n): ").lower()
            if prompt_ == 'n':
                pass
            elif prompt_ == 'y':
                output_to_excel()
            else:
                print(f"invalid selection (y/n)")
                output_prompt_for_excel()
    
    return

def main():
    banner()
    handle_existing_files()

    # arg logic for -u and -l
    if _url and _list:
        parser.error("Either -u or -l must be provided, but not both.")
        
    run_checks()
    output_prompt_for_excel()

if __name__ == "__main__":
    main()



