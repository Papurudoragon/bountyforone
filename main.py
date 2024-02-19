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
sys.path.append('bin/')
import go_packages
from pathlib import Path
import random
from colorama import Fore
import pyfiglet



# python banner text
banner_text = pyfiglet.figlet_format("BountyforOne")
author_text = "by Papv2"
desc_text = "One base, for all tools."

# arguments to add for custom use
parser = argparse.ArgumentParser(description="Bounty for one - Bug bounty tool")
parser.add_argument("-u", "--url", required=True, help="Enter the domain name for the target (e.g example.com)")
parser.add_argument("-s", "--subdomains", action='store_true', help="first discover subdomains and/or apex domains (if -ax), then run options against discovered subdomains (use flag by itself to gather only subdomains)")
parser.add_argument("-ax", "--apex", action='store_true', help="Grab apex domains (include this option to also run options against discovered apex domains)")
parser.add_argument("-td", "--tech-detection", action='store_true', help="run technnology detection against a single url (or discovere and run against apex and/or subdomains if -s is selected)")
parser.add_argument("-p", "--port", action='store_true', help="basic port scan on subdomains, apex, or url")
parser.add_argument("-vs", "--vulnscan", action='store_true', help="basic vuln scan on subdomains, apex, or url")
parser.add_argument("-sp", "--spider", action='store_true', help="basic spider on subdomains, apex, or url")
parser.add_argument("-as", "--asn",  action='store_true', help="grab asn information",)
parser.add_argument("-o", "--output", required=False, action='store_true', help="output results to a .txt file")
parser.add_argument("-oe", "--output-excel",  action='store_true', help="output results in excel format as well as txt")
parser.add_argument("-oa", "--output-all",  action='store_true', help="output results in all formats (txt, xlsx)")

# flag for all checks
parser.add_argument("-a", "--all", action='store_true', help="Run all checks default if only -u is selected with nothing else.")

args = parser.parse_args()

_url = args.url
_subdomains = args.subdomains
_apex = args.apex
_tech_detection = args.tech_detection
_ports = args.port
_vulnscan = args.vulnscan
_spider = args.spider
_asn = args.asn
_output = args.output
_outputexcel = args.output_excel
_outputall = args.output_all

# I want all to be default if nothing selected
_all = args.all

_outputs = any([_output, _outputexcel, _outputall])
_flags = any([_subdomains, _apex, _tech_detection, _ports, _vulnscan, _spider, _asn])



## Global vars
domain_name = _url.split(".")[0]
base_dir = Path('output') / domain_name
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
timeout = 300


## Output Section
###### ----------------------------------------------------------------------------------------------------------------------  

# assign output file names
apex = base_dir / f"apex_{domain_name}.txt"
asn = base_dir / f"asn_{domain_name}.txt"
subdomains = base_dir / f"subdomains_{domain_name}.txt"
live_subs = base_dir / f"live_subs_{domain_name}.txt"
sub_takeover = base_dir / f"sub_takeover_{domain_name}.txt"
tech = base_dir / f"tech_{domain_name}.txt"
portscan = base_dir / f"portscan_{domain_name}.txt"
vulnscan = base_dir / f"vulnscan_{domain_name}.txt"
spider = base_dir / f"spider_{domain_name}.txt"

# this is for the excel file
excel_file = base_dir / f"{domain_name}_recon_spreadsheet.xlsx"

# This is just here to add more output later and make it cleaner
all_output = (
    apex,
    asn,
    subdomains,
    live_subs,
    sub_takeover,
    tech,
    portscan,
    vulnscan,
    spider,
    excel_file
    )


# output file directory for the file names
output_path = Path("output") / domain_name
output_path.mkdir(parents=True, exist_ok=True)



# Command flags
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

gospider_flag_all = "-S"
gospider_flag_url = "-s"



# commands:
commands = {
    "apex": [
        f"python3 src/check_mdi-main/check_mdi.py -d {_url}"
    ],
    "apex_output": [
        f"python3 src/check_mdi-main/check_mdi.py -d {_url} >> {apex}"
    ],


    "subdomains_apex": [
        f"subfinder {subfinder_flag_all} {apex} -v",
        # f"amass enum -d {apex}",
        f"httpx {httpx_flag_all} {subdomains}"
    ],
    "subdomains_no_apex": [
        f"subfinder {subfinder_flag_url} {_url} -v",
        # f"amass enum -d {_url}",
        f"httpx {httpx_flag_all} {subdomains}"
    ],
    "subdomains_apex_output": [
        f"subfinder {subfinder_flag_all} {apex} -v -o {subdomains} ",
        # f"amass enum -d {apex}",
        f"httpx {httpx_flag_all} {subdomains} -v -o {live_subs}"
    ],
    "subdomains_no_apex_output": [
        f"subfinder {subfinder_flag_url} {_url} -v -o {subdomains}",
        # f"amass enum -d {_url}",
        f"httpx {httpx_flag_all} {subdomains} -o {live_subs}"
    ],


    "tech_detection": [
        f"httpx -sc -td -ip -method -cl {httpx_flag_all} {subdomains}"
    ],
    "tech_detection_url_only": [
        f"httpx -sc -td -ip -method -cl {httpx_flag_url} {_url}"
    ],
    "tech_detection_output": [
        f"httpx -sc -td -ip -method -cl {httpx_flag_all} {subdomains} -o {tech}"
    ],
    "tech_detection_url_only_output": [
        f"httpx -sc -td -ip -method -cl {httpx_flag_url} {_url} -o {tech}"
    ],



    "subdomain_takeover": [
        f"subzy run --targets {live_subs}"
    ],
    "subdomain_takeover_output": [
        f"subzy run --targets {live_subs} >> {sub_takeover}"
    ],


    "portscan": [
        f"naabu {naabu_flag_all} {subdomains} -v -p {naabu_ports}"
    ],
    "portscan_url_only": [
        f"naabu {naabu_flag_url} {_url} -v -p {naabu_ports}"
    ],
    "portscan_output": [
        f"naabu {naabu_flag_all} {subdomains} -v -p {naabu_ports} -o {portscan}"
    ],
    "portscan_url_only_output": [
        f"naabu {naabu_flag_url} {_url} -v -p {naabu_ports} -o {portscan}"
    ],


    "vulnscan": [
        f"nuclei {nuclei_flag_all} {live_subs} -t http/ -v"
    ],
    "vulnscan_url_only": [
        f"nuclei {nuclei_flag_url} {_url} -t http/ -v"
    ],
    "vulnscan_output": [
         f"nuclei {nuclei_flag_all} {live_subs} -t http/ -v -o {vulnscan}"
    ],
    "vulnscan_url_only_output": [
        f"nuclei {nuclei_flag_url} {_url} -t http/ -v -o {vulnscan}"
    ],


    "spider": [
        f"gospider {gospider_flag_all} {live_subs} -t 2 --js --sitemap --robots -v"
    ],
    "spider_url_only":[
        f"gospider {gospider_flag_url} https://{_url} -t 2 --js --sitemap --robots -v"
    ],
    "spider_output": [
        f"gospider {gospider_flag_all} {live_subs} -t 2 --js --sitemap --robots -v >> {spider}"
    ],
    "spider_url_only_output":[
        f"gospider {gospider_flag_url} https://{_url} -t 2 --js --sitemap --robots -v >> {spider}"
    ]
}


##### -----------------------------------------------------------------------------------------------------------------------------


"""The section below is to run commands"""


#### -----------------------------------------------------------------------------------------------------------------------------------

def run_apex():
    sorted_output = ""
    try:
        # iterate through the commands and run each of them
        for i in range(len(commands["apex"])):
            output = subprocess.check_output(commands["apex"][i], stderr=subprocess.STDOUT, text=True, shell=True, timeout=timeout)
            print(output)
            sorted_output += f"{output}\n"
            time.sleep(1)
            i += 1
    except subprocess.CalledProcessError as e:
        print(f'Command {commands["apex"]} failed with error: {e.stderr}')
    except subprocess.TimeoutExpired:
        print(f'Command timed out')
    
    # only extract domains, we can use regex for this
    domain_pattern = re.compile(r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    domains = set(domain_pattern.findall(sorted_output))
    
    with open(apex, 'w+') as f:
        for domain in sorted(domains):
            f.write(f"{domain}\n")


# this is to run all of the commands above (-a or --all flags
def run_commands(command):
    try:
        # iterate through the commands and run each of them
        for i in range(len(command)):

            if not any([_outputs]):

                # logic here can be if _output then subprocess to output, else then just run
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

            else:
                if any([_outputs]):

                    # its pointless to keep running through subdomains if the file is already created
                    if (_subdomains and command == commands["subdomains_apex_output"]) or (_subdomains and command == commands["subdomains_no_apex_output"]):
                        if subdomains.exists():
                            in_ = input(f"both {subdomains} and {live_subs} already exists, would you like to re-run the command and append (Y/N)?").lower()
                            if in_ == "y":
                                continue
                            elif in_ == "n":
                                # skip over live subs check
                                i += 2
                                continue
                                
                            
                    if (_ports and command == commands["portscan_output"]) or (_ports and command == commands["portscan_url_only_output"]):
                        if portscan.exists():
                            in_ = input(f"{portscan} already exists, would you like to re-run the command and append (Y/N)?").lower()
                            if in_ == "y":
                                continue
                            elif in_ == "n":
                                # skip over live subs check
                                i += 1
                                continue

                    
                    if (_spider and command == commands["spider_url_only_output"]) or (_spider and command == commands["spider_output"]):
                        if spider.exists():
                            in_ = input(f"{spider} already exists, would you like to re-run the command and append (Y/N)?").lower()
                            if in_ == "y":
                                continue
                            elif in_ == "n":
                                # skip over live subs check
                                i += 1
                                continue

                    
                    if (_tech_detection and command == commands["tech_detection_output"]) and (_tech_detection and command == commands["tech_detection_url_only_output"]):
                        if tech.exists():
                            in_ = input(f"{tech} already exists, would you like to re-run the command and append (Y/N)?").lower()
                            if in_ == "y":
                                continue
                            elif in_ == "n":
                                # skip over live subs check
                                i += 1
                                continue

                        
                    if (_vulnscan and command == commands["vulnscan_output"]) and (_vulnscan and command == commands["vulnscan_url_only_output"]):
                        if vulnscan.exists():
                            in_ = input(f"{portscan} already exists, would you like to re-run the command and append (Y/N)?").lower()
                            if in_ == "y":
                                continue
                            elif in_ == "n":
                                # skip over live subs check
                                i += 1 
                                continue 
                

                # logic here can be if _output then subprocess to output, else then just run
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
        print(f'Command {command} failed with error: {e.stderr}')
    except subprocess.TimeoutExpired:
        print(f'Command timed out')



# grab ASNs for given domain (part of the commands, technically)
def asn_grab():

    response = requests.get (f"https://api.bgpview.io/search?query_term={_url}", headers=headers) # randomize user agents
    if response.status_code == 200:
        data = response.json()

        if not any([_outputall]):
            if 'data' in data and 'ipv4_prefixes' in data['data']:
                for prefix in data['data']['ipv4_prefixes']:
                    print(f"{prefix['ip']}, {prefix['name']}")
        
        if _output:
            with open(asn, "w+") as file1:
                if 'data' in data and 'ipv4_prefixes' in data['data']:
                    for prefix in data['data']['ipv4_prefixes']:
                        file1.write(f"{prefix['ip']}, {prefix['name']}\n")
                        print(f"{prefix['ip']}, {prefix['name']}")

        
        else:
            print("no ASNs found")
    
    else:
        print(f"failed to fetch asn data: {response.status_code}")


# handle the existing files (prompt user) and do some stuff: #######
def handle_existing_files():
    existing_files = [file for file in all_output if file.exists()]
    if not existing_files:
        pass

    else:
        prompt = input("\n\nwould you like to overwrite existing data? (yes or no):\t")
        prompt = prompt.lower()



        if prompt == 'yes':
            if _all:
                for i in range(len(all_output)):
                    file_path = Path(all_output[i]) # this needs to iterate

                    # Delete the file is this option is selected.
                    if platform.system() == 'Windows':
                        subprocess.run(['del', file_path], check=True, shell=True)
                        i += 1
                        continue

                    else:
                        subprocess.run(['rm', file_path], check=True)
                        i += 1
                        continue

                print("files have been removed and will be recreated")
                time.sleep(5)

                return
        
            else:


                if _apex:
                    if platform.system() == 'Windows':
                        subprocess.run(['del', apex], check=True, shell=True)
                        

                    else:
                        subprocess.run(['rm', apex], check=True)
                    
                    return

    


                if _asn:
                    if platform.system() == 'Windows':
                        subprocess.run(['del', asn], check=True, shell=True)
                        

                    else:
                        subprocess.run(['rm', asn], check=True)

                    return
                    
            
                
                if _ports:
                    if platform.system() == 'Windows':
                        subprocess.run(['del', portscan], check=True, shell=True)
                        

                    else:
                        subprocess.run(['rm', portscan], check=True)

                    return

                

                if _subdomains:
                    if platform.system() == 'Windows':
                        subprocess.run(['del', subdomains], check=True, shell=True)
                        subprocess.run(['del', live_subs], check=True, shell=True)
                        

                    else:
                        subprocess.run(['rm', subdomains], check=True)
                        subprocess.run(['rm', live_subs], check=True)

                    return



                if _spider:
                    if platform.system() == 'Windows':
                        subprocess.run(['del', spider], check=True, shell=True)
                        

                    else:
                        subprocess.run(['rm', spider], check=True)

                    return



                if _tech_detection:
                    if platform.system() == 'Windows':
                        subprocess.run(['del', tech], check=True, shell=True)
                        

                    else:
                        subprocess.run(['rm', tech], check=True)

                    return
                


                if _vulnscan:
                    if platform.system() == 'Windows':
                        subprocess.run(['del', vulnscan], check=True, shell=True)
                        

                    else:
                        subprocess.run(['rm', vulnscan], check=True)

                    
                    return


        elif prompt == 'no':
            print("files will not be overwritten (This may take up more disc space and lead to duplicates)")
            time.sleep(5)
            return
        
        else:
            print("invalid option selected")
            handle_existing_files() # restart this function if invalid response


###### ---------------------------------------------------------------------------------------------------------------------------------------


def output_to_excel():
    """all_output = (
    apex,
    asn,
    subdomains,
    live_subs,
    sub_takeover,
    tech,
    portscan,
    vulnscan,
    spider
    )"""

    # read several files and format for excel
    
    try:
        with open(apex, 'r', encoding='utf-8') as apex_file:
            apex_content = apex_file.read().splitlines()
            for line in apex_content:
                apex_xlsx.append(f"{line}\n")
    except FileNotFoundError:
        pass

    try:
        with open(asn, 'r', encoding='utf-8') as asn_file:
            asn_content = asn_file.read().splitlines()
            for line in asn_content:
                asn_xlsx.append(f"{line}\n")
    except FileNotFoundError:
        pass

    try:
        with open(subdomains, 'r', encoding='utf-8') as subdomains_file:
            sub_content = subdomains_file.read().splitlines()
            for line in sub_content:
                subdomain_xlsx.append(f"{line}\n")
    except FileNotFoundError:
        pass

    
    try:
        with open(live_subs, 'r', encoding='utf-8') as live_file:
            live_content = live_file.read().splitlines()
            for line in live_content:
                live_subdomains_xlsx.append(f"{line}\n")
    except FileNotFoundError:
        pass


    # httpx results need a but more cleaning and formatting
    try:
        with open(tech, 'r', encoding='utf-8') as tech_file:
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
        with open(portscan, 'r', encoding='utf-8') as port_file:
                for line in port_file:
                    host, port = line.strip().split(':')
                    port_scan_xlsx.append((host, port))
    except FileNotFoundError:
        pass


    # nuclei needs a bit of formatting
    try:
        with open(vulnscan, 'r', encoding='utf-8') as vuln_file:
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
        with open(spider, 'r', encoding='utf-8') as spider_file:
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




def banner():

    # banner shoes usage if implemented without flags
    print(f"{Fore.GREEN}{banner_text}")
    print(f"{Fore.YELLOW}{author_text}")
    print(f"{Fore.YELLOW}{desc_text}")
    print(f"{Fore.CYAN}usage: python3 bountyforone.py -h/--help")
    time.sleep(3)

    
    return




# handle_existing_files()
# run_apex()
# asn_grab()
# run_commands()

def main():
    banner()

    # Set arg variables
    if _all:

        print("\n\n\nall flags selected, script will run all commands and output results in all available formats...\n\nPlease allow adequate time for completion...")
        time.sleep(5)

        # remove existing files if yes
        handle_existing_files()

        # asn grab
        asn_grab()

        # pull from the commands above
        run_apex()
        run_commands(commands["subdomains_apex_output"])
        run_commands(commands["tech_detection_output"])
        run_commands(commands["subdomain_takeover_output"])
        run_commands(commands["portscan_output"])
        run_commands(commands["vulnscan_output"])
        run_commands(commands["spider_output"])
    
        return


    if not _all:
         
        if not _all and not _flags and not _outputs:
 
            print("\n\n\nno flags selected, script will run all commands and output results by default...\n\nPlease allow adequate time for completion...")
            time.sleep(5)

            # remove existing files if yes
            handle_existing_files()

            # asn grab
            asn_grab()

            # pull from the commands above
            run_apex()
            run_commands(commands["subdomains_apex_output"])
            run_commands(commands["tech_detection_output"])
            run_commands(commands["subdomain_takeover_output"])
            run_commands(commands["portscan_output"])
            run_commands(commands["vulnscan_output"])
            run_commands(commands["spider_output"])

            output_to_excel()

            return



        if _asn:
            handle_existing_files()
            asn_grab()


        # if subdomains or apex is specified
        if not _subdomains and not _apex:
            if not any([_outputs]):
                if _ports:
                    run_commands(commands["portscan_url_only"])
                    
                
                if _tech_detection:
                    run_commands(commands["tech_detection_url_only"])

                if _vulnscan:
                    run_commands(commands["vulnscan_url_only"])

                if _spider:
                    run_commands(commands["spider_url_only"])

                return
            
            if _output:
                # remove existing files if yes
                handle_existing_files()
                if _ports:
                    run_commands(commands["portscan_url_only_output"])
                
                if _tech_detection:
                    run_commands(commands["tech_detection_url_only_output"])

                if _vulnscan:
                    run_commands(commands["vulnscan_url_only_output"])

                if _spider:
                    run_commands(commands["spider_url_only_output"])

                return
            
            if _outputexcel:
                # remove existing files if yes
                handle_existing_files()
                if _ports:
                    run_commands(commands["portscan_url_only_output"])
                
                if _tech_detection:
                    run_commands(commands["tech_detection_url_only_output"])

                if _vulnscan:
                    run_commands(commands["vulnscan_url_only_output"])

                if _spider:
                    run_commands(commands["spider_url_only_output"])
                
                output_to_excel()
                return




        # is subdomains is specified but not apex (output automatically for subdomains for file read)
        if not _apex:
            if not any([_outputs]):

                if _subdomains:

                    run_commands(commands["subdomains_no_apex_output"])

                if _ports:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])
                        

                    run_commands(commands["portscan"])

                
                if _tech_detection:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])
                    
                    run_commands(commands["tech_detection"])

                
                if _spider:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])
                    
                    run_commands(commands["spider"])

                
                if _vulnscan:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])
                    
                    run_commands(commands["vulnscan"])

                return
            
            if _output:
                # remove existing files if yes
                handle_existing_files()
                if _subdomains:

                    run_commands(commands["subdomains_no_apex_output"])
    

                if _ports:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])

                    run_commands(commands["portscan_output"])

                
                if _tech_detection:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])
                    
                    run_commands(commands["tech_detection_output"])

                
                if _spider:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])
                    
                    run_commands(commands["spider_output"])
     
                
                if _vulnscan:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])
                    
                    run_commands(commands["vulnscan_output"])

                return

            if _outputexcel:
                # remove existing files if yes
                handle_existing_files()
                if _subdomains:

                    run_commands(commands["subdomains_no_apex_output"])

                if _ports:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])

                    run_commands(commands["portscan_output"])

                
                if _tech_detection:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])
                    
                    run_commands(commands["tech_detection_output"])

                
                if _spider:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])
                    
                    run_commands(commands["spider_output"])

                
                if _vulnscan:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_no_apex_output"])
                    
                    run_commands(commands["vulnscan_output"])
                
                output_to_excel()

                return

        

        # run the apex domains
        if _apex:
            if not any([_outputs]):
                run_apex()
                
                if _subdomains:

                    run_commands(commands["subdomains_apex"])
          
                
                if _ports:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex"])

                    run_commands(commands["portscan"])
              
                
                if _tech_detection:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex"])
                    
                    run_commands(commands["tech_detection"])
            
                
                if _spider:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex"])
                    
                    run_commands(commands["spider"])
           
                
                if _vulnscan:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex"])
                    
                    run_commands(commands["vulnscan"])
                
                return
            
            if _output:
                # remove existing files if yes
                handle_existing_files()
                run_apex()
                
                if _subdomains:

                    run_commands(commands["subdomains_apex_output"])
                
                if _ports:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex_output"])

                    run_commands(commands["portscan_output"])
                
                if _tech_detection:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex_output"])
                    
                    run_commands(commands["tech_detection_output"])
                
                if _spider:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex_output"])
                    
                    run_commands(commands["spider_output"])
                
                if _vulnscan:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex_output"])
                    
                    run_commands(commands["vulnscan_output"])
                
                return
            
            if _outputexcel:
                # remove existing files if yes
                handle_existing_files()
                run_apex()
                
                if _subdomains:

                    run_commands(commands["subdomains_apex_output"])
                
                if _ports:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex_output"])

                    run_commands(commands["portscan_output"])
                
                if _tech_detection:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex_output"])
                    
                    run_commands(commands["tech_detection_output"])
                
                if _spider:
                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex_output"])
                    
                    run_commands(commands["spider_output"])
                
                if _vulnscan:

                    if not subdomains.exists():
                        run_commands(commands["subdomains_apex_output"])
                    
                    run_commands(commands["vulnscan_output"])
                
                output_to_excel()
                return


            ################# LEFT OFF HERE


if __name__ == "__main__":
    main()



#### To Do
    
##### I need to add outputs for all and also the xlsx outputs   ---> so far only .txt (-o) is completed

# arg help page
# create requirements and package up
# change the way apex and asn handle -o (give it a non -o output)
# readme.md
# Add threading
# requirements.txt ---> inatall paths include go_requirements.py - include that in main
# add more tools
##### add more args
# optimize
# grab js, parameters
# fyi - if you want to specify a subdomain, just save it in an output folder as "output/domain/domain_subdomains.txt"
# add shodan subdomain support
# add github enum
# add bbot enum
# add permutations