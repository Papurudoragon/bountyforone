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
import random
import requirements


# arguments to add for custom use
parser = argparse.ArgumentParser(description="Bounty for one - Bug bounty tool")
parser.add_argument("-u", "--url", required=True, help="Enter the domain name for the target (e.g example.com)")
parser.add_argument("-s", "--subdomains", action='store_true', help="first discover subdomains and/or apex domains (if -ax), then run options against discovered subdomains")
parser.add_argument("-ax", "--apex", action='store_true', help="Grab apex domains (include this option to also run options against discovered apex domains)")
parser.add_argument("-td", "--tech-detection", action='store_true', help="run technnology detection against a single url (or discovere and run against apex and/or subdomains if -s is selected)")
parser.add_argument("-p", "--port", action='store_true', help="basic port scan on subdomains, apex, or url")
parser.add_argument("-vs", "--vulnscan", action='store_true', help="basic vuln scan on subdomains, apex, or url")
parser.add_argument("-sp", "--spider", action='store_true', help="basic spider on subdomains, apex, or url")
parser.add_argument("-as", "--asn",  action='store_true', help="grab asn information",)
parser.add_argument("-o", "--output", required=False, action='store_true', help="output results to a .txt file")
parser.add_argument("-oe", "--output-excel",  action='store_true', help="output results in excel format")
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
tech_xlsx = []
port_scan_xlsx = []
vuln_scan_xlsx = []
dir_search_xlsx = []
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
    spider
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
    "subdomain_no_apex": [
        f"subfinder {subfinder_flag_url} {_url} -v",
        # f"amass enum -d {_url}",
        f"httpx {httpx_flag_all} {subdomains}"
    ],
    "subdomains_apex_output": [
        f"subfinder {subfinder_flag_all} {apex} -v -o {subdomains} ",
        # f"amass enum -d {apex}",
        f"httpx {httpx_flag_all} {subdomains} -v -o {live_subs}"
    ],
    "subdomain_no_apex_output": [
        f"subfinder {subfinder_flag_url} {_url} -v -o {subdomains}",
        # f"amass enum -d {_url}",
        f"httpx {httpx_flag_all} {subdomains} -o {live_subs}"
    ],


    "tech_detection": [
        f"httpx -sc -td -ip -method -title -cl -server {httpx_flag_all} {subdomains}"
    ],
    "tech_detection_url_only": [
        f"httpx -sc -td -ip -method -title -cl -server {httpx_flag_url} {_url}"
    ],
    "tech_detection_output": [
        f"httpx -sc -td -ip -method -title -cl -server {httpx_flag_all} {subdomains} -o {tech}"
    ],
    "tech_detection_url_only_output": [
        f"httpx -sc -td -ip -method -title -cl -server {httpx_flag_url} {_url} -o {tech}"
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
        f"nuclei {nuclei_flag_all} {subdomains} -t /"
    ],
    "vulnscan_url_only": [
       f"nuclei {nuclei_flag_url} {_url} -t /"
    ],
    "vulnscan_output": [
        f"nuclei {nuclei_flag_all} {subdomains} -t / -o {vulnscan}"
    ],
    "vulnscan_url_only_output": [
       f"nuclei {nuclei_flag_url} {_url} -t / -o {vulnscan}"
    ],


    "spider": [
        f"gospider {gospider_flag_all} {subdomains} -t 2 --js --sitemap --robots -v"
    ],
    "spider_url_only":[
        f"gospider {gospider_flag_url} {_url} -t 2 --js --sitemap --robots -v"
    ],
    "spider_output": [
        f"gospider {gospider_flag_all} {subdomains} -t 2 --js --sitemap --robots -v -o {spider}"
    ],
    "spider_url_only_output":[
        f"gospider {gospider_flag_url} {_url} -t 2 --js --sitemap --robots -v -o {spider}"
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
def run_commands(commands):
    try:
        # iterate through the commands and run each of them
        for i in range(len(commands)):

            # logic here can be if _output then subprocess to output, else then just run
            output = subprocess.check_output(commands[i], stderr=subprocess.STDOUT, text=True, shell=True, timeout=timeout)
            print(output)
            time.sleep(1)
            
####################################

            i += 1
    except subprocess.CalledProcessError as e:
        print(f'Command {commands} failed with error: {e.stderr}')
    except subprocess.TimeoutExpired:
        print(f'Command timed out')



# grab ASNs for given domain (part of the commands, technically)
def asn_grab():

    response = requests.get (f"https://api.bgpview.io/search?query_term={_url}", headers=headers) # randomize user agents
    if response.status_code == 200:
        data = response.json()

        if 'data' in data and 'ipv4_prefixes' in data['data']:
            for prefix in data['data']['ipv4_prefixes']:
                print(f"{prefix['ip']}, {prefix['name']}")
        
        else:
            print("no ASNs found")
    
    else:
        print(f"failed to fetch asn data: {response.status_code}")


# handle the existing files (prompt user) and do some stuff:
def handle_existing_files():
    existing_files = [file for file in all_output if file.exists()]
    if not existing_files:
        pass

    else:
        prompt = input("\n\nwould you like to overwrite existing data? (yes or no):\t")
        prompt = prompt.lower()

        if prompt == 'yes':
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

        elif prompt == 'no':
            print("files will be appended to existing results (This may take up more disc space and lead to duplicates)")
            time.sleep(5)
            return
        
        else:
            print("invalid option selected")
            handle_existing_files() # restart this function if invalid response


###### ---------------------------------------------------------------------------------------------------------------------------------------
















# handle_existing_files()
# run_apex()
# asn_grab()
# run_commands()

def main():

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

            return



        if _asn:
            asn_grab()
            return





        if not _subdomains and not _apex:
            if not any([_outputs]):
                if _ports:
                    run_commands(commands["portscan_url_only"])
                    
                    return
                
                if _tech_detection:
                    run_commands(commands["tech_detection_url_only"])
                    return

                if _vulnscan:
                    run_commands(commands["vulnscan_url_only"])
                    return

                if _spider:
                    run_commands(commands["spider_url_only"])
                    return
            
            if _output:
                # remove existing files if yes
                handle_existing_files()
                if _ports:
                    run_commands(commands["portscan_url_only_output"])
                    
                    return
                
                if _tech_detection:
                    run_commands(commands["tech_detection_url_only_output"])
                    return

                if _vulnscan:
                    run_commands(commands["vulnscan_url_only_output"])
                    return

                if _spider:
                    run_commands(commands["spider_url_only_output"])
                    return





        if not _apex:
            if not any([_outputs]):

                if _subdomains:

                    run_commands(commands["subdomain_no_apex"])
                    return

                if _ports:

                    if not subdomains.exists():
                        run_commands(commands["subdomain_no_apex"])

                    run_commands(commands["portscan"])
                    return
                
                if _tech_detection:
                    if not subdomains.exists():
                        run_commands(commands["subdomain_no_apex"])
                    
                    run_commands(commands["tech_detection"])
                    return
                
                if _spider:
                    if not subdomains.exists():
                        run_commands(commands["subdomain_no_apex"])
                    
                    run_commands(commands["spider"])
                    return
                
                if _vulnscan:

                    if not subdomains.exists():
                        run_commands(commands["subdomain_no_apex"])
                    
                    run_commands(commands["vulnscan"])
                    return
            
            if _output:
                # remove existing files if yes
                handle_existing_files()
                if _subdomains:

                    run_commands(commands["subdomain_no_apex_output"])
                    return

                if _ports:

                    if not subdomains.exists():
                        run_commands(commands["subdomain_no_apex_output"])

                    run_commands(commands["portscan_output"])
                    return
                
                if _tech_detection:
                    if not subdomains.exists():
                        run_commands(commands["subdomain_no_apex_output"])
                    
                    run_commands(commands["tech_detection_output"])
                    return
                
                if _spider:
                    if not subdomains.exists():
                        run_commands(commands["subdomain_no_apex_output"])
                    
                    run_commands(commands["spider_output"])
                    return
                
                if _vulnscan:

                    if not subdomains.exists():
                        run_commands(commands["subdomain_no_apex_output"])
                    
                    run_commands(commands["vulnscan_output"])
                    return

        


        if _apex:
            if not any([_outputs]):
                run_apex()
                
                if _subdomains:

                    run_commands(commands["subdomains_apex"])
                    return
                
                if _ports:

                    if not subdomains.exists():
                        run_commands(commands["subdomain_apex"])

                    run_commands(commands["portscan"])
                    return
                
                if _tech_detection:
                    if not subdomains.exists():
                        run_commands(commands["subdomain_apex"])
                    
                    run_commands(commands["tech_detection"])
                    return
                
                if _spider:
                    if not subdomains.exists():
                        run_commands(commands["subdomain_apex"])
                    
                    run_commands(commands["spider"])
                    return
                
                if _vulnscan:

                    if not subdomains.exists():
                        run_commands(commands["subdomain_apex"])
                    
                    run_commands(commands["vulnscan"])
                    return
            
            if _output:
                # remove existing files if yes
                handle_existing_files()
                run_apex()
                
                if _subdomains:

                    run_commands(commands["subdomains_apex_output"])
                    return
                
                if _ports:

                    if not subdomains.exists():
                        run_commands(commands["subdomain_apex_output"])

                    run_commands(commands["portscan_output"])
                    return
                
                if _tech_detection:
                    if not subdomains.exists():
                        run_commands(commands["subdomain_apex_output"])
                    
                    run_commands(commands["tech_detection_output"])
                    return
                
                if _spider:
                    if not subdomains.exists():
                        run_commands(commands["subdomain_apex_output"])
                    
                    run_commands(commands["spider_output"])
                    return
                
                if _vulnscan:

                    if not subdomains.exists():
                        run_commands(commands["subdomain_apex_output"])
                    
                    run_commands(commands["vulnscan_output"])
                    return




            ################# LEFT OFF HERE




if __name__ == "__main__":
    main()









#### To Do
    
##### I need to add outputs for all and also the xlsx outputs   ---> so far only .txt (-o) is completed

# arg help page
# readme.md
# requirements.txt ---> inatall paths include go_requirements.py - include that in main
# add more tools
##### add more args
# optimize
# grab js, parameters
# fyi - if you want to specify a subdomain, just save it in an output folder as "output/domain/domain_subdomains.txt"
