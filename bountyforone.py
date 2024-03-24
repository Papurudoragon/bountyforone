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
import urllib.parse
from pathlib import Path
import random
from colorama import Fore
import pyfiglet
import io
from contextlib import redirect_stdout
import tldextract
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry
import logging
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import warnings
import signal
import threading
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
from Wappalyzer import Wappalyzer, WebPage
from alive_progress import alive_bar
import httpx as http_client
import sys
from scapy.all import *
import socket
from comcrawl import IndexClient



# define our class for domain handling and output
class DomainName:
    
    # strips tld and subdomain, so example.com would return example
    def __init__(self, domain):
        extracted = tldextract.extract(domain)

        self.domain = extracted.domain.lower()
        # self.output = output

    # return just the domain not tld or subdoamin
    def get_dname(self): 
        return self.domain


# class to sanitze domains and extract only the domain and not .com etc
    
class DomainCheck:
    
    # strips tld and subdoamin, so example.com would return example
    def __init__(self, domain):
        self.domain = domain

    # return just the domain not tld or subdoamin
    def get_domain(self): 
        return self.domain
    
    def set_domain(self, domain):
        domain_regex = '^(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$'
        if not isinstance(domain, str):
            raise ValueError("Domain must be of type <str>!")
        if not re.match(domain_regex, domain):
            raise ValueError(f"{domain} is not a valid domain. please enter a valid domain.")

        self.domain = domain

# class for js links and url links
class LinkSort:
    def __init__(self, extracted_js=None):
        self.extracted_js = set(extracted_js) if extracted_js is not None else set()
        self.links_found = set()

    # getter for links_found
    def get_links(self):
        return self.links_found
    
    # getter for extracted_js
    def get_js(self):
        return self.extracted_js
        
    # setter for links_found
    def set_links(self, link: str):
        # append to set()
        self.links_found.add(link)

    # setter for extracted_js
    def set_js(self, js):
        self.extracted_js.add(js)


# initialize linksort_class
linksort_ = LinkSort()

# python banner text
banner_text = pyfiglet.figlet_format("BountyforOne")
author_text = "by Papv2"
desc_text = "One base, for many tools."

# arguments to add for url or file use
parser = argparse.ArgumentParser(description="Bounty for one - Bug bounty tool")
parser.add_argument("-u", "--url", help="Enter the domain name for a single target (e.g example.com)")

# args to run scripts
parser.add_argument("-s", "--subdomains", action='store_true', help="grab subdomains for a given domain")
parser.add_argument("-ls", "--live-subdomains", action='store_true', help="verify the status of a domain or file of doamins")
parser.add_argument("-ax", "--apex", action='store_true', help="Grab apex domains of a domain for file of domains")
parser.add_argument("-td", "--tech-detection", action='store_true', help="run technnology detection against a single url or list of domains")
parser.add_argument("-p", "--port", action='store_true', help="basic port scan on url or list of domains")
parser.add_argument("-vs", "--vulnscan", action='store_true', help="basic vuln scan on url or list of domains")
parser.add_argument("-cd", "--content-discovery", action='store_true', help="basic spider on url or list of domains")
parser.add_argument("-as", "--asn",  action='store_true', help="grab asn information for url or list of domains",)

args = parser.parse_args()

_url = args.url
_subdomains = args.subdomains
_livesubs = args.live_subdomains
_apex = args.apex
_tech_detection = args.tech_detection
_ports = args.port
_vulnscan = args.vulnscan
_content = args.content_discovery
_asn = args.asn

    
if _url is not None:
    url_output = DomainName(_url)


# selected args vars for later mapping and parsing with file handling
selected_args = []
if _subdomains: selected_args.append('subdomains')
if _apex: selected_args.append('apex')
if _tech_detection: selected_args.append('tech_detection')
if _ports: selected_args.append('ports')
if _vulnscan: selected_args.append('vulnscan')
if _content: selected_args.append('spider')
if _asn: selected_args.append('asn')
if _livesubs: selected_args.append('live_subs')

# string format
selected_args_str = ", ".join(selected_args)

selected_args = [] # this is for existing args
existing_files = [] # this is for existing files
sub_results = [] # for subdomains
sub_sorted_cleaned = [] # for cleaned subdomains
openp = [] # port scanner
filtereddp = [] # port scanner
asns_data = []

# base_dir = Path('output') / domain_name
max_memory = 0 # we gotta limit memory usage to handle processing with less RAM
curr_memory = 0 # we gotta limit memory usage to handle processing with less RAM
domain_regex = re.compile(r'(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}')

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
js_content_xlsx = []

output_dir = Path('output') / DomainName(args.url).get_dname()

# add output paths if not exist
if not os.path.exists(Path("output")):
    Path("output").mkdir(parents=True, exist_ok=True)

if not os.path.exists(Path("results")):
    Path("results").mkdir(parents=True, exist_ok=True)

if not os.path.exists(Path("data")):
    Path("data").mkdir(parents=True, exist_ok=True)

if not os.path.exists(Path(output_dir)):
    Path(output_dir).mkdir(parents=True, exist_ok=True)


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
excel_file =  Path('output') / DomainName(args.url).get_dname() / "bountyforone_spreadsheet.xlsx"

# Command flags
# apex location flag
apex_mdi = Path("bin") / "check_mdi.py"


def run_apex(url):
    
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
    with open(Path(output_dir) / f"{DomainName(args.url).get_dname()}_apex.txt", 'w', encoding='utf-8') as file:
        for domain in sorted(domains):
            file.write(f"{domain}\n")

    # Close the StringIO object
    f.close()



"""Subdomain flag"""
def crt_subdomain(url):
    global sub_results, domain_regex

    output_path = Path("output") / "crt_results.html"

    # grab subdomains from crt.sh first:
    crt_url = f"https://crt.sh/?q={url}"

    http = urllib3.PoolManager()
    try:
        # Use the PoolManager instance to make the request
        req = http.request(
            method="GET",
            url=crt_url,
            headers=headers,
            timeout=300
        )

        with open(output_path, "w", encoding='utf-8') as file:

            if req.status == 200:
                data = req.data.decode('utf-8').strip()

                file.write(data)

            time.sleep(3)
        
        with open(output_path, 'r', encoding='utf-8') as file:
            html_content = file.read()
            soup = BeautifulSoup(html_content, 'html.parser')

            # extract subdomains
            for td in soup.find_all('td'):
                sub_matches = domain_regex.findall(td.text)
                for match in sub_matches:
                    if url in match:
                        if match not in sub_results:
                            sub_results.append(f"{match}")
    
        return sub_results

    except urllib3.exceptions.HTTPError as e:
        print(f"HTTP error encountered: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    finally:
        http.clear() 
    
    return



# DNS Dumpster
def dns_Dumpster(url):
    global sub_results, domain_regex
    cookies = []

    # create our session
    session = requests.Session()

    # regex for getting subdomains


    # initialize URL
    dnsdump_url = "https://dnsdumpster.com/"

    # make a get req to grab the csrf_token
    response = session.get(dnsdump_url)

    #grab the cookies value, this is going to be used for the request later
    with open(Path("data") / "dnsdump_cookies.txt", 'w', encoding='utf-8') as f1:
        for cookie in session.cookies:
            f1.write(cookie.value) # ---> for troubleshooting only
            cookies.append(cookie.value)
            # print(''.join(cookies))

    # now make the post request to DNSdumsper

    headers = {
        'User-Agent': random.choice(user_agent),
        'Referer': 'https://dnsdumpster.com/',
        'Cookie': f"csrftoken={''.join(cookies)}"
    }

    data = {
        'csrfmiddlewaretoken': f"{''.join(cookies)}",
        'targetip': f'{url}',
        'user': 'free'
    }

    http = urllib3.PoolManager()

    response = session.post(
        dnsdump_url,
        headers=headers,
        data=data
    )            

    with open(Path("data") / "dnsdump_results.txt", 'w', encoding='utf-8') as f2:
        f2.write(response.text)

    with open(Path("data") / "dnsdump_results.txt", 'r', encoding='utf-8') as f2:
        html_content = f2.read()
        soup = BeautifulSoup(html_content, 'html.parser')

        # extract subdomains
        for td in soup.find_all('td'):
            sub_matches = domain_regex.findall(td.text)
            for match in sub_matches:
                if url in match:
                    if match not in sub_results:
                        sub_results.append(f"{match}")
                        # for line in sub_results:
                        #     print(f"{''.join(line)}\n")
    return



# suppress beautifuls soup warnings                        
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

def tech_detection(url):
    # Initialize wappalyzer
    wappalyzer = Wappalyzer.latest()

    # alive bar init

    with open(Path(output_dir) / f"{DomainName(args.url).get_dname()}_tech_detect.txt", "w", encoding='utf-8') as file:
        # for url in sub_sorted_cleaned:
        #     url = ''.join(url) # ---> used for a list instead of a single url
        success = False
        for protocol in ["http", "https"]:
            if success:
                break
            try: 
                webpage = WebPage.new_from_url(f"{protocol}://{url}", timeout=20)
                tech = wappalyzer.analyze_with_versions_and_categories(webpage)
                tech_str = ', '.join(tech)
                # print(f"{protocol}://{url} - {tech_str}\n") # for troubleshooting
                file.write(f"{protocol}://{url} - {tech_str}\n")
                success = True
            # except SSLError as ssl_error:
            #     print(f"SSLError encountered for {url} with {protocol}, retrying with different protocol: {ssl_error}")
            # used for troubleshooting only
            except ConnectionError as conn_error:
                pass
            except Exception as e:
                pass
    return

def live_sub_check(url):
    global headers

    # use python httpx for this --> renamed to http_client
    success = False

    with open(Path(output_dir) / f"{DomainName(args.url).get_dname()}_live_hosts.txt", "w", encoding='utf-8') as file:
        for protocol in ['http', 'https']:
            if success:
                break
            with http_client.Client(headers=headers, follow_redirects=True) as client:
                try:
                    req = client.get(f"{protocol}://{url}")
                    # print(f"{req.url} - {req.status_code}")
                    file.write(f"{req.url} - {req.status_code}")
                    success = True
                except Exception as e:
                    print(f"live sub check error: {e}")

    return


"""SYN scanner"""

def port_scan(url):
    print("portscan coming soon...")
    pass



"""content discovery"""

def send_request_wayback(url):
    global headers

    WAYBACK_URL = f'https://web.archive.org/cdx/search/cdx?url={url}&matchType=domain&collapse=urlkey&fl=original&filter=statuscode:200'

    http = urllib3.PoolManager()
    try:
        # Use the PoolManager instance to make the request
        req = http.request(
            method="GET",
            url=WAYBACK_URL,
            headers=headers,
            timeout=100
        )
        # Check if the status code is 200
        if req.status == 200:
            data = req.data.decode('utf-8').strip()  # Decode the response data

            # Start a separate thread for the set_links operation
            thread = threading.Thread(target=linksort_.set_links, args=(data.replace('http://', '').replace('https://', ''),))
            thread.start()
            thread.join()

            return linksort_.get_links()

        elif req.status == 429:
            print(f"429: archive.org rate limit reached, unable to get links from Wayback..")
            return
        
        elif req.status == 503:
            print(f"503: The server (archive.org) is unavailable for some reason, moving onto other checks..")
            return
        
        else:
            print(f"Request returned an unexpected status code: {req.status}")
            return None
    except urllib3.exceptions.HTTPError as e:
        print(f"HTTP error encountered: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    finally:
        http.clear()

def send_request_ccrawl(url):
    try:

        # we can wrap the function here in async
        client = IndexClient(["2019-51", "2023-50"])
        crawled_site = f"*.{DomainCheck(url).get_domain()}/*"

        client.search(crawled_site)
        client.results = [res for res in client.results if res['status'] == '200'][:1000000] # stop after 1 million results
        
        # return client.results
        for result in client.results:
            # print(f"{result.get('url')}\n")
            linksort_.set_links(f"{result.get('url')}")

    except Exception as e:
        print(f"error: {e}")
        
    else:
        pass

    return


def content_dicovery(url):
    send_request_wayback(url)
    send_request_ccrawl(url)


def vulnscan(url):
    print("vuln scan coming soon...")
    pass


# grab ASNs for given domain
def asn_grab(url):
    global asns_data

    response1 = requests.get(f"https://api.bgpview.io/search?query_term={url}", headers=headers) # randomize user agents
    if response1.status_code == 200:
        data = response1.json()
        if 'data' in data and 'asns' in data['data']:
            for asn in data['data']['asns']:
                asns_data.append(f"{asn['asn']}, {asn['name']}")
    
    response2 = requests.get("https://www.cidr-report.org/as2.0/autnums.html", headers=headers)
    if response2.status_code == 200:
        html_content = response2.text
        soup = BeautifulSoup(html_content, 'html.parser')
        for link in soup.find_all('a'):
            asn_text = link.text.strip()
            description_text = link.next_sibling.strip() if link.next_sibling else ""
            full_line_text = f"{asn_text} {description_text}"
            match = re.match(r'^AS(\d+)\s*(.*)$', full_line_text)
            if match:
                asns_data.append((match.group(1), match.group(2).split(',')[0].strip()))

    with open(Path(output_dir) / f"{DomainName(args.url).get_dname()}_asn.txt", "w", encoding='utf-8') as file1:
        for asn in asns_data:
            if (str(DomainName(_url).get_dname()).upper() in asn) or ((str(DomainName(_url).get_dname()) in asn)):
                file1.write(f"{asn}\n")

    # print(asns_data) # ---> only for troubleshooting
    
    return asns_data

# handle the existing files and fail if the user specifies a file that already exists ---> to remove later
def handle_existing_files():
    pass


def output_to_excel():
    global apex_xlsx, asn_xlsx, subdomain_xlsx, live_subdomains_xlsx, tech_xlsx, port_scan_xlsx, vuln_scan_xlsx, spider_xlsx

    # read several files and format for excel
    
    directory = os.path.dirname(Path(output_dir) / f"{DomainName(args.url).get_dname()}")

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

            # check if 'apex' is in the filename
            if "asn" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as asn_file:
                    asn_content = asn_file.read().splitlines()
                    for line in asn_content:
                        ip, domain = line.strip().split(',')
                        asn_xlsx.append((ip, domain))
                    print(asn_xlsx)

            # check if 'apex' is in the filename
            if "subdomain" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as subdomains_file:
                    sub_content = subdomains_file.read().splitlines()
                    for line in sub_content:
                        subdomain_xlsx.append(f"{line}\n")

            if "live_host" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as live_file:
                    for line in live_file:
                        host, status = line.strip().split('-')
                        live_subdomains_xlsx.append((host, status))

            if "tech" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as tech_file:
                    for line in tech_file:
                        host, tech = line.strip().split('-')
                        tech_xlsx.append((host, tech))

            if "portscan" in filename:
                # construct full path to the file if the file has apex in it
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as port_file:
                        for line in port_file:
                            host, port = line.strip().split('-')
                            port_scan_xlsx.append((host, port))

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

            if "content" in filename:
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
        df_live = pd.DataFrame(live_subdomains_xlsx, columns=['Subdomains', 'Status Code'])
        df_tech = pd.DataFrame(tech_xlsx, columns=['Subdomains', 'Tech Stack'])
        df_port = pd.DataFrame(port_scan_xlsx, columns=['Domain', 'Port'])
        df_vuln = pd.DataFrame(vuln_scan_xlsx, columns=['Vuln Check', 'Method', 'Severity', 'Domains', 'Findings'])
        df_content = pd.DataFrame(spider_xlsx, columns=['Content'])

        # export dataframes to xlsx
        df_apex.to_excel(writer, sheet_name='apex_domains')
        df_asn.to_excel(writer, sheet_name='asn_findings')
        df_subdomains.to_excel(writer, sheet_name='subdomains')
        df_live.to_excel(writer, sheet_name='live_subdomains')
        df_tech.to_excel(writer, sheet_name='tech_stack')
        df_port.to_excel(writer, sheet_name='port_scan')
        df_vuln.to_excel(writer, sheet_name='vuln_findings')
        df_content.to_excel(writer, sheet_name='content_discovery')

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
            sub_flag(_url)

        if _livesubs:
            live_sub_check(_url)

        if _ports:
            port_scan(_url) 

        if _content:
            content_dicovery(_url)
            with open(Path(output_dir) / f"{DomainName(args.url).get_dname()}_content.txt", "w", encoding='utf-8') as file:
                for line in linksort_.get_links():
                    file.write(f"{''.join(line)}\n")   

        if _tech_detection: 
            tech_detection(_url)

        if _vulnscan: 
            vulnscan(_url)
    
    # if _list:
    #     if _asn:
    #         asn_grab(_list)
    #     if _apex:
    #         run_apex(_list)
    #     if _subdomains: 
    #         sub_flag()
    #     if _livesubs:
    #         run_commands(commands['live_subs_output'])           
    #     if _ports:
    #         run_commands(commands["portscan_output"])
    #     if _content:
    #         run_commands(commands["spider_output"])
    #     if _tech_detection: 
    #         run_commands(commands["tech_detection_output"])
    #     if _vulnscan: 
    #         run_commands(commands["vulnscan_output"])
    
    return

def output_prompt_for_excel():
    global sub_sorted_cleaned

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


def sub_flag(url):
    global output_dir, _url

    crt_subdomain(DomainCheck(url).get_domain())
    dns_Dumpster(DomainCheck(url).get_domain())

    # deduplicate findings
    sub_sorted = list(set(sub_results))

    # clean the list a bit so all .com are on a new line
    with open(Path(output_dir) / f"{DomainName(args.url).get_dname()}_subdomains.txt", "w", encoding='utf-8') as file:

        # This is to clean up the files and add a new line to some of the .com results that got stuck together.
        for str in sub_sorted:
            parts = str.split('.com')
            if parts[-1] == '':
                cleaned = '.com\n'.join(parts[:-1]) + '.com'
            else:
                '.com\n'.join(parts)
            sub_sorted_cleaned.append(cleaned)

        # Now we can write to a file
        for subdomain in sub_sorted_cleaned:
            file.write(''.join(f"{subdomain}\n"))


def main():

    banner()
    # handle_existing_files()        
    
    run_checks()
    output_prompt_for_excel()

if __name__ == "__main__":
    main()



