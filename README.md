This tool simplifies the recon process for bugbounty and organizes all findings into an Excel Document. The idea behind this is to collect information for recon, and help with visualizing the data that is collected. 

![plot](src/image.png)


# Install Instructions:

(all OS):
  ```
  python3 bin_installer.py
  pip install -r requirements.txt
  ```


# Usage:

*usage:* bountyforone.py -u URL [-s] [-ls] [-ax] [-td] [-p] [-vs] [-cd] [-as]

**Bountyforone - Bug bounty tool**

```
options:
  -h, --help                    show this help message and exit
  -u URL, --url URL             Enter the domain name for the target [e.g example.com]
  -s, --subdomains              grab subdomains for a given domain
  -ls --live-subdomains         verify the status of a domain or file of doamins
  -ax, --apex                   Grab apex domains of a domain for file of domains
  -td, --tech-detection         run technnology detection against a single url or list of domains
  -p, --port                    basic port scan on url or list of domains
  -vs, --vulnscan               basic vuln scan on url or list of domains
  -cd, --content-discovery      basic spider on url or list of domains
  -as, --asn                    grab asn information for url or list of domains
  ```


example usage:
  **This example extracts technology stack from the specified url**
  ```
  python3 bountyforone.py -u example.txt -td 
  ```





