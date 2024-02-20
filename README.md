This tool simplifies the recon process for bugbounty and organizes all findings into an Excel Document

# Install Instructions:

(all OS):
  ```
  python3 bin_installer.py
  pip install -r requirements.txt
  ```

**linux ONLY**" 
** This command MUST also be run for linux systems for the script to work**
  ```
  sudo chmod +x bin/*/*
  ```


# usage:

*usage:* bountyforone.py -u/-l URL [-s] [-ax] [-td] [-p] [-vs] [-sp] [-as] [-o] [-oe] [-oa] [-a]

**Bountyforone - Bug bounty tool**

```
options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Enter the domain name for the target (e.g example.com)
  -s, --subdomains      first discover subdomains and/or apex domains (if -ax), then run options against discovered subdomains
  -ax, --apex           Grab apex domains (include this option to also run options against discovered apex domains)
  -td, --tech-detection run technnology detection against a single url (or discovere and run against apex and/or subdomains if -s is selected)
  -p, --port            basic port scan on subdomains, apex, or url
  -vs, --vulnscan       basic vuln scan on subdomains, apex, or url
  -sp, --spider         basic spider on subdomains, apex, or url
  -as, --asn            grab asn information
  -o, --output          output results to a .txt file
  -oe, --output-excel   output results in excel format as well as txt
  -oa, --output-all     output results in all formats (txt, xlsx)
  -a, --all             Run all checks default if only -u is selected with nothing else.
  ```


example usage:
  **This example extracts subdomains, technology stack, and ports from the gathered subdomains**
  `python3 bountyforone.py -l example.com -s -td -p`





