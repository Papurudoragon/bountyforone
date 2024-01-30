import requests
from bs4 import BeautifulSoup
from pathlib import Path

# Function to parse HTML and extract specific data
def parse_html_and_save(url, selector, output_file):
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.select(selector)
        with open(output_file, 'w') as file:
            for link in links:
                file.write(link.get('href').replace('/detailed/', '').strip() + '\n')
    
    return

# Main function to process a domain
def process_domain(domain):
    # Directory setup
    d_name = domain.split(".")
    d_name = d_name[0]
    output_dir = Path("output") / d_name
    curdir = Path.cwd()
    domain_dir = curdir / 'output' / d_name / 'logs'
    domain_dir.mkdir(parents=True, exist_ok=True)

    # URLs to process
    company_url = f"https://builtwith.com/company/{domain}"
    relationships_url = f"https://builtwith.com/relationships/{domain}"
    
    # Parsing HTML and saving data
    parse_html_and_save(company_url, 'a[href^="/detailed/"]', domain_dir / f"{d_name}-company-associated-domains.txt")
    parse_html_and_save(relationships_url, 'a[href^="/relationships/"]', domain_dir / f"{d_name}-relationships.txt")
    
    return
