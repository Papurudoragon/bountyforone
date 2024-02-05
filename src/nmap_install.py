# this is only needed for the httpx -p flag

import subprocess
import requests
import os
from pathlib import Path
from bs4 import BeautifulSoup

def get_latest_nmap_installer_url():
    download_page_url = "https://nmap.org/download.html"
    response = requests.get(download_page_url)
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Look for the download link for the Windows installer
    for a in soup.find_all('a', href=True):
        if 'nmap-' in a['href'] and 'setup.exe' in a['href']:
            return a['href']
    return None

def download_file(url, local_filename):
    print(f"Downloading: {url}")
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    return local_filename

def install_nmap_linux():
    print("Installing Nmap on Linux...")
    subprocess.check_call(["sudo", "apt-get", "update"])
    subprocess.check_call(["sudo", "apt-get", "install", "-y", "nmap"])
    print("Nmap installation on Linux completed.")
    return

def install_nmap_macos():
    print("Installing Nmap on macOS using Homebrew...")
    subprocess.check_call(["/bin/bash", "-c", "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"], shell=True)
    subprocess.check_call(["brew", "install", "nmap"])
    print("Nmap installation on macOS completed.")
    return

def install_nmap_windows():
    installer_url = get_latest_nmap_installer_url()
    if installer_url is None:
        print("Failed to find the Nmap installer URL.")
        return

    installer_path = download_file(installer_url, "nmap_installer.exe")
    print("Opening Nmap installer...")
    try:
        process = subprocess.Popen(installer_path)
        process.wait()  # Wait for the installation process to complete
        print("Nmap installation on Windows completed.")
        nmap_path = "C:\\Program Files (x86)\\Nmap"  # Adjust if your installation path is different
        if nmap_path not in os.environ["PATH"]:
            os.environ["PATH"] += os.pathsep + nmap_path
    except Exception as e:
        print(f"Installation failed: {e}")
    finally:
        os.remove(installer_path)
        print("Installer file removed.")

def is_nmap_installed():
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False