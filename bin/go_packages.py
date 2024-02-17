import subprocess
import os
import platform
from urllib.request import urlretrieve
import shutil
import time
import requests
from bs4 import BeautifulSoup

class GoNotInstalledException(Exception):
    pass

def is_go_installed():
    """Check if Go is installed by attempting to run 'go version'."""
    try:
        subprocess.run(["go", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except Exception as e:
        print(f"{e}")
        return False

def download_file(url, filename):
    try:
        print(f"Downloading from {url}")
        urlretrieve(url, filename)
        print("Download completed.")
        return True
    except Exception as e:
        print(f"Error downloading file: {e}")
        return False

def get_latest_go_version_url(operating_system):
    try:
        response = requests.get('https://golang.org/dl/')
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            file_extension = ""
            if operating_system == "Windows":
                file_extension = "windows-amd64.msi"
            elif operating_system == "Linux":
                file_extension = "linux-amd64.tar.gz"
            elif operating_system == "macOS":
                file_extension = "darwin-amd64.pkg"

            for link in soup.find_all('a'):
                href = link.get('href')
                if href and file_extension in href:
                    return 'https://golang.org' + href
        return None
    except Exception as e:
        print(f"Error occurred: {e}")
        return None

def install_go_windows():
    go_installer_url = get_latest_go_version_url("Windows")
    if not go_installer_url:
        print("Failed to find the latest Go version URL for Windows.")
        return

    installer_filename = "go_installer.msi"

    if download_file(go_installer_url, installer_filename):
        print("Running Go installer...")
        os.startfile(installer_filename)
        print("Please complete the installation with the GUI installer.")

        while not is_go_installed():
            print("Waiting for Go installation to complete...")
            time.sleep(5)
    
    # remove the installer if it exists - we dont need it anymore after install
    if is_go_installed():
            if os.path.exists(installer_filename):
                os.remove(installer_filename)
    return


def install_go_linux():
    go_linux_url = get_latest_go_version_url("Linux")
    if not go_linux_url:
        print("Failed to find the latest Go version URL for Linux.")
        return

    install_command = f"wget {go_linux_url} && sudo tar -C /usr/local -xzf {go_linux_url.split('/')[-1]} && rm {go_linux_url.split('/')[-1]}"
    subprocess.run(install_command, shell=True, check=True)
    return

def install_go_mac():
    go_mac_url = get_latest_go_version_url("macOS")
    pkg_file = go_mac_url.split('/')[-1]
    if not go_mac_url:
        print("Failed to find the latest Go version URL for macOS.")
        return

    install_command = f"curl -O {go_mac_url} && sudo installer -pkg {pkg_file} -target /"
    subprocess.run(install_command, shell=True, check=True)

    # remove the installer if it exists - we dont need it anymore after install
    if os.path.exists(pkg_file):
        os.remove(pkg_file)

    return


def set_go_path():
    operating_system = platform.system()
    if operating_system == "Windows":
        gopath = os.path.join(os.environ['USERPROFILE'], 'go')
    else:
        gopath = os.path.join(os.environ['HOME'], 'go')

    os.environ['GOPATH'] = gopath
    os.environ['PATH'] = os.path.join(gopath, 'bin') + os.pathsep + os.environ['PATH']

    print(f"GOPATH set to: {gopath}")
    print(f"PATH updated to include: {os.path.join(gopath, 'bin')}")
    return

# This is where we install our packages
def install_go_packages():
    try:
        subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"], stdout=subprocess.PIPE, check=True)
        subprocess.run(["go", "install", "-v", "github.com/owasp-amass/amass/v4/...@master"], stdout=subprocess.PIPE, check=True)
        subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"], stdout=subprocess.PIPE, check=True)
        subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"], stdout=subprocess.PIPE, check=True)
        subprocess.run(["go", "install", "-v", "github.com/LukaSikic/subzy@latest"], stdout=subprocess.PIPE, check=True)

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while installing Go packages: {e}")
    return


