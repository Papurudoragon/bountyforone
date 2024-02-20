import subprocess
import os
import platform
from urllib.request import urlretrieve
import shutil
import time
import requests
from bs4 import BeautifulSoup
import tempfile
import shutil

class GoNotInstalledException(Exception):
    pass


def is_go_installed():
    """Check if Go is installed by searching for the 'go' command in PATH."""
    return shutil.which("go") is not None


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
        return False

    # Use a temporary file for the download to avoid name conflicts and cleanup issues
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        download_command = f"wget -O {tmpfile.name} '{go_linux_url}'"
        try:
            print("Downloading Go...")
            subprocess.run(download_command, shell=True, check=True)
            
            print("Extracting Go...")
            # Now extract directly using the temporary file path
            extract_command = f"sudo tar -C /usr/local -xzf {tmpfile.name}"
            subprocess.run(extract_command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Command failed: {e}")
            return False
        finally:
            # Clean up the downloaded file
            os.remove(tmpfile.name)
        
        print("Go installation successful. Please ensure /usr/local/go/bin is in your PATH.")
        return True

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
        gopath = "/usr/local/go"

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
        subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], stdout=subprocess.PIPE, check=True)
        subprocess.run(["go", "install", "-v", "github.com/jaeles-project/gospider@latest"], stdout=subprocess.PIPE, check=True)

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while installing Go packages: {e}")
    return


