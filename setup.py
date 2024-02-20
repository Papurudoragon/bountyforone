import sys
sys.path.append('src/')
import install_packages
import subprocess


# install requirements.txt
subprocess.run([f"python3", "-m", "pip", "install", "-r", "requirements.txt"], stderr=subprocess.STDOUT, text=True, shell=True, timeout=300)


# check for go installation and install if missing, this is necessary for the script
install_packages.install_go()
install_packages.install_nmap()
