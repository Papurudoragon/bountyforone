import sys
sys.path.append('src/')
import install_packages
import go_packages
import subprocess
from setuptools import setup, find_packages



# Read the list of dependencies from requirements.txt
def load_requirements(filename='requirements.txt'):
    with open(filename, 'r') as f:
        return f.read().splitlines()

setup(
    name='YourPackageName',
    version='0.1',
    packages=find_packages(),
    install_requires=load_requirements(),
)


# install go and go packages
install_packages.install_go()
install_packages.install_nmap()
go_packages.set_go_path()
go_packages.install_go_packages()