import subprocess
import os
from pathlib import Path
import time

class waymoreNotInstalledException(Exception):
    pass

# check for an install
def check_waymore():
    waymore_path = Path("src") / "waymore" / "waymore.py"
    try:
        if waymore_path.is_file():
            print(f"'waymore.py' found at {waymore_path}")
            return True
        else:
            print(f"'waymore.py' not found. attempting to install...")
            time.sleep(2)
            return False
    except Exception as e:
        print(e)
    return

# time for some waymore :) --> first we install it
def install_waymore():
    try:
        print(os.getcwd())
        requirements_path = Path("src") / "waymore" / "requirements.txt"
        install_path = Path("src") / "waymore"
        install_path.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git","clone", "https://github.com/xnl-h4ck3r/waymore.git", install_path], stdout=subprocess.PIPE, text=True)
        subprocess.run(["python3", "-m", "pip", "install", "-r", requirements_path], stdout=subprocess.PIPE, text=True)
    except Exception as e:
        print(e)
    return