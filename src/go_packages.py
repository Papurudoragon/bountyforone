import subprocess

# install our go packages
def install_go_packages():
    try:
        subprocess.run([f"go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"], stdout=subprocess.PIPE, check=True)
        subprocess.run([f"go install -v github.com/owasp-amass/amass/v4/...@master"], stdout=subprocess.PIPE, check=True)
        subprocess.run([f"go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"], stdout=subprocess.PIPE, check=True)
        subprocess.run([f"go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"], stdout=subprocess.PIPE, check=True)
        subprocess.run([f"go install -v github.com/LukaSikic/subzy@latest"], stdout=subprocess.PIPE, check=True)
        subprocess.run([f"go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], stdout=subprocess.PIPE, check=True)
        subprocess.run([f"go install -v github.com/jaeles-project/gospider@latest"], stdout=subprocess.PIPE, check=True)

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while installing Go packages: {e}")
    return


