import requests
import platform
import os
from pathlib import Path
import shutil


# urls to download
httpx_base = 'https://github.com/projectdiscovery/httpx/releases/download/v1.4.0/httpx_1.4.0'
nuclei_base = 'https://github.com/projectdiscovery/nuclei/releases/download/v3.1.10/nuclei_3.1.10'
naabu_base = 'https://github.com/projectdiscovery/naabu/releases/download/v2.2.1/naabu_2.2.1'
subfinder_base = 'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.5/subfinder_2.6.5'
katana_base = 'https://github.com/projectdiscovery/katana/releases/download/v1.0.5/katana_1.0.5'




# these are all of the downloads that we need

def download_file(url, local_filename):
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

def get_download_url():
    os_arch = platform.machine().lower()
    os_type = platform.system().lower()

    # grab the file name based on OS and architecture
    if os_type == "linux":
        if os_arch in ["x86_64", "amd64"]:
            file_name = "linux_amd64.zip"
        elif os_arch == "arm64":
            file_name = "linux_arm64.zip"
        elif os_arch == "arm":
            file_name = "linux_arm.zip"
        else:
            file_name = "linux_386.zip"
    elif os_type == "darwin": # macOS
        if os_arch == "arm64":
            file_name = "macOS_arm64.zip"
        else:
            file_name = "macOS_amd64.zip"
    elif os_type == "windows":
        if os_arch in ["x86_64", "amd64"]:
            file_name = "windows_amd64.zip"
        else:
            file_name = "windows_386.zip"
    else:
        raise ValueError("Unsupported operating system.")

    return f"{file_name}"



# for httpx
httpx_url = f"{httpx_base}_{get_download_url()}"

# for nuclei
nuclei_url = f"{nuclei_base}_{get_download_url()}"

# for naabu
naabu_url = f"{naabu_base}_{get_download_url()}"

# for subfinder
subfinder_url = f"{subfinder_base}_{get_download_url()}"

# for katana
katana_url = f"{katana_base}_{get_download_url()}"


# save files in bin
localfile_httpx = Path('bin') / httpx_url.split("/")[-1]
localfile_nuclei = Path('bin') / nuclei_url.split("/")[-1]
localfile_naabu = Path('bin') / naabu_url.split("/")[-1]
localfile_subfinder = Path('bin') / subfinder_url.split("/")[-1]
localfile_katana = Path('bin') / katana_url.split("/")[-1]


# now we can download them all
download_file(httpx_url, localfile_httpx)
download_file(nuclei_url, localfile_nuclei)
download_file(naabu_url, localfile_naabu)
download_file(subfinder_url, localfile_subfinder)
download_file(katana_url, localfile_katana)


# new directory names
httpx_dir = Path('bin') / f"httpx"
nuclei_dir = Path('bin') / f"nuclei"
naabu_dir = Path('bin') / f"naabu"
subfinder_dir = Path('bin') / f"subfinder"
katana_dir = Path('bin') / f"katana"


# make directories for each
httpx_dir.mkdir(parents=True)
nuclei_dir.mkdir(parents=True)
naabu_dir.mkdir(parents=True)
subfinder_dir.mkdir(parents=True)
katana_dir.mkdir(parents=True)


# now we unzip them
shutil.unpack_archive(localfile_httpx, Path('bin') / "httpx")
shutil.unpack_archive(localfile_nuclei, Path('bin') / "nuclei")
shutil.unpack_archive(localfile_naabu, Path('bin') / "naabu")
shutil.unpack_archive(localfile_subfinder, Path('bin') / "subfinder")
shutil.unpack_archive(localfile_katana, Path('bin') / "katana")


# now we remove the zips
localfile_httpx.unlink()
localfile_nuclei.unlink()
localfile_naabu.unlink()
localfile_subfinder.unlink()
localfile_katana.unlink()