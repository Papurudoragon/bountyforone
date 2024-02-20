import sys
import platform
import nmap_install
sys.path.append('src/')
import go_packages

# go installer
def install_go():
    try:
        current_os = platform.system()
        if not go_packages.is_go_installed():
            print(f"Go is not detected. Attempting installation for {current_os}...")
            current_os = platform.system()
            if current_os == "Windows":
                go_packages.install_go_windows()
            elif current_os == "Linux":
                go_packages.install_go_linux()
            elif current_os == "Darwin":  # macOS is recognized as 'Darwin'
                go_packages.install_go_mac()
            else:
                print("Unsupported operating system.")
                
            exit()  # Exit the script if the OS is not supported

        print("Setting up Go environment and installing packages")
        go_packages.set_go_path()
        go_packages.install_go_packages()

    except Exception as e:
        print(e)


# nmap insaller
def install_nmap():
    # nmap install check
    if not nmap_install.is_nmap_installed():
        print("Nmap is not installed. Installing...")
        if sys.platform.startswith("linux"):
            nmap_install.install_nmap_linux()
        elif sys.platform.startswith("darwin"):
            nmap_install.install_nmap_macos()
        elif sys.platform.startswith("win"):
            nmap_install.install_nmap_windows()
        else:
            print("Unsupported operating system.")
            sys.exit(1)
    else:
        print("Nmap is already installed.")

    print("Please ensure Nmap is added to your PATH if it's not already configured.")
