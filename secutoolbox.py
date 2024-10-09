import subprocess

RESET = '\033[0m'
BOLD = '\033[1m'
LCYAN = '\033[96m'
RED = '\033[91m'
LPURPLE = '\033[94m'
GREEN = '\033[92m'

def run_ffuf_subdomain(url, wordlist):
    try:
        command = f"ffuf -u 'http://{url}' -H 'Host: FUZZ.{url}' -w {wordlist} -c -t 100 -fw 1546"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running ffuf: {e}{RESET}")

def run_ffuf(url, wordlist):
    try:
        command = f"ffuf -u {url}/FUZZ -w {wordlist} -t 100"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running ffuf: {e}{RESET}")

def run_nmap_full(target):
    try:
        command = f"sudo nmap -sC -sV -O --open -p- -oA full {target} -Pn"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running nmap: {e}{RESET}")

def run_nmap_udp(target):
    try:
        command = f"sudo nmap -Pn -sU -sV -sC --top-ports=20 -oN top_20_udp_nmap.txt {target}"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running nmap: {e}{RESET}")

def run_whatweb(url):
    try:
        command = f"whatweb {url}"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running whatweb: {e}{RESET}")

def run_wfuzz(url, wordlist):
    try:
        command = f"wfuzz -c -z file,{wordlist} --hc 404 {url}/FUZZ"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running wfuzz: {e}{RESET}")

def run_gobuster_dir(url, wordlist):
    try:
        command = f"gobuster dir -u {url} -w {wordlist} -t 100"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running gobuster: {e}{RESET}")

def run_gobuster_dns(url, wordlist):
    try:
        command = f"gobuster dns -d {url} -t 50 -w {wordlist}"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running gobuster: {e}{RESET}")

def run_gobuster_vhost(url, wordlist):
    try:
        command = f"gobuster vhost -u {url} -t 50 -w {wordlist} --append-domain"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running gobuster: {e}{RESET}")

def run_dirsearch(url, wordlist):
    try:
        command = f"dirsearch -u {url} -e txt,bak,php,html,js,asp,aspx -x 403,404 -w {wordlist}"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running dirsearch: {e}{RESET}")

def run_smbclient(url):
    try:
        command = f"smbclient -L \\\\{url} -N"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running smbclient: {e}{RESET}")

def run_smbmap(url):
    try:
        command = f"smbmap -u '' -p '' -H {url}"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running smbmap: {e}{RESET}")

def run_evilwinrm_password(url, username, password):
    try:
        command = f"evil-winrm -i {url} -u {username} -p '{password}'"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running evilwinrm: {e}{RESET}")

def run_evilwinrm_hash(url, username, hash):
    try:
        command = f"evil-winrm -i {url} -u {username} -H {hash}"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running evilwinrm: {e}{RESET}")

def run_crackmapexec_smb_password(url, username, password):
    try:
        command = f"sudo crackmapexec smb {url} -u {username} -p '{password}' -x whoami --local-auth"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running crackmapexec: {e}{RESET}")

def run_crackmapexec_smb_hash(url, username, hash):
    try:
        command = f"sudo crackmapexec smb {url} -u {username} -H {hash} -x whoami --local-auth"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running crackmapexec: {e}{RESET}")

def run_crackmapexec_evil_password(url, username, password):
    try:
        command = f"sudo crackmapexec winrm {url} -u {username} -p '{password}' -x whoami --local-auth"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running crackmapexec: {e}{RESET}")

def run_crackmapexec_evil_hash(url, username, hash):
    try:
        command = f"sudo crackmapexec winrm {url} -u {username} -H {hash} -x whoami --local-auth"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running crackmapexec: {e}{RESET}")

def run_rpcclient(url):
    try:
        command = f"rpcclient -U '' -N {url}"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running rpcclient: {e}{RESET}")

def run_enum4linux(url):
    try:
        command = f"enum4linux -a {url}"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running enum4linux: {e}{RESET}")

def run_snmpwalk_all(url):
    try:
        command = f"snmpwalk -c public -v1 -t 10 {url}"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running snmpwalk: {e}{RESET}")

def run_snmpwalk_extend(url):
    try:
        command = f"snmpwalk -v1 -c public {url} NET-SNMP-EXTEND-MIB::nsExtendObjects"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running snmpwalk: {e}{RESET}")

def run_xfreerdp(url, username, password):
    try:
        command = f"xfreerdp /u:{username} /p:{password} /v:{url}"
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"{RED}Error running xfreerdp: {e}{RESET}")

def main():
    print(f"{LCYAN}{BOLD}"
        f"                                                                                \n"
        f" ,---.                       ,--------.             ,--.,--.                    \n"
        f"'   .-'  ,---.  ,---.,--.,--.'--.  .--',---.  ,---. |  ||  |-.  ,---.,--.  ,--. \n"
        f"`.  `-. | .-. :| .--'|  ||  |   |  |  | .-. || .-. ||  || .-. '| .-. |\  `'  /  \n"
        f".-'    |\   --.\ `--.'  ''  '   |  |  ' '-' '' '-' '|  || `-' |' '-' '/  /.  \  \n"
        f"`-----'  `----' `---' `----'    `--'   `---'  `---' `--' `---'  `---''--'  '--' \n"
        f"                                                                                \n"
        f"{RESET}")

    while True:
        print(f"{BOLD}{GREEN}\nTools :{RESET}")
        print(f"{LCYAN}\nLinux & Windows{RESET}")
        print("1. Run ffuf (subdomain)")
        print("2. Run ffuf (directory)")
        print("3. Run nmap (full)")
        print("4. Run nmap (udp)")
        print("5. Run whatweb")
        print("6. Run wfuzz")
        print("7. Run gobuster (directory)")
        print("8. Run gobuster (dns)")
        print("9. Run gobuster (vhost)")
        print("10. Run dirsearch")
        print(f"{LPURPLE}\nActive Directory{RESET}")
        print("11. Run smbclient")
        print("12. Run smbmap")
        print("13. Run evilwinrm (password)")
        print("14. Run evilwinrm (hash)")
        print("15. Run crackmapexec smb (password)")
        print("16. Run crackmapexec smb (hash)")
        print("17. Run crackmapexec evilwinrm (password)")
        print("18. Run crackmapexec evilwinrm (hash)")
        print("19. Run rpcclient")
        print("20. Run enum4linux")
        print("21. Run snmpwalk")
        print("22. Run snmpwalk extend")
        print("23. Run xfreerdp")
        print("0. Exit")

        choice = input(f"{BOLD}{GREEN}\nEnter your choice: {RESET}")

        if choice == '1':
            url = input("Enter the URL: ")
            wordlist = input("Enter the path to the wordlist: ")
            run_ffuf_subdomain(url, wordlist)
        elif choice == '2':
            url = input("Enter the URL: ")
            wordlist = input("Enter the path to the wordlist: ")
            run_ffuf(url, wordlist)
        elif choice == '3':
            target = input("Enter the target: ")
            run_nmap_full(target)
        elif choice == '4':
            target = input("Enter the target: ")
            run_nmap_udp(target)
        elif choice == '5':
            url = input("Enter the URL: ")
            run_whatweb(url)
        elif choice == '6':
            url = input("Enter the URL: ")
            wordlist = input("Enter the path to the wordlist: ")
            run_wfuzz(url, wordlist)
        elif choice == '7':
            url = input("Enter the URL: ")
            wordlist = input("Enter the path to the wordlist: ")
            run_gobuster_dir(url, wordlist)
        elif choice == '8':
            url = input("Enter the URL: ")
            wordlist = input("Enter the path to the wordlist: ")
            run_gobuster_dns(url, wordlist)
        elif choice == '9':
            url = input("Enter the URL: ")
            wordlist = input("Enter the path to the wordlist: ")
            run_gobuster_vhost(url, wordlist)
        elif choice == '10':
            url = input("Enter the URL: ")
            wordlist = input("Enter the path to the wordlist: ")
            run_dirsearch(url, wordlist)
        elif choice == '11':
            url = input("Enter the URL: ")
            run_smbclient(url)
        elif choice == '12':
            url = input("Enter the URL: ")
            run_smbmap(url)
        elif choice == '13':
            url = input("Enter the URL: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            run_evilwinrm_password(url, username, password)
        elif choice == '14':
            url = input("Enter the URL: ")
            username = input("Enter username: ")
            hash = input("Enter hash: ")
            run_evilwinrm_hash(url, username, hash)
        elif choice == '15':
            url = input("Enter the URL: ")
            username = input("Enter username/username.txt: ")
            password = input("Enter password/password.txt: ")
            run_crackmapexec_smb_password(url, username, password)
        elif choice == '16':
            url = input("Enter the URL: ")
            username = input("Enter username/username.txt: ")
            hash = input("Enter hash: ")
            run_crackmapexec_smb_hash(url, username, hash)
        elif choice == '17':
            url = input("Enter the URL: ")
            username = input("Enter username/username.txt: ")
            password = input("Enter password/password.txt: ")
            run_crackmapexec_evil_password(url, username, password)
        elif choice == '18':
            url = input("Enter the URL: ")
            username = input("Enter username/username.txt: ")
            hash = input("Enter hash: ")
            run_crackmapexec_evil_hash(url, username, hash)
        elif choice == '19':
            url = input("Enter the URL: ")
            run_rpcclient(url)
        elif choice == '20':
            url = input("Enter the URL: ")
            run_enum4linux(url)
        elif choice == '21':
            url = input("Enter the URL: ")
            run_snmpwalk_all(url)
        elif choice == '22':
            url = input("Enter the URL: ")
            run_snmpwalk_extend(url)
        elif choice == '23':
            url = input("Enter the URL: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            run_xfreerdp(url, username, password)
        elif choice == '0':
            break
        else:
            print(f"{RED}Invalid choice. Please try again.{RESET}")

if __name__ == "__main__":
    main()
