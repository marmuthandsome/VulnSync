#!/usr/bin/python3
import os
import sys
import subprocess

# Define color codes (you may need to import them or define them)
RESTORE = '\033[0m'
BLACK, RED, GREEN, YELLOW, BLUE, PURPLE, CYAN, LIGHTGRAY = [
    f'\033[00;3{i}m' for i in range(8)]
LBLACK, LRED, LGREEN, LYELLOW, LBLUE, LPURPLE, LCYAN, WHITE = [
    f'\033[01;3{i}m' for i in range(8)]
OVERWRITE = '\033[1A\033[K'

# Main function


def main():
    # Your default values
    output_file = "output.txt"
    ports = ""  # Define ports in a broader scope

    def parser():
        script_name = sys.argv[0]
        print(f"""
{LCYAN}
                _         __                     
 /\   /\ _   _ | | _ __  / _\ _   _  _ __    ___ 
 \ \ / /| | | || || '_ \ \ \ | | | || '_ \  / __|
  \ V / | |_| || || | | |_\ \| |_| || | | || (__ 
   \_/   \__,_||_||_| |_|\__/ \__, ||_| |_| \___|
                              |___/              
{RESTORE}""")

    def handle_option(option):
        run_scan_loop = True

        while run_scan_loop:

            if option == "1":
                hosts = "clear"
                os.system(hosts)
                print(f"""
{LCYAN}        _         __                     
/\   /\ _   _ | | _ __  / _\ _   _  _ __    ___ 
\ \ / /| | | || || '_ \ \ \ | | | || '_ \  / __|
 \ V / | |_| || || | | |_\ \| |_| || | | || (__ 
  \_/   \__,_||_||_| |_|\__/ \__, ||_| |_| \___|
                             |___/              
{RESTORE}""")
                print("Fast Scan Selected.\n")
                # User Input For Insert IP
                ip = input("Enter the target IP/URL: ")
                print("")
                # Command For Fast Scan
                command = f"sudo nmap -sV -sC -O -T4 -n -oA fastscan {ip} -oN {output_file} -vv"
                print("Starting!!!\n")
                print("On Progress!!! (Please be patient)\n")
                print("+++=======================================================+++\n")
                # Hide Output
                try:
                    with open(os.devnull, 'w') as nullfile:
                        subprocess.check_call(command, shell=True,
                                              stdout=nullfile, stderr=nullfile)
                except subprocess.CalledProcessError:
                    print("Error occurred while running the Nmap scan.")
                    print("")
                # Show Output Fast Scanning
                print("Open Port: ")
                os.system(f"grep --color syn-ack {output_file}")
                print("")
                print("Close Port: ")
                os.system(f"grep --color 'filtered\|closed' {output_file}")
                print("")

                # User Input For Ports
                ports = input("Enter the ports to scan (e.g., 22): ")

            elif option == "2":
                print("Executing Option 2")
                # Your code for Option 2 goes here
            elif option == "3":
                print("Executing Option 3")
                # Your code for Option 3 goes here
            else:
                print("Invalid option. Please choose a valid option.")

            # If Else Port Exploit
            if "22" in ports.split(','):
                command = f"sudo nmap -p22 -sC -Pn -sV --script ssh2-enum-algos --script ssh-auth-methods {ip} -oN result.txt -vv"
                try:
                    with open(os.devnull, 'w') as nullfile:
                        subprocess.check_call(command, shell=True,
                                              stdout=nullfile, stderr=nullfile)
                except subprocess.CalledProcessError:
                    print("Error occurred while running the Nmap scan.")
                    print("")

                check_and_display_vulnerabilities("result.txt")

                retry_vulnerabilities = input(
                    "Do you want to scan another port? (yes/no): ").lower()
                if retry_vulnerabilities == 'yes':
                    continue  # Go back to the beginning of the loop for another scan
                else:
                    run_scan_loop = False  # Exit the loop and end the program
            else:
                run_scan_loop = False

    def check_and_display_vulnerability(vulnerability_name, grep_pattern, severity, description, recommendation):
        hosts = f"grep -q -oh '{grep_pattern}' result.txt"
        if os.system(hosts) == 0:
            print("")
            print(f"Vulnerability: {vulnerability_name}")
            print(f"Severity: {severity}")
            print(f"Impact : {description}")
            print("")
            print(f"Recommendation : {recommendation}")
            print("")
            print("+++=======================================================+++")
            print("")

    def check_and_display_vulnerabilities(filename):
        # Check and display each vulnerability
        check_and_display_vulnerability(
            "SSH Authentication Methods Enumeration",
            "ssh-auth-methods",
            "Informational",
            "\nSecurity Risk: Enumerating SSH authentication methods can reveal potentially insecure methods, which could be targeted by attackers.",
            "\nDisable Weak Methods: Disable deprecated and weak authentication methods (e.g., password-based authentication and publickey-based authentication) in favor of more secure methods such as public key-based authentication.",
        )

        check_and_display_vulnerability(
            "Weak SSH Enumeration Algorithms",
            "3des-cbc\|arcfour\|rc4",
            "Informational",
            "\nSecurity Risk: The use of weak SSH enumeration algorithms such as 3des-cbc, arcfour, and rc4 poses a significant security risk. These algorithms have known vulnerabilities and weaknesses that can be exploited by attackers to compromise the confidentiality and integrity of SSH communications.",
            "\nUpdate SSH Configuration: It is strongly recommended to update the SSH server configuration to disallow the use of weak encryption algorithms, including 3des-cbc, arcfour, and rc4."
        )

        check_and_display_vulnerability(
            "Insecure SSH Authentication Methods",
            "publickey\|password",
            "Informational",
            "\nDiscovered that the SSH server supports both the 'publickey' and 'password' authentication methods, potentially exposing the system to security risks.",
            "\nThis configuration exposes the system to the risk of brute force attacks, where attackers may attempt to gain unauthorized access using weak passwords or by exploiting vulnerabilities in the public key authentication process."
        )

    # Your main script logic goes here
    parser()
    print("1. Fast Scan")
    print("2. Full Scan")
    print("3. Option 3")
    menu_option = input("Choose an option (1-3): ")
    handle_option(menu_option)


# Run the main function if this script is executed
if __name__ == "__main__":
    main()
