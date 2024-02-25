import os
import sys
import subprocess

# Define color and style codes
RESET = '\033[0m'
BOLD = '\033[1m'
LCYAN = '\033[96m'
RED = '\033[91m'
LPURPLE = '\033[94m'

# Main function


def main():
    # Your default values
    output_file = "output.txt"

    def parser():
        script_name = sys.argv[0]
        print(f"{LCYAN}{BOLD}"
              f"                _         __                     \n"
              f" /\   /\ _   _ | | _ __  / _\\_   _  _ __    ___ \n"
              f" \ \ / /| | | || || '_ \ \ \ | | | || '_ \  / __|\n"
              f"  \ V / | |_| || || | | |_\ \| |_| || | | || (__ \n"
              f"   \_/   \__,_||_||_| |_|\__/ \__, ||_| |_| \___|\n"
              f"                              |___/              \n"
              f"{RESET}")

    def handle_option():
        try:
            run_scan_loop = True

            while run_scan_loop:
                hosts = "clear"
                os.system(hosts)

                print(f"{LCYAN}{BOLD}"
                      f"                _         __                     \n"
                      f" /\   /\ _   _ | | _ __  / _\\_   _  _ __    ___ \n"
                      f" \ \ / /| | | || || '_ \ \ \ | | | || '_ \  / __|\n"
                      f"  \ V / | |_| || || | | |_\ \| |_| || | | || (__ \n"
                      f"   \_/   \__,_||_||_| |_|\__/ \__, ||_| |_| \___|\n"
                      f"                              |___/              \n"
                      f"{RESET}")

                # Check if the output file exists
                if os.path.exists(output_file):
                    print(
                        f"Output file {output_file} found. Showing contents.\n")
                    print(f"{BOLD}Open Port:{RESET} ")
                    os.system(f"grep --color syn-ack {output_file}")
                    print("")
                    print(f"{BOLD}Close Port:{RESET} ")
                    os.system(f"grep --color 'filtered\|closed' {output_file}")
                    print("")
                else:
                    print("Output file not found. Starting a new scan.\n")
                    # User Input For Insert IP
                    ip = input("Enter the target IP/URL: ")
                    print("")
                    # Command For Fast Scan
                    command = f"sudo nmap -sV -sC -O -T4 -n -oA fastscan {ip} -oN {output_file} -vv"
                    print("Starting!!!\n")
                    print("On Progress!!! (Please be patient)\n")
                    print(
                        "+++=======================================================+++\n")
                    # Hide Output
                    try:
                        with open(os.devnull, 'w') as nullfile:
                            subprocess.check_call(command, shell=True,
                                                  stdout=nullfile, stderr=nullfile)
                    except subprocess.CalledProcessError:
                        print("Error occurred while running the Nmap scan.")
                        print("")
                    # Show Output Fast Scanning
                    print(f"{BOLD}Open Port:{RESET} ")
                    os.system(f"grep --color syn-ack {output_file}")
                    print("")
                    print(f"{BOLD}Close Port:{RESET} ")
                    os.system(f"grep --color 'filtered\|closed' {output_file}")
                    print("")

                # User Input For Ports
                ports = input("Enter the ports to scan (e.g., 22): ")

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

                retry_option = input(
                    "Do you want to scan another port (yes/no) or exit the program (exit): ").lower()
                if retry_option == 'yes':
                    continue  # Go back to the beginning of the loop for another scan
                elif retry_option == 'exit':
                    run_scan_loop = False  # Exit the loop and end the program

            # Cleanup: Remove the output file
            if os.path.exists(output_file):
                os.remove(output_file)
                print(f"Removed {output_file}")

        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected. Exiting...")
            # Cleanup: Remove the output file if it exists
            if os.path.exists(output_file):
                os.remove(output_file)
                print(f"Removed {output_file}")

    def check_and_display_vulnerability(vulnerability_name, grep_pattern, severity, description, recommendation):
        hosts = f"grep -q -oh '{grep_pattern}' result.txt"
        if os.system(hosts) == 0:
            print("")
            print(f"{RED}Vulnerability{RESET}: {vulnerability_name}")
            print(f"{RED}Severity{RESET}: {severity}")
            print(f"{RED}Impact{RESET}: {description}")
            print("")
            print(f"{LPURPLE}Recommendation{RESET}: {recommendation}")
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
    handle_option()


# Run the main function if this script is executed
if __name__ == "__main__":
    main()
