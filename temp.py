import re

CYAN = "\033[96m"
RED = "\033[91m"
RESTORE = "\033[0m"

# ...

# Your existing code for listing open, closed, and filtered ports

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

# Iterate through each port
for port, service in open_ports:
    # Find vulnerabilities for the current port
    vulnerabilities_for_port = re.findall(rf"{port}/tcp[^V]+VULNERABLE:(.*?)State: VULNERABLE", sample_output, re.DOTALL)

    # Only print information for ports with vulnerabilities
    if vulnerabilities_for_port:
        print(f"{RED}Vulnerabilities For Port: {port}/tcp open {service} {RESTORE}")
        print("Vulnerabilities:")
        for vulnerability in vulnerabilities_for_port:
            # Extract the relevant information from the nested structure
            vuln_info = re.search(r"\|(.+?)\n", vulnerability, re.DOTALL)
            if vuln_info:
                print(vuln_info.group(1).strip())

        # Add a line break after printing vulnerabilities for the current port
        print()
