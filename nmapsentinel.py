#!/usr/bin/python3
import os
import sys
import subprocess

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

# Function to validate input file

def validate_input_file(input_file):
    if not os.path.isfile(input_file):
        print(f"{RED}Error: The input file '{input_file}' does not exist.{RESTORE}")
        sys.exit(1)

# Main function

def main():
    def parser():
        script_name = sys.argv[0]
        print(f"""
{LCYAN}
        █▀▀▄ █▀▄▀█ █▀▀█ █▀▀█ ▒█▀▀▀█ █▀▀ █▀▀▄ ▀▀█▀▀ ░▀░ █▀▀▄ █▀▀ █░░
        █░░█ █░▀░█ █▄▄█ █░░█ ░▀▀▀▄▄ █▀▀ █░░█ ░░█░░ ▀█▀ █░░█ █▀▀ █░░
        ▀░░▀ ▀░░░▀ ▀░░▀ █▀▀▀ ▒█▄▄▄█ ▀▀▀ ▀░░▀ ░░▀░░ ▀▀▀ ▀░░▀ ▀▀▀ ▀▀▀
{RESTORE}

Usage: {script_name} [options] input_file

Options:
    {LBLUE}-h, --help{RESTORE}              Show this help message and exit
    {LBLUE}-p, --port PORT{RESTORE}         Specify a specific port to scan
    {LBLUE}--fast-scan{RESTORE}             Perform a fast scan
    {LBLUE}--full-scan{RESTORE}             Perform a full scan
    {LBLUE}--full-scan-slower{RESTORE}      Perform a slower full scan (Recommended)
    {LBLUE}--full-vuln{RESTORE}             Perform a full scan with vuln (Recommended)
    {LBLUE}--full-vuln-extras{RESTORE}      Perform a full scan with extras vuln (Long Time)
    {LBLUE}--ftp{RESTORE}                   Perform a scanning port 21
    {LBLUE}--ssh{RESTORE}                   Perform a scanning port 22
    {LBLUE}--telnet{RESTORE}                Perform a scanning port 23
    {LBLUE}--smtp{RESTORE}                  Perform a scanning port 25, 465, 587
    {LBLUE}--dns{RESTORE}                   Perform a scanning port 53
    {LBLUE}--web{RESTORE}                   Perform a scanning port 80, 443
    {LBLUE}--smb / --smb-brute{RESTORE}     Perform a scanning port 139, 445
    {LBLUE}--snmp{RESTORE}                  Perform a scanning port 161, 162, 10161, 10162
    {LBLUE}--ldap{RESTORE}                  Perform a scanning port 389, 636, 3268, 3269
    {LBLUE}--mssql{RESTORE}                 Perform a scanning port 1433
    {LBLUE}--mysql{RESTORE}                 Perform a scanning port 3306
    {LBLUE}--rdp{RESTORE}                   Perform a scanning port 3389
    {LBLUE}--cassandra{RESTORE}             Perform a scanning port 9042, 9160
    {LBLUE}--cipher{RESTORE}                Perform a scanning cipher vuln
    {LBLUE}--port-specific PORT{RESTORE}    Specify a specific port to scan (e.g., 21, 22, 23, etc.)
    {LBLUE}-o, --output OUTPUT{RESTORE}     Specify the custom output file name

Example:
    {script_name} --fast-scan input.txt
    {script_name} --full-scan input.txt
    {script_name} --port 80 input.txt
    {script_name} --port-specific 22 input.txt -o custom_output.txt
""")

    input_file = None
    output_file = "output.txt"  # Default output file name
    port = None
    fast_scan = False
    full_scan = False
    full_scan_slower = False
    full_vuln = False
    full_vuln_extras = False
    port_specific = None
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
        elif arg in ["-p", "--port"]:
            port = args.pop(0)
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
        elif arg == "--full-scan-slower":
            full_scan_slower = True
        elif arg == "--full-vuln":
            full_vuln = True
        elif arg == "--full-vuln-extras":
            full_vuln_extras = True
        elif arg == "--ftp":
            ftp = True
        elif arg == "--ssh":
            ssh = True
        elif arg == "--telnet":
            telnet = True
        elif arg == "--smtp":
            smtp = True
        elif arg == "--dns":
            dns = True
        elif arg == "--smb":
            smb = True
        elif arg == "--smb-brute":
            smb_brute = True
        elif arg == "--snmp":
            snmp = True
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
        elif arg == "--port-specific":
            port_specific = args.pop(0)
        else:
            input_file = arg

    # Check if an input file is provided
    if input_file is None:
        print(f"{RED}Error: Please provide an input file.{RESTORE}")
        parser()
        sys.exit(1)

    # Validate the input file
    validate_input_file(input_file)

    command = None
    if fast_scan:
        command = f"sudo nmap -sV -sC -O -T4 -n -Pn -oA fastscan -iL {input_file} -oN {output_file} -vv"
    elif full_scan:
        command = f"sudo nmap -sV -sC -O -T4 -n -Pn -p- -oA fullfastscan -iL {input_file} -oN {output_file} -vv"
    elif full_scan_slower:
        command = f"sudo nmap -sV -sC -O -p- -n -Pn -oA fullscan -iL {input_file} -oN {output_file} -vv"
    elif full_vuln:
        command = f"sudo nmap -sV -T4 -Pn --script=vulners --script=vuln -iL {input_file} -oN {output_file} -vv"
    elif full_vuln_extras:
        command = f"sudo nmap -sV -sC -O -p- -n -Pn -oA fullscan --script=vuln --script=vulners -iL {input_file} -oN {output_file} -vv"
    elif ftp:
        command = f"sudo nmap -sV -p21 -sC -A -Pn --script ftp-* -iL {input_file} -oN {output_file} -vv"
    elif ssh:
        command = f"sudo nmap -p22 -sC -Pn -sV --script ssh2-enum-algos --script ssh-hostkey --script-args ssh_hostkey=full --script ssh-auth-methods --script-args=\"ssh.user=root\" -iL {input_file} -oN {output_file} -vv"
    elif telnet:
        command = f"sudo nmap -n -sV -Pn --script \"*telnet* and safe\" -p 23 -iL {input_file} -oN {output_file} -vv"
    elif smtp:
        command = f"sudo nmap -Pn -sV --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25,465,587 -iL {input_file} -oN {output_file} -vv"
    elif dns:
        command = f"sudo nmap -Pn -sV -n --script '(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport' -p 53 -iL {input_file} -oN {output_file} -vv"
    elif smb:
        command = f"sudo nmap -p 139,445 -vv -Pn --script smb-security-mode.nse --script smb2-security-mode --script smb-vuln* --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse -iL {input_file} -oN {output_file} -vv"
    elif smb_brute:
        command = f"sudo nmap --script smb-vuln* -Pn -p 139,445 -iL {input_file} -oN {output_file} -vv"
    elif snmp:
        command = f"sudo nmap -Pn -p 161,162,10161,10162 -sV --script \"snmp* and not snmp-brute\" -iL {input_file} -oN {output_file} -vv"
    elif mssql:
        command = f"sudo nmap -Pn --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 -iL {input_file} -oN {output_file} -vv"
    elif mysql:
        command = f"sudo nmap -Pn -sV --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse -p 3306 -iL {input_file} -oN {output_file} -vv"
    elif rdp:
        command = f"sudo nmap -sV -Pn --script \"rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info\" -p 3389 -T4 -iL {input_file} -oN {output_file} -vv"
    elif cassandra:
        command = f"sudo nmap -sV -Pn --script cassandra-info -p 9042,9160 -iL {input_file} -oN {output_file} -vv"
    elif cipher_scan:
        command = f"sudo nmap -sV -p 80,443 -Pn --script ssl-enum-ciphers -iL {input_file} -oN {output_file} -vv"
    elif ldap:
        command = f"sudo nmap -sV -Pn --script \"ldap* and not brute\" --script ldap-search -p 389,636,3268,3269 -iL {input_file} -oN {output_file} -vv"
    elif web:
        command = f"sudo nmap -T4 --reason -Pn -sV -p 443 --script='banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)' -iL {input_file} -oN {output_file} -vv"
    elif port is not None:
        command = f"sudo nmap -sC -sV -sS -p{port} -iL {input_file} -oN {output_file} -vv"
    elif port_specific is not None:
        command = f"sudo nmap -sC -sV -sS -p{port_specific} -iL {input_file} -oN {output_file} -vv"
    else:
        print(f"{RED}Error: Please specify a valid scan option.{RESTORE}")
        parser()
        sys.exit(1)

    # Execute the Nmap command
    print(f"{LCYAN}")
    print("█▀▀▄ █▀▄▀█ █▀▀█ █▀▀█ ▒█▀▀▀█ █▀▀ █▀▀▄ ▀▀█▀▀ ░▀░ █▀▀▄ █▀▀ █░")
    print("█░░█ █░▀░█ █▄▄█ █░░█ ░▀▀▀▄▄ █▀▀ █░░█ ░░█░░ ▀█▀ █░░█ █▀▀ █░░")
    print("▀░░▀ ▀░░░▀ ▀░░▀ █▀▀▀ ▒█▄▄▄█ ▀▀▀ ▀░░▀ ░░▀░░ ▀▀▀ ▀░░▀ ▀▀▀ ▀▀▀")
    print(f"{RESTORE}")
    print("")
    print(f"{LYELLOW}Created by MarmutHandsome{RESTORE}")
    print(f"{LBLUE}Version 1.0{RESTORE}")
    print("")
    print(f"{GREEN}Starting!!!{RESTORE}")
    try:
        with open(os.devnull, 'w') as nullfile:
            subprocess.check_call(command, shell=True, stdout=nullfile, stderr=nullfile)
            print(f"{GREEN}Scan completed successfully!{RESTORE}")
    except subprocess.CalledProcessError:
            print(f"{RED}Error occurred while running the Nmap scan.{RESTORE}")
    
    # Output
    print("")
    print(f"{CYAN}Open Port: {RESTORE}")
    hosts = f"grep -T --color open output.txt"
    os.system(hosts)
    print("")
    print(f"{CYAN}Close Port: {RESTORE}")
    hosts = f"grep -T --color filtered output.txt"
    os.system(hosts)
    print("")
    print(f"{RED}Vulnerabilies For Port: {RESTORE}")

    # Port 80 / 443
    hosts = f"grep -T --color 80/tcp output.txt"
    os.system(hosts)
    hosts = f"grep 443/tcp output.txt"
    os.system(hosts)
    print("")
    print(f"Severity {LGREEN}[Informational]{RESTORE}")
    print("")
    print(f"{RED}Vulnerabilies Name: {RESTORE}")
    hosts = f"grep -oh 'HSTS not configured in HTTPS Server' output.txt"
    os.system(hosts)
    print("")
    print(f"{RED}Impact: {RESTORE}")
    print(f"| {CYAN}Improved Security{RESTORE}: Enabling HSTS significantly enhances the security of your website by ensuring that all communications are encrypted using HTTPS. It mitigates risks associated with SSL-stripping attacks and prevents downgrade attacks.")
    print(f"| {CYAN}Data Integrity{RESTORE}: HSTS helps protect the integrity of data transmitted between the user's browser and your server, reducing the risk of data tampering.")
    print(f"{LPURPLE}Recommendation: {RESTORE}")
    print(f"| Configure your web server to send the HSTS header in the HTTP response.")
    print(f"| {CYAN}Strict-Transport-Security: max-age=31536000; includeSubDomains{RESTORE}")
    print("")
    print("+====================================+")
    print("")
    print(f"{RED}Vulnerabilies Name: {RESTORE}")
    hosts = f"grep -oh 'Potentially risky methods: TRACE' output.txt"
    os.system(hosts)
    print("")
    print(f"{RED}Impact: {RESTORE}")
    print(f"| {CYAN}Improved Security{RESTORE}: The primary impact of fixing this issue is improved security. Disabling TRACE and implementing other security measures can help protect your web application from certain types of attacks and vulnerabilities.")
    print(f"{LPURPLE}Recommendation: {RESTORE}")
    print(f"| {CYAN}Disable TRACE Method{RESTORE}: The most effective way to fix this issue is to disable the TRACE method altogether on your web server. This can usually be done in the web server configuration.")
    print("")
    print("+====================================+")
    print("")
    print(f"{RED}Vulnerabilies Name: {RESTORE}")
    hosts = f"grep -oh '64-bit block cipher 3DES vulnerable to SWEET32 attack' output.txt"
    os.system(hosts)
    print("")
    print(f"{RED}Impact: {RESTORE}")
    print(f"| {CYAN}Security Improvement{RESTORE}: Replacing 3DES with a more secure cipher, like AES, will significantly enhance the security of your data transmissions. It will protect against SWEET32 attacks, which exploit vulnerabilities in ciphers with 64-bit block sizes.")
    print(f"{LPURPLE}Recommendation: {RESTORE}")
    print(f"| {CYAN}Replace 3DES{RESTORE}: Replace the 3DES (Triple Data Encryption Standard) cipher with a more secure alternative, such as AES (Advanced Encryption Standard). AES is widely considered to be secure and is not vulnerable to SWEET32 attacks.")
    print("")
    print("+====================================+")
    print("")
    print(f"{RED}Vulnerabilies Name: {RESTORE}")
    hosts = f"grep -oh 'Broken cipher RC4 is deprecated by RFC 7465' output.txt"
    os.system(hosts)
    print("")
    print(f"{RED}Impact: {RESTORE}")
    print(f"| {CYAN}Security Enhancement{RESTORE}: Disabling RC4 is essential as it is known to have serious security weaknesses. By deprecating RC4, you prevent vulnerabilities like the BEAST attack and other cryptographic attacks.")
    print(f"{LPURPLE}Recommendation: {RESTORE}")
    print(f"| {CYAN}Disable RC4{RESTORE}: Immediately disable the RC4 cipher suite in your SSL/TLS configurations. This should be done both on the server and client sides.")
    print("")
    print("+====================================+")
    print("")
    print(f"{RED}Vulnerabilies Name: {RESTORE}")
    hosts = f"grep -oh 'TLSv1.0\|TLSv1.1' output.txt"
    os.system(hosts)
    print("")
    print(f"{RED}Impact: {RESTORE}")
    print(f"| {CYAN}Security Risk{RESTORE}: TLSv1.0 and TLSv1.1 have known vulnerabilities that can be exploited by attackers to intercept and manipulate encrypted data. This poses a significant security risk to your system.")
    print(f"{LPURPLE}Recommendation: {RESTORE}")
    print(f"| {CYAN}Upgrade to TLSv1.2 or TLSv1.3{RESTORE}: Upgrade your servers and applications to support TLSv1.2 or TLSv1.3. These versions are more secure and offer better protection against attacks.")
    print(f"| {CYAN}Disable TLSv1.0 and TLSv1.1{RESTORE}: Disable TLSv1.0 and TLSv1.1 on your servers and applications. Ensure that they are not used as negotiation options during the TLS handshake.")
    print("")
    print("+====================================+")
    print("")
    hosts = f""
    os.system(hosts)
    print("")

if __name__ == "__main__":
    main()
