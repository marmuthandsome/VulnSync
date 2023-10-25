#!/bin/bash

# Define color codes
RESTORE='\033[0m'
BLACK='\033[00;30m'
RED='\033[00;31m'
GREEN='\033[00;32m'
YELLOW='\033[00;33m'
BLUE='\033[00;34m'
PURPLE='\033[00;35m'
CYAN='\033[00;36m'
LIGHTGRAY='\033[00;37m'
LBLACK='\033[01;30m'
LRED='\033[01;31m'
LGREEN='\033[01;32m'
LYELLOW='\033[01;33m'
LBLUE='\033[01;34m'
LPURPLE='\033[01;35m'
LCYAN='\033[01;36m'
WHITE='\033[01;37m'
OVERWRITE='\e[1A\e[K'

# Nmap Tool - A simple script for running Nmap scans with different options

# Function to validate input file
validate_input_file() {
    if [ ! -f "$1" ]; then
        echo -e "${RED}Error: The input file '$1' does not exist.${RESTORE}"
        exit 1
    fi
}

# Main function
main() {
    parser() {
        local script_name="$0"
        printf "
${LCYAN}
        █▀▀▄ █▀▄▀█ █▀▀█ █▀▀█ ▒█▀▀▀█ █▀▀ █▀▀▄ ▀▀█▀▀ ░▀░ █▀▀▄ █▀▀ █░░ 
        █░░█ █░▀░█ █▄▄█ █░░█ ░▀▀▀▄▄ █▀▀ █░░█ ░░█░░ ▀█▀ █░░█ █▀▀ █░░ 
        ▀░░▀ ▀░░░▀ ▀░░▀ █▀▀▀ ▒█▄▄▄█ ▀▀▀ ▀░░▀ ░░▀░░ ▀▀▀ ▀░░▀ ▀▀▀ ▀▀▀
${RESTORE}

Usage: $script_name [options] input_file

Options:
    ${LBLUE}-h, --help${RESTORE}              Show this help message and exit
    ${LBLUE}-p, --port PORT${RESTORE}         Specify a specific port to scan
    ${LBLUE}--fast-scan${RESTORE}             Perform a fast scan
    ${LBLUE}--full-scan${RESTORE}             Perform a full scan
    ${LBLUE}--full-scan-slower${RESTORE}      Perform a slower full scan (Recommended)
    ${LBLUE}--full-vuln${RESTORE}             Perform a full scan with vuln (Recommended)
    ${LBLUE}--full-vuln-extras${RESTORE}      Perform a full scan with extras vuln (Long Time)
    ${LBLUE}--ftp${RESTORE}                   Perform a scanning port 21
    ${LBLUE}--ssh${RESTORE}                   Perform a scanning port 22
    ${LBLUE}--telnet${RESTORE}                Perform a scanning port 23
    ${LBLUE}--smtp${RESTORE}                  Perform a scanning port 25, 465, 587
    ${LBLUE}--dns${RESTORE}                   Perform a scanning port 53
    ${LBLUE}--web${RESTORE}                   Perform a scanning port 80, 443
    ${LBLUE}--smb / --smb-brute${RESTORE}     Perform a scanning port 139, 445
    ${LBLUE}--snmp${RESTORE}                  Perform a scanning port 161, 162, 10161, 10162
    ${LBLUE}--ldap${RESTORE}                  Perform a scanning port 389, 636, 3268, 3269
    ${LBLUE}--mssql${RESTORE}                 Perform a scanning port 1433
    ${LBLUE}--mysql${RESTORE}                 Perform a scanning port 3306
    ${LBLUE}--rdp${RESTORE}                   Perform a scanning port 3389
    ${LBLUE}--cassandra${RESTORE}             Perform a scanning port 9042, 9160
    ${LBLUE}--cipher${RESTORE}                Perform a scanning cipher vuln
    ${LBLUE}--port-specific PORT${RESTORE}    Specify a specific port to scan (e.g., 21, 22, 23, etc.)
    ${LBLUE}-o, --output OUTPUT${RESTORE}     Specify the custom output file name

Example:
    $script_name --fast-scan input.txt
    $script_name --full-scan input.txt
    $script_name --port 80 input.txt
    $script_name --port-specific 22 input.txt -o custom_output.txt
"
    }

    local input_file
    local output_file="output.txt"  # Default output file name
    local port
    local fast_scan
    local full_scan
    local full_scan_slower
    local full_vuln
    local full_vuln_extras
    local port_specific
    local ssh
    local ftp
    local telnet
    local smtp
    local dns
    local smb
    local smb_brute
    local snmp
    local mssql
    local mysql
    local rdp
    local cassandra
    local cipher
    local ldap
    local web

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                parser
                exit 0
                ;;
            -p|--port)
                port="$2"
                shift 2
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            --cipher)
                cipher_scan=true
                shift
                ;;
            --web)
                web=true
                shift
                ;;
            --fast-scan)
                fast_scan=true
                shift
                ;;
            --full-scan)
                full_scan=true
                shift
                ;;
            --full-scan-slower)
                full_scan_slower=true
                shift
                ;;
            --full-vuln)
                full_vuln=true
                shift
                ;;
            --full-vuln-extras)
                full_vuln_extras=true
                shift
                ;;
            --ftp)
                ftp=true
                shift
                ;;
            --ssh)
                ssh=true
                shift
                ;;
            --telnet)
                telnet=true
                shift
                ;;
            --smtp)
                smtp=true
                shift
                ;;
            --dns)
                dns=true
                shift
                ;;
            --smb)
                smb=true
                shift
                ;;
            --smb-brute)
                smb_brute=true
                shift
                ;;
            --snmp)
                snmp=true
                shift
                ;;
            --mssql)
                mssql=true
                shift
                ;;
            --mysql)
                mysql=true
                shift
                ;;
            --rdp)
                rdp=true
                shift
                ;;
            --cassandra)
                cassandra=true
                shift
                ;;
            --ldap)
                ldap=true
                shift
                ;;
            --port-specific)
                port_specific="$2"
                shift 2
                ;;
            *)
                input_file="$1"
                shift
                ;;
        esac
    done

    # Check if an input file is provided
    if [ -z "$input_file" ]; then
        echo -e "${RED}Error: Please provide an input file.${RESTORE}"
        parser
        exit 1
    fi

    # Validate the input file
    validate_input_file "$input_file"

    if [ "$fast_scan" = true ]; then
        command="sudo nmap -sV -sC -O -T4 -n -Pn -oA fastscan -iL $input_file -oN $output_file -vv"
    elif [ "$full_scan" = true ]; then
        command="sudo nmap -sV -sC -O -T4 -n -Pn -p- -oA fullfastscan -iL $input_file -oN $output_file -vv"
    elif [ "$full_scan_slower" = true ]; then
        command="sudo nmap -sV -sC -O -p- -n -Pn -oA fullscan -iL $input_file -oN $output_file -vv"
    elif [ "$full_vuln" = true ]; then
        command="sudo nmap -sV -T4 -Pn --script=vulners --script=vuln -iL $input_file -oN $output_file -vv"
    elif [ "$full_vuln_extras" = true ]; then
        command="sudo nmap -sV -sC -O -p- -n -Pn -oA fullscan --script=vuln --script=vulners -iL $input_file -oN $output_file -vv"
    elif [ "$ftp" = true ]; then
        command="sudo nmap -sV -p21 -sC -A -Pn--script ftp-* -iL $input_file -oN $output_file -vv"
    elif [ "$ssh" = true ]; then
        command="sudo nmap -p22 -sC -Pn -sV --script ssh2-enum-algos --script ssh-hostkey --script-args ssh_hostkey=full --script ssh-auth-methods --script-args=\"ssh.user=root\" -iL $input_file -oN $output_file -vv"
    elif [ "$telnet" = true ]; then
        command="sudo nmap -n -sV -Pn --script \"*telnet* and safe\" -p 23 -iL $input_file -oN $output_file -vv"
    elif [ "$smtp" = true ]; then
        command="sudo nmap -Pn -sV --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25,465,587 -iL $input_file -oN $output_file -vv"
    elif [ "$dns" = true ]; then
        command="sudo nmap -Pn -sV -n --script '(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport' -p 53 -iL $input_file -oN $output_file -vv"
    elif [ "$smb" = true ]; then
        command="sudo nmap -p 139,445 -vv -Pn --script smb-security-mode.nse --script smb2-security-mode --script smb-vuln* --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse -iL $input_file -oN $output_file -vv"
    elif [ "$smb_brute" = true ]; then
        command="sudo nmap --script smb-vuln* -Pn -p 139,445 -iL $input_file -oN $output_file -vv"
    elif [ "$snmp" = true ]; then
        command="sudo nmap -Pn -p 161,162,10161,10162 -sV --script \"snmp* and not snmp-brute\" -iL $input_file -oN $output_file -vv"
    elif [ "$mssql" = true ]; then
        command="sudo nmap -Pn --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 -iL $input_file -oN $output_file -vv"
    elif [ "$mysql" = true ]; then
        command="sudo nmap -Pn -sV --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse -p 3306 -iL $input_file -oN $output_file -vv"
    elif [ "$rdp" = true ]; then
        command="sudo nmap -sV -Pn --script \"rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info\" -p 3389 -T4 -iL $input_file -oN $output_file -vv"
    elif [ "$cassandra" = true ]; then
        command="sudo nmap -sV -Pn --script cassandra-info -p 9042,9160 -iL $input_file -oN $output_file -vv"
    elif [ "$cipher_scan" = true ]; then
        command="sudo nmap -sV -p 80,443 -Pn --script ssl-enum-ciphers -iL $input_file -oN $output_file -vv"
    elif [ "$ldap" = true ]; then
        command="sudo nmap -sV -Pn --script \"ldap* and not brute\" --script ldap-search -p 389,636,3268,3269 -iL $input_file -oN $output_file -vv"
    elif [ "$web" = true ]; then
        command="sudo nmap -T4 --reason -Pn -sV -p 80,443 --script='banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)' -iL $input_file -oN $output_file -vv"
    elif [ -n "$port" ]; then
        command="sudo nmap -sC -sV -sS -p$port -iL $input_file -oN $output_file -vv"
    elif [ -n "$port_specific" ]; then
        command="sudo nmap -sC -sV -sS -p$port_specific -iL $input_file -oN $output_file -vv"
    else
        echo -e "${RED}Error: Please specify a valid scan option.${RESTORE}"
        parser
        exit 1
    fi

    # Execute the Nmap command
    echo -e "${LCYAN}"
    echo "█▀▀▄ █▀▄▀█ █▀▀█ █▀▀█ ▒█▀▀▀█ █▀▀ █▀▀▄ ▀▀█▀▀ ░▀░ █▀▀▄ █▀▀ █░"
    echo "█░░█ █░▀░█ █▄▄█ █░░█ ░▀▀▀▄▄ █▀▀ █░░█ ░░█░░ ▀█▀ █░░█ █▀▀ █░░"
    echo "▀░░▀ ▀░░░▀ ▀░░▀ █▀▀▀ ▒█▄▄▄█ ▀▀▀ ▀░░▀ ░░▀░░ ▀▀▀ ▀░░▀ ▀▀▀ ▀▀▀"
    echo -e "${RESTORE}"
    echo ""
    echo -e "${LYELLOW}Created by MarmutHandsome${RESTORE}"
    echo -e "${LBLUE}Version 1.0${RESTORE}"
    echo ""
    echo -e "${GREEN}Starting!!!${RESTORE}"
    eval "$command"
}

main "$@"