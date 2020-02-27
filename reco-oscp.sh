#!/bin/bash

function error() {
    echo -e "\e[91mError\e[0m: $@" >&2
}

function info() {
    echo -e "\e[96mInfo\e[0m: $@"
}

function grep-ip() {
    grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'
}

function reco() {
    topUdp=200
    sTime=3
    weblistCommon='/usr/share/seclists/Discovery/Web-Content/common.txt'

    info "reco of $1 starting"
    mkdir -p "reco_$1"
    cd "reco_$1"

    info "TCP scan on $1"
    sudo nmap -Pn -n -vv --open -sT -p - -oA "${1}_tcp_all_ports" "$1"
    sleep "$sTime"
    cat "${1}_tcp_all_ports.gnmap" | grep -o '[0-9]*/open/tcp' | cut -d'/' -f1 | sort -nu > "tcp_ports.txt"

    info "UDP scan on $1 (top $topUdp)"
    sudo nmap -Pn -n -vv --open -sU --top-ports "$topUdp" -oA "${1}_udp_top_${topUdp}" "$1"
    sleep "$sTime"
    cat "${1}_udp_top_${topUdp}.gnmap" | grep -o '[0-9]*/open/udp' | cut -d'/' -f1 | sort -nu > "udp_ports.txt"
    
    info "TCP scan for software versions on $1"
    echo sudo nmap -Pn -n -vv --open -sT -sV -p "$(cat "tcp_ports.txt" | tr '\n' ',')" -oA "${1}_tcp_versions" "$1"
    sleep "$sTime"

    if grep -q '^21$' "tcp_ports.txt" ; then
        info "Port 21 open, launching nmap scripts for FTP service"
        sudo nmap -Pn -n -vv --open -sT -sC --script='ftp*' -p 21 -oA "${1}_scripts_21_ftp" "$1"
        sleep "$sTime"
    fi

    if grep -q '^445$' "tcp_ports.txt" ; then
        info "Port 445 open, launching nmap scripts for SMB service"
        sudo nmap -Pn -n -vv --open -sT -sC --script='smb*' -p 445 -oA "${1}_scripts_445_smb" "$1"
        sleep "$sTime"
    fi

    for port in 80 443 8080 8443 ; do
        if grep -q "^${port}\$" "tcp_ports.txt" ; then
            info "Port $port open, launching nmap scripts for HTTP service"
            sudo nmap -Pn -n -vv --open -sT -sC --script='http*' -p "$port" -oA "${1}_scripts_${port}_http" "$1"
            sleep "$sTime"
        fi
    done

    if grep -q '^3306$' "tcp_ports.txt" ; then
        info "Port 3306 open, launching nmap scripts for MYSQL service"
        sudo nmap -Pn -n -vv --open -sT -sC --script='mysql*' -p 8443 -oA "${1}_scripts_3306_mysql" "$1"
        sleep "$sTime"
    fi

    if grep -q '^1433$' "tcp_ports.txt" ; then
        info "Port 1433 open, launching nmap scripts for MS-SQL service"
        sudo nmap -Pn -n -vv --open -sT -sC --script='ms-sql*' -p 1433 -oA "${1}_scripts_1433_mssql" "$1"
        sleep "$sTime"
    fi

    if grep -q '^25$' "tcp_ports.txt" ; then
        info "Port 25 open, launching nmap scripts for SMTP service"
        sudo nmap -Pn -n -vv --open -sT -sC --script='smtp*' -p 8443 -oA "${1}_scripts_25_smtp" "$1"
        sleep "$sTime"
    fi

    if grep -q '^22$' "tcp_ports.txt" ; then
        info "Port 22 open, launching nmap scripts for SSH service"
        sudo nmap -Pn -n -vv --open -sT -sC --script='ssh*' -p 8443 -oA "${1}_scripts_22_ssh" "$1"
        sleep "$sTime"
    fi

    if grep -q '^53$' "udp_ports.txt" ; then
        info "Port 53 open, launching nmap scripts for DNS service"
        sudo nmap -Pn -n -vv --open -sT -sU -sC --script='dns*' -p 53 -oA "${1}_scripts_53_dns" "$1"
        sleep "$sTime"
    fi

    if grep -q '^161$' "udp_ports.txt" ; then
        info "Port 161 open, launching nmap scripts for SNMP service"
        sudo nmap -Pn -n -vv --open -sT -sU -sC --script='snmp*' -p 161 -oA "${1}_scripts_161_snmp" "$1"
        sleep "$sTime"
    fi

    for port in 80 443 8080 8443 ; do
        if grep -q "^${port}\$" "tcp_ports.txt" ; then
            info "Port $port open, launching nikto"
            nikto -Format csv -output "nikto_${1}_${port}.csv" -port ${port} -host "$1"
            sleep "$sTime"
        fi
    done

    for port in 80 8080 ; do
        if grep -q "^${port}\$" "tcp_ports.txt" ; then
            info "Port $port open, launching dirb with common wordlist"
            dirb "http://${1}/" "$weblistCommon"| tee dirb_http-${1}_common.log
            sleep "$sTime"
        fi
    done

    for port in 443 8443 ; do
        if grep -q "^${port}\$" "tcp_ports.txt" ; then
            info "Port $port open, launching dirb with common wordlist"
            dirb "https://${1}/" "$weblistCommon"| tee dirb_https-${1}_common.log
            sleep "$sTime"
        fi
    done

    sudo chown -R "$(id -u)" .
}


while [[ "$#" -gt "0" ]] ; do
    if ! echo "$1" | grep -q '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$' ; then
        error "$1 is not a valid IP address. Skipping..."
        shift
        continue
    fi
    reco "$1"
    shift
done

