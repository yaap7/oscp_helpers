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
    ip="${1}"
    
    dirReco="${ip}/reco"
    topUdp=200
    sTime=3
    nmapOpt='-Pn -n -vv --open --max-retries 2 --max-rtt-timeout 200ms'
    weblistCommon='/usr/share/seclists/Discovery/Web-Content/common.txt'
    weblistFuzz='/home/kali/tools/fuzz.txt/fuzz.txt'
    defaultUA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3569.0 Safari/537.36'

    info "reco of ${ip} starting"

    mkdir -p "${dirReco}"
    cd "${dirReco}"

    ################
    ###   NMAP   ###
    ################

    info "TCP scan on ${ip}"
    sudo nmap $nmapOpt -sT -p - -oA "nmap_${ip}_tcp_all_ports" "${ip}"
    sleep "$sTime"
    cat "nmap_${ip}_tcp_all_ports.gnmap" | grep -o '[0-9]*/open/tcp' | cut -d'/' -f1 | sort -nu > "tcp_ports.txt"

    info "UDP scan on ${ip} (top $topUdp)"
    sudo nmap $nmapOpt -sU --top-ports "$topUdp" -oA "nmap_${ip}_udp_top_${topUdp}" "${ip}"
    sleep "$sTime"
    cat "nmap_${ip}_udp_top_${topUdp}.gnmap" | grep -o '[0-9]*/open/udp' | cut -d'/' -f1 | sort -nu > "udp_ports.txt"
    
    info "TCP scan for software versions on ${ip}"
    sudo nmap $nmapOpt -sT -sV -p "$(cat "tcp_ports.txt" | tr '\n' ',')" -oA "nmap_${ip}_tcp_versions" "${ip}"
    sleep "$sTime"

    if grep -q '^21$' "tcp_ports.txt" ; then
        info "Port 21 open, launching nmap scripts for FTP service"
        sudo nmap $nmapOpt -sT -sC --script='ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln*' -p 21 -oA "nmap_${ip}_scripts_21_ftp" "${ip}"
        sleep "$sTime"
    fi

    if grep -q '^445$' "tcp_ports.txt" ; then
        info "Port 445 open, launching crackmapexec for SMB discovery"
        crackmapexec smb "${ip}" | tee "cme_${ip}_discovery.cme"
        info "Port 445 open, launching nmap scripts for SMB service"
        sudo nmap $nmapOpt -sT -sC --script='smb2-security-mode,smb2-capabilities,smb-ls,smb-os-discovery,smb-protocols,smb-security-mode,smb-system-info,smb-vuln*' -p 445 -oA "nmap_${ip}_scripts_445_smb" "${ip}"
        sleep "$sTime"
    fi

    for port in 80 443 8080 8443 ; do
        if grep -q "^${port}\$" "tcp_ports.txt" ; then
            info "Port $port open, launching nmap scripts for HTTP service"
            sudo nmap $nmapOpt -sT -sC --script='http-vuln*,http-title,http-put,http-trace,http-userdir-enum,http-svn*,http-shellshock,http-server-header,http-robots*,http-php-version,http-passwd,http-methods,http-ls,http-headers,http-git,http-config-backup,http-apache-server-status' -p "$port" -oA "nmap_${ip}_scripts_${port}_http" "${ip}"
            sleep "$sTime"
        fi
    done

    if grep -q '^3306$' "tcp_ports.txt" ; then
        info "Port 3306 open, launching nmap scripts for MYSQL service"
        sudo nmap $nmapOpt -sT -sC --script='mysql-enum,mysql-vuln*' -p 3306 -oA "nmap_${ip}_scripts_3306_mysql" "${ip}"
        sleep "$sTime"
    fi

    if grep -q '^1433$' "tcp_ports.txt" ; then
        info "Port 1433 open, launching nmap scripts for MS-SQL service"
        sudo nmap $nmapOpt -sT -sC --script='ms-sql-info,ms-sql-ntlm-info,' -p 1433 -oA "nmap_${ip}_scripts_1433_mssql" "${ip}"
        sleep "$sTime"
    fi

    if grep -q '^3389$' "tcp_ports.txt" ; then
        info "Port 3389 open, launching nmap scripts for RDP service"
        sudo nmap $nmapOpt -sT -sC --script='rdp*' -p 3389 -oA "nmap_${ip}_scripts_3389_rdp" "${ip}"
        sleep "$sTime"
    fi

    if grep -q '^25$' "tcp_ports.txt" ; then
        info "Port 25 open, launching nmap scripts for SMTP service"
        sudo nmap $nmapOpt -sT -sC --script='smtp-vuln*,smtp-ntlm-info,smtp-commands' -p 25 -oA "nmap_${ip}_scripts_25_smtp" "${ip}"
        sleep "$sTime"
    fi

    if grep -q '^22$' "tcp_ports.txt" ; then
        info "Port 22 open, launching nmap scripts for SSH service"
        sudo nmap $nmapOpt -sT -sC --script='sshv1,ssh-auth-methods' -p 22 -oA "nmap_${ip}_scripts_22_ssh" "${ip}"
        sleep "$sTime"
    fi

    if grep -q '^2049$' "tcp_ports.txt" "udp_ports.txt" ; then
        info "Port 2049 open, exporting shares with showmount"
        showmount -a "${ip}" | tee "showmount_${ip}_nfs_2049.log"
        showmount -d "${ip}" | tee -a "showmount_${ip}_nfs_2049.log"
        showmount -e "${ip}" | tee -a "showmount_${ip}_nfs_2049.log"
        info "Port 2049 open, launching nmap scripts for NFS service"
        sudo nmap $nmapOpt -sT -sU -sC --script='nfs*,rpcinfo' -p 2049 -oA "nmap_${ip}_scripts_2049_nfs" "${ip}"
        sleep "$sTime"
    fi

    if grep -q '^53$' "tcp_ports.txt" "udp_ports.txt" ; then
        info "Port 53 open, launching nmap scripts for DNS service"
        sudo nmap $nmapOpt -sT -sU -sC --script='dns-nsid,dns-recursion,dns-service-discovery' -p 53 -oA "nmap_${ip}_scripts_53_dns" "${ip}"
        sleep "$sTime"
    fi

    if grep -q '^161$' "udp_ports.txt" ; then
        info "Port 161 open, launching nmap scripts for SNMP service"
        sudo nmap $nmapOpt -sT -sU -sC --script='snmp-brute,snmp-info,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32*' -p 161 -oA "nmap_${ip}_scripts_161_snmp" "${ip}"
        sleep "$sTime"
    fi

    #################
    ###   NIKTO   ###
    #################

    for port in 80 443 8080 8443 ; do
        if grep -q "^${port}\$" "tcp_ports.txt" ; then
            info "Port $port open, launching nikto"
            nikto -Format csv -output "nikto_${ip}_${port}.csv" -port ${port} -host "${ip}" | tee "nikto_${ip}_${port}.log"
            sleep "$sTime"
        fi
    done

    ####################
    ###   GOBUSTER   ###
    ####################

    for port in 80 8080 ; do
        if grep -q "^${port}\$" "tcp_ports.txt" ; then
            info "Port $port open, launching gobuster with common wordlist"
            gobuster dir -a "$defaultUA" -e -k -l -o "gobuster_${ip}_${port}_http_common.log" -u "http://${ip}:${port}/" -w "$weblistCommon"
            sleep "$sTime"
        fi
    done

    for port in 443 8443 ; do
        if grep -q "^${port}\$" "tcp_ports.txt" ; then
            info "Port $port open, launching gobuster with common wordlist"
            gobuster dir -a "$defaultUA" -e -k -l -o "gobuster_${ip}_${port}_https_common.log" -u "https://${ip}:${port}/" -w "$weblistCommon"
            sleep "$sTime"
        fi
    done

    sudo chown -R "$(id -u)" .
}


while [[ "$#" -gt "0" ]] ; do
    if ! echo "${1}" | grep -q '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$' ; then
        error "${1} is not a valid IP address. Skipping..."
        shift
        continue
    fi
    reco "${1}"
    shift
done

