#!/bin/bash

if [[ $(id -u) != "0" ]]; then
    echo -e "\e[0;31m"Error: You must be root to run this install script."\e[0m"
    exit 1
fi

basepath=$(dirname $0)
cd ${basepath}

Config_Variable() {
    # Variable settings
    # Single IP maximum number of connections, the default is 2
    maxsameclients=1
    # The maximum number of connections, the default is 16
    maxclients=1024
    # Server certificate and key file, placed in the same directory with the script, the key file permissions should be 600 or 400
    servercert=${1-server-cert.pem}
    serverkey=${2-server-key.pem}
    # VPN Intranet IP segment
    vpnnetwork="172.16.24.0/24"
    # DNS
    dns1="8.8.8.8"
    dns2="8.8.4.4"
    # Configuration directory
    confdir="/etc/ocserv"

    # Obtain the network card interface name
    systemctl start NetworkManager.service
    ethlist=$(nmcli --nocheck d | grep -v -E "(^(DEVICE|lo)|unavailable|^[^e])" | awk '{print $1}')
    eth=$(printf "${ethlist}\n" | head -n 1)
    if [[ $(printf "${ethlist}\n" | wc -l) -gt 1 ]]; then
        echo ======================================
        echo "Network Interface list:"
        printf "\e[33m${ethlist}\e[0m\n"
        echo ======================================
        echo "Which network interface you want to listen for ocserv?"
        printf "Default network interface is \e[33m${eth}\e[0m, let it blank to use this network interface: "
        read ethtmp
        if [[ -n "${ethtmp}" ]]; then
            eth=${ethtmp}
        fi
    fi

    port=443
    username=test
    password=test
}

Print_Variable() {
    # Print the configuration parameters
    clear

    ipv4=$(ip -4 -f inet addr show ${eth} | grep 'inet' | sed 's/.*inet \([0-9\.]\+\).*/\1/')
    ipv6=$(ip -6 -f inet6 addr show ${eth} | grep -v -P "(::1\/128|fe80)" | grep -o -P "([a-z\d]+:[a-z\d:]+)")
    echo -e "IPv4:\t\t\e[34m$(echo ${ipv4})\e[0m"
    if [ ! "$ipv6" = "" ]; then
        echo -e "IPv6:\t\t\e[34m$(echo ${ipv6})\e[0m"
    fi

    SAVEDSTTY=$(stty -g)
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty ${SAVEDSTTY}
}

Install_Ocserv() {
    echo -e "\e[0;36m"Installing Ocserv..."\e[0m"
    apt-get update
    apt-get install -y ocserv gnutls-bin
    if [    "$?" = "0" ];then
        echo -e "\e[0;32m"Ocserv Installation Was Successful."\e[0m"
    else
        echo -e "\e[0;31m"Ocserv Installation Is Failed"\e[0m"
        exit 1
    fi    
}

Config_Ocserv() {
   # Detects whether there is a certificate and a key file
    if [[ ! -f "${servercert}" ]] || [[ ! -f "${serverkey}" ]]; then
        # Create a ca certificate and a server certificate (refer to http://www.infradead.org/ocserv/manual.html#heading5)
        certtool --generate-privkey --outfile ca-key.pem

        cat << _EOF_ >ca.tmpl
cn = "Endway Cisco VPN"
organization = "Endway"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
_EOF_

        certtool --generate-self-signed --load-privkey ca-key.pem \
        --template ca.tmpl --outfile ca-cert.pem
        certtool --generate-privkey --outfile ${serverkey}

        cat << _EOF_ >server.tmpl
cn = "Endway Cisco VPN"
organization = "Endway"
serial = 2
expiration_days = 3650
signing_key
encryption_key #only if the generated key is an RSA one
tls_www_server
_EOF_

        certtool --generate-certificate --load-privkey ${serverkey} \
        --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
        --template server.tmpl --outfile ${servercert}
    fi

    # Copy the certificate
    cp "${servercert}" /etc/pki/ocserv/public/server.crt
    cp "${serverkey}" /etc/pki/ocserv/private/server.key

    # Edit the configuration file
    (echo "${password}"; sleep 1; echo "${password}") | ocpasswd -c "${confdir}/ocpasswd" ${username}

    sed -i 's@auth = "pam"@#auth = "pam"\nauth = "plain[passwd=/etc/ocserv/ocpasswd]"@g' "${confdir}/ocserv.conf"
    sed -i "s/max-same-clients = 2/max-same-clients = ${maxsameclients}/g" "${confdir}/ocserv.conf"
    sed -i "s/max-clients = 16/max-clients = ${maxclients}/g" "${confdir}/ocserv.conf"
    sed -i "s/tcp-port = 443/tcp-port = ${port}/g" "${confdir}/ocserv.conf"
    sed -i "s/udp-port = 443/udp-port = ${port}/g" "${confdir}/ocserv.conf"
    sed -i 's/^ca-cert = /#ca-cert = /g' "${confdir}/ocserv.conf"
    sed -i 's/^cert-user-oid = /#cert-user-oid = /g' "${confdir}/ocserv.conf"
    sed -i "s/default-domain = example.com/#default-domain = example.com/g" "${confdir}/ocserv.conf"
    sed -i "s@#ipv4-network = 192.168.1.0/24@ipv4-network = ${vpnnetwork}@g" "${confdir}/ocserv.conf"
    sed -i "s/#dns = 192.168.1.2/dns = ${dns1}\ndns = ${dns2}/g" "${confdir}/ocserv.conf"
    sed -i "s/cookie-timeout = 300/cookie-timeout = 86400/g" "${confdir}/ocserv.conf"
    sed -i 's/user-profile = profile.xml/#user-profile = profile.xml/g' "${confdir}/ocserv.conf"
    sed -i 's/^#mtu/mtu = 1420/g' "${confdir}/ocserv.conf"
    sed -i 's/auth = "pam\[gid-min=1000\]"/#auth = "pam\[gid-min=1000\]"/g'  "${confdir}/ocserv.conf"
    sed -i "s/route = 10.0.0.0\/8/#route = 10.0.0.0\/8/g" "${confdir}/ocserv.conf"
    sed -i "s/route = 172.16.0.0\/12/#route = 172.16.0.0\/12/g" "${confdir}/ocserv.conf"
    sed -i "s/route = 192.168.0.0\/8/#route = 192.168.0.0\/16/g" "${confdir}/ocserv.conf"
    ######################PAMMMMMM
}

Config_Firewall() {
   iptables -I INPUT -p tcp --dport 80 -j ACCEPT
   iptables -I INPUT -p tcp --dport ${port} -j ACCEPT
   iptables -I INPUT -p udp --dport ${port} -j ACCEPT
   iptables -I FORWARD -s ${vpnnetwork} -j ACCEPT
   iptables -I FORWARD -d ${vpnnetwork} -j ACCEPT
   iptables -t nat -A POSTROUTING -s ${vpnnetwork} -o ${eth} -j MASQUERADE   
}

Config_System() {
    #Disabled selinux
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
    #Modify the system
    echo "Enable IP forward."
    sysctl -w net.ipv4.ip_forward=1
    echo net.ipv4.ip_forward = 1 >> "/etc/sysctl.conf"
    systemctl daemon-reload
    echo "Enable ocserv service to start during bootup."
    systemctl enable ocserv.service
    #Start the ocserv service
    systemctl start ocserv.service
    echo
}

INSTALL_PANNEL_Env() {
     echo -e "\e[0;36m"Installing Pannel Environment..."\e[0m"
    apt install python3 python3-pip virtualenv build-essential python3-dev nginx git -y
    if [    "$?" = "0" ];then
        echo -e "\e[0;32m"Environment Installation Was Successful."\e[0m"
    else
        echo -e "\e[0;31m"Environment Installation Is Failed"\e[0m"
        exit 1
    fi
}

GIT_PROJECT(){
    echo -e "\e[0;36m"Get Project From Git Repository..."\e[0m"
    git clone https://github.com/mmtaee/Ocserv-Vpn-User-Management.git
    if [    "$?" = "0" ];then
        echo -e "\e[0;32m"Git Clone Was Successful."\e[0m"
    else
        echo -e "\e[0;31m"Cannot "Git Clone" Project From "github"."\e[0m"
        exit 1
    fi
}

PRO_DIR() {
    echo -e "\e[0;36m"Preparation Directorys And Files..."\e[0m"

    mkdir /var/www/html/ocserv_pannel/

    cp -r $(pwd)/* /var/www/html/ocserv_pannel/
}

PRO_VENV() {
    echo -e "\e[0;36m"Creating Python virtualenv..."\e[0m"

    cd /var/www/html/ocserv_pannel/

    virtualenv -p python3 venv

    source venv/bin/activate

    pip install -r requirements.txt

    ./manage.py migrate

    echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('admin', 'admin@myproject.com', 'admin')" | python manage.py shell

    mkdir static

    echo -e yes\n |./manage.py collectstatic

    chown -R www-data /var/www/html/ocserv_pannel/

    echo www-data ALL = NOPASSWD: /usr/bin/ocpasswd >> /etc/sudoers

    echo www-data ALL = NOPASSWD: /usr/bin/occtl >> /etc/sudoers
    
    echo www-data ALL = NOPASSWD: /usr/bin/systemctl restart ocserv.service >> /etc/sudoers
    
    echo www-data ALL = NOPASSWD: /usr/bin/systemctl status ocserv.service >> /etc/sudoers
}

PRO_SERVICES() {
    echo -e "\e[0;36m"Preparation Nginx"\e[0m"
    #################COPY CONFIG FILE
    rm -rf /etc/nginx/sites-enabled/default
    mv /var/www/html/ocserv_pannel/configs/ocserv_nginx.conf /etc/nginx/conf.d/
    mv /var/www/html/ocserv_pannel/configs/ocserv_uwsgi.service /lib/systemd/system
    systemctl daemon-reload;systemctl restart nginx ocserv_uwsgi.service;systemctl enable nginx ocserv_uwsgi.service;
    NGINX_STATE=`systemctl is-active nginx`
    if [    "$NGINX_STATE" = "active"  ]; then
        echo -e "\e[0;32m"Nginx Is Started."\e[0m"
    else
        echo -e "\e[0;31m"Nginx Is Not Running."\e[0m"
        exit 1
    fi
    OCSERV_STATE=`systemctl is-active ocserv`
    if [    "$OCSERV_STATE" = "active"  ]; then
        echo -e "\e[0;32m"Ocserv Is Started."\e[0m"
    else
        echo -e "\e[0;31m"Ocserv Is Not Running."\e[0m"
        exit 1
    fi  
        OCSERV_UWSGI_STATE=`systemctl is-active ocserv_uwsgi`
    if [    "$OCSERV_UWSGI_STATE" = "active"   ]; then
        echo -e "\e[0;32m"Ocserv_Uwsgi Is Started."\e[0m"
    else
        echo -e "\e[0;31m"Ocserv_Uwsgi Is Not Running."\e[0m"
        exit 1
    fi        
    
}

Config_Variable
Print_Variable
Install_Ocserv
Config_Ocserv
Config_Firewall
Config_System
INSTALL_PANNEL_Env
PRO_DIR
PRO_VENV
PRO_SERVICES
