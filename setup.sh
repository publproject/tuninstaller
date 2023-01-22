#!/bin/bash
# ===============================================================================
#  Name        : TunInstaller
#  Version     : V1.0 ( Stable Releases )
#  Desc        : Bash script to install Tunnel Service in Linux Server
#  Author      : PublProject [ Wildy, 𝑫𝒀𝑳𝑨𝑵 ]
#  Date        : 18-01-2023
#  Requirement : Ubuntu 18+, Debian 9+
#  License     : https://github.com/publproject/tuninstaller/blob/main/LICENSE
# ===============================================================================

# >> Declare Color
export RED="\033[0;31m"
export GREEN="\033[0;32m"
export YELLOW="\033[0;33m"
export BLUE="\033[0;34m"
export PURPLE="\033[0;35m"
export CYAN="\033[0;36m"
export LIGHT="\033[0;37m"
export NC="\033[0m"
export RED_BG="\e[41m"

# >> Declare Debug flag
export INFO="[${YELLOW} INFO ${NC}]"
export FAIL="[${RED} FAIL ${NC}]"
export OKEY="[${GREEN} OKEY ${NC}]"
export SEND="[${YELLOW} SEND ${NC}]"
export WAIT="[${YELLOW} WAIT ${NC}]"

# >> Check root access
if [[ $(whoami) != 'root' ]]; then
    clear; echo -e "${FAIL} Root access required for this process !"; exit 1
fi

# >> Check Arcitecture Support
if [[ $(uname -m ) != 'x86_64' ]]; then
    clear; echo -e "${FAIL} Only Supported 64Bit System !"; exit 1
fi

# >> Checking Operating Sytem
if [[ $(cat /etc/os-release | grep -w ID | sed 's/ID//g' | sed 's/"//g' | sed 's/=//g' | sed 's/ //g') == 'ubuntu' ]]; then
    if [[ $(cat /etc/os-release | grep -w VERSION_ID | sed 's/VERSION_ID//g' | sed 's/"//g' | sed 's/=//g' | cut -d '.' -f1 | sed 's/ //g') -lt 18 ]]; then
        clear; echo -e "${FAIL} $(cat /etc/os-release | grep -w ID | sed 's/ID//g' | sed 's/"//g' | sed 's/=//g' | sed 's/\b[a-z]/\u&/g') $(cat /etc/os-release | grep -w VERSION_ID | sed 's/VERSION_ID//g' | sed 's/ //g' | sed 's/"//g' | sed 's/=//g') Not Supported"; exit 1
    else
        export OS_USAGE="$(cat /etc/os-release | grep -w ID | sed 's/ID//g' | sed 's/"//g' | sed 's/=//g' | sed 's/\b[a-z]/\u&/g') $(cat /etc/os-release | grep -w VERSION_ID | sed 's/VERSION_ID//g' | sed 's/ //g' | sed 's/"//g' | sed 's/=//g')"
    fi
elif [[ $(cat /etc/os-release | grep -w ID | sed 's/ID//g' | sed 's/"//g' | sed 's/=//g' | sed 's/ //g') == 'debian' ]]; then
    if [[ $(cat /etc/os-release | grep -w VERSION_ID | sed 's/VERSION_ID//g' | sed 's/"//g' | sed 's/=//g' | cut -d '.' -f1 | sed 's/ //g') -lt 9 ]]; then
        clear; echo -e "${FAIL} $(cat /etc/os-release | grep -w ID | sed 's/ID//g' | sed 's/"//g' | sed 's/=//g' | sed 's/\b[a-z]/\u&/g') $(cat /etc/os-release | grep -w VERSION_ID | sed 's/VERSION_ID//g' | sed 's/ //g' | sed 's/"//g' | sed 's/=//g') Not Supported"; exit 1
    else
        export OS_USAGE="$(cat /etc/os-release | grep -w ID | sed 's/ID//g' | sed 's/"//g' | sed 's/=//g' | sed 's/\b[a-z]/\u&/g') $(cat /etc/os-release | grep -w VERSION_ID | sed 's/VERSION_ID//g' | sed 's/ //g' | sed 's/"//g' | sed 's/=//g')"
    fi
else
    clear; echo -e "${FAIL} Operating System not supported"; exit 1
fi

# >> Checking Requirement packages
for pkg in sudo wget curl nano zip unzip socat jq bzip2; do
    if ! command -V $pkg > /dev/null 2>&1; then
        clear; echo -e $"${INFO} Packages $pkg not installed, press enter to install"; read
        apt install $pkg -y
        if ! command -V $pkg > /dev/null 2>&1; then
            clear; echo -e "${INFO} Type 'apt update -y; apt upgrade -y' and try again"; exit 1
        else
            clear; echo -e "${INFO} $pkg Successfully installed !"; sleep 2 # >> Sleep 2 to continue on looping
        fi
    fi
done

# >> ini api gateway nanti mau di ganti jan lupa ingatkan
# >> Check IP Address
export REQUEST_TO_API=$(curl --silent --ipv4 --disable --no-buffer --url https://api.wildy.my.id/ipgeo/)
if [[ $(echo $REQUEST_TO_API | jq -r '.respon_code' ) == '200' ]]; then
    export IPGEO_IPADDR="$(echo $REQUEST_TO_API | jq -r '.ip')"
    export IPGEO_ASN="$(echo $REQUEST_TO_API | jq -r '.asn')"
    export IPGEO_ISP="$(echo $REQUEST_TO_API | jq -r '.isp')"
    export IPGEO_REGION="$(echo $REQUEST_TO_API | jq -r '.region')"
    export IPGEO_CITY="$(echo $REQUEST_TO_API | jq -r '.city')"
    export IPGEO_COUNTRY="$(echo $REQUEST_TO_API | jq -r '.country')"
    export IPGEO_DATE="$(echo $REQUEST_TO_API | jq -r '.date')"
    export IPGEO_TIME="$(echo $REQUEST_TO_API | jq -r '.time')"
    export IPGEO_DATETIME="$(echo $REQUEST_TO_API | jq -r '.datetime')"
    export IPGEO_TIMEZONE="$(echo $REQUEST_TO_API | jq -r '.timezone')"
else
    clear; echo -e "${FAIL} IPGEO API Under Maintenance"; exit 1
fi

# >> Checking Installation status
if [[ -r /etc/publproject/tuninstaller ]]; then
    clear; echo -e "${FAIL} Script already installed, Press Enter to replace but all data will be lost"; read
    rm -rf /etc/publproject
fi

# >> Create Required Dir
mkdir -p /etc/publproject
mkdir -p /etc/publproject/tuninstaller
mkdir -p /etc/publproject/tuninstaller/bin
mkdir -p /etc/publproject/tuninstaller/config
mkdir -p /etc/publproject/tuninstaller/cache
mkdir -p /etc/publproject/tuninstaller/logs
mkdir -p /etc/publproject/tuninstaller/certificate
mkdir -p /etc/publproject/tuninstaller/webserver

# >> Input DNS
clear; echo -e "
                      Welcome to TunInstaller
                 Version 1.0 [Stable] | 18-01-2023

               OS Requirement Debian 9+ / Ubuntu 18+
                Author PublProject [ Wildy, Dylan ]

                 This Project Licensed under GPLV3
   <https://github.com/publproject/tuninstaller/blob/main/LICENSE>

"
echo -e "${INFO} Starting TunInstaller Setup"
read -p "$(echo -e "${WAIT} Input Hostname : ")" hostname
if [[ ! $hostname =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$ ]]; then
    clear; echo -e "${FAIL} Domain invalid, input a valid domain and try again"; exit 1
else
echo -e "${INFO} Domain validated"
fi
echo -e "${OKEY} Your Hostname is $hostname"
echo -e "${OKEY} IP Address is $IPGEO_IPADDR"
echo -e "${OKEY} ISP is $IPGEO_ISP"
echo -e "${OKEY} Region is $IPGEO_REGION"
echo -e "${OKEY} City is $IPGEO_CITY"
echo -e "${OKEY} Country is $IPGEO_COUNTRY"
echo -e $"\n\nAll data is correct ? if yes type enter to continue"; read inputbro
case $inputbro in
    [Yy]*)
        clear; echo -e "${INFO} Installing will starting in 5 seconds"; sleep 5; clear
    ;;
    *)
        clear; echo -e "${INFO} Installation canceled"; rm -rf setup.sh; exit 1
    ;;
esac

# >> Create dns configuration
jq -r '.' > /etc/publproject/tuninstaller/config/network.json <<END
{"ip": "$IPGEO_IPADDR","hostname": "$hostname", "interface": "$(ip route | grep default | awk '{print $5}')"}
END

# >> Kill 443 and 80 port if used
lsof -t -i tcp:80 -s tcp:listen | xargs kill > /dev/null 2>&1
lsof -t -i tcp:443 -s tcp:listen | xargs kill > /dev/null 2>&1

# >> Create SSL Certificate
rm -rf /root/.acme.sh; mkdir -p /root/.acme.sh; cd /root/.acme.sh
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/bin/acme.sh" --output acme.sh
chmod +x acme.sh > /dev/null 2>&1
./acme.sh --set-default-ca --server letsencrypt  # >> Setting default ca to letsencrypt
./acme.sh --register-account -m halokakak@wildyqing.my.id
./acme.sh --issue -d $(cat /etc/publproject/tuninstaller/config/network.json | jq -r '.hostname') --standalone -k ec-256 -ak ec-256
./acme.sh --installcert -d $(cat /etc/publproject/tuninstaller/config/network.json | jq -r '.hostname') \
--certpath /etc/publproject/tuninstaller/certificate/ssl.cert \
--keypath /etc/publproject/tuninstaller/certificate/ssl.key \
--capath /etc/publproject/tuninstaller/certificate/ca.cer \
--fullchainpath /etc/publproject/tuninstaller/certificate/fullchain.cer --ecc
read -p "$( echo -e $"\n------------------------------------\nPress any key to continue")"

# >> Clear terminal
clear

# >> Set timezone to jakarta
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# >> Set locale time
localectl set-locale LC_TIME="en_GB.UTF-8"

# >> Update repository and remove not used packages
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt remove --purge nginx apache2 ufw -y
apt autoremove -y
apt clean -y

# >> Installing requirement tools
apt install jq socat sudo net-tools openssl curl wget \
git zip unzip nano make lsof  bc gcc cmake htop libssl-dev \
sed zlib1g-dev libsqlite3-dev libpcre3 libpcre3-dev \
libxslt-dev apt-transport-https build-essential libxml2-dev \
rsyslog libreadline-dev screen libgd-dev libconfig-dev \
libconfig-dev libwrap0-dev libsystemd-dev libcap-dev \
libev-dev libbsd-dev libpcre2-dev debconf-utils -y

# >> Configure iptables-persistent ipv4 and ipv5 
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections

# >> Installing iptables-persistent and netfilter-persistent
apt install iptables netfilter-persistent iptables-persistent -y

# >> Configure environment
cat > /etc/environment << END
localectl set-locale LC_TIME="en_GB.UTF-8" # >> Set locale to utf8
PATH=/etc/publproject/tuninstaller/bin:/root/.acme.sh:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
END
source /etc/environment

# >> Install python
apt install python -y > /dev/null 2>&1
apt install python2 -y > /dev/null 2>&1
apt install python3 -y > /dev/null 2>&1

# >> Configure Python enviroment
if [[ $( which python3 ) == '' ]]; then
    # >> Python2
    cp --force $(which python) /etc/publproject/tuninstaller/bin/python > /dev/null 2>&1
else
    # >> Python3
    cp --force $(which python3) /etc/publproject/tuninstaller/bin/python3 > /dev/null 2>&1
    cp --force $(which python3) /etc/publproject/tuninstaller/bin/python > /dev/null 2>&1
fi

# >> Install Vnstat
rm -rf /root/vnstat; cd /root/ # >> Back to root directory
curl --silent --ipv4 --disable --no-buffer --url https://raw.githubusercontent.com/publproject/tuninstaller/main/source/vnstat.zip --output vnstat.zip
curl --silent --ipv4 --disable --no-buffer --url https://raw.githubusercontent.com/publproject/tuninstaller/main/service/vnstat.service --output /lib/systemd/system/vnstat.service
unzip -o /root/vnstat.zip > /dev/null 2>&1; cd /root/vnstat/; chmod +x configure
./configure --prefix=/usr --sysconfdir=/etc && make && make install
sed -i 's/;Interface ""/Interface "'""$(cat /etc/publproject/tuninstaller/config/network.json | jq -r '.interface')""'"/g' /etc/vnstat.conf; cd /root/
systemctl daemon-reload; systemctl disable vnstat; systemctl stop vnstat; systemctl enable vnstat; systemctl start vnstat; systemctl restart vnstat
rm -rf /root/vnstat; rm -rf /root/vnstat.zip cd; /root

# >> Installing Squid Proxy
apt install squid -y
curl --silent --ipv4 --disable --no-buffer --url https://raw.githubusercontent.com/publproject/tuninstaller/main/config/squid.conf --output /etc/squid/squid.conf
sed -i "s/hostnya/$(cat /etc/publproject/tuninstaller/config/network.json | jq -r '.ip')/g" /etc/squid/squid.conf
systemctl restart squid

# >> Installing BadVPN
cd /etc/publproject/tuninstaller/bin/
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/bin/badvpn-udpgw" --output /etc/publproject/tuninstaller/bin/badvpn-udpgw
chmod +x /etc/publproject/tuninstaller/bin/badvpn-udpgw
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/service/badvpn-7100.service" --output /etc/systemd/system/badvpn-7100.service
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/service/badvpn-7200.service" --output /etc/systemd/system/badvpn-7200.service
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/service/badvpn-7300.service" --output /etc/systemd/system/badvpn-7300.service
systemctl disable badvpn-7100; systemctl stop badvpn-7100; systemctl enable badvpn-7100; systemctl start badvpn-7100; systemctl restart badvpn-7100
systemctl disable badvpn-7200; systemctl stop badvpn-7200; systemctl enable badvpn-7200; systemctl start badvpn-7200; systemctl restart badvpn-7200
systemctl disable badvpn-7300; systemctl stop badvpn-7300; systemctl enable badvpn-7300; systemctl start badvpn-7300; systemctl restart badvpn-7300

# >> Installing Webserver
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/bin/webserver.py" --output /etc/publproject/tuninstaller/bin/webserver.py
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/service/webserver.service" --output /etc/systemd/system/webserver.service
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/index.file" --output /etc/publproject/tuninstaller/webserver/index.html
systemctl enable webserver; systemctl start webserver; systemctl restart webserver

# >> Install XRay Core
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/bin/xray" --output /etc/publproject/tuninstaller/bin/xray
chmod +x /etc/publproject/tuninstaller/bin/xray > /dev/null 2>&1
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/service/xray%40.service" --output /etc/systemd/system/xray@.service
mkdir -p /etc/publproject/tuninstaller/cache/xray; mkdir -p /etc/publproject/tuninstaller/config/xray/

# >> Configure common-password
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/common-password" --output /etc/pam.d/common-password
chmod +x /etc/pam.d/common-password

# >> Replace sshd configuration
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/sshd.conf" --output /etc/ssh/sshd_config
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/banner.conf" --output /etc/publproject/tuninstaller/config/banner.conf
systemctl daemon-reload; systemctl restart ssh; systemctl restart sshd

# >> Installing WS-ePro
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/bin/ws-epro" --output /etc/publproject/tuninstaller/bin/ws-epro
chmod +x /etc/publproject/tuninstaller/bin/ws-epro
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/ws-epro.conf" --output /etc/publproject/tuninstaller/config/ws-epro.conf
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/service/ws-epro.service" --output /etc/systemd/system/ws-epro.service
systemctl daemon-reload; systemctl disable ws-epro; systemctl stop ws-epro; systemctl enable ws-epro; systemctl start ws-epro; systemctl restart ws-epro

# >> Installing Dropbear
echo -e "# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/bin/dash
/usr/bin/dash
/usr/bin/tmux
/usr/bin/screen
/bin/false
" > /etc/shells
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/source/dropbear.zip" --output /root/dropbear.zip
cd /root/; unzip -o dropbear.zip > /dev/null 2>&1; cd dropbear; chmod -R 777 *
./configure && make && make install
cd /root/; rm -rf dropbear; rm -rf dropbear.zip
rm -rf /etc/dropbear; mkdir -p /etc/dropbear
mv /usr/local/sbin/dropbear /etc/publproject/tuninstaller/bin; killall dropbear > /dev/null 2>&1
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/service/dropbear.service" --output /etc/systemd/system/dropbear.service
systemctl daemon-reload; systemctl disable dropbear; systemctl stop dropbear; systemctl enable dropbear; systemctl start dropbear

# >> Installing XRay Main Reserve port
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/main.json" --output /etc/publproject/tuninstaller/config/xray/main.json
systemctl daemon-reload; systemctl disable xray@main; systemctl stop xray@main; systemctl enable xray@main; systemctl start xray@main

# >> Installing OpenVPN
apt update -y; apt upgrade -y; apt dist-upgrade -y; apt autoremove -y; apt clean -y
apt install openvpn unzip openssl iptables jq nano wget curl -y
rm -rf /etc/openvpn; mkdir -p /etc/openvpn; cd /etc/openvpn/
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/certificate/ovpn-cert.zip" --output openvpn.zip
unzip -o openvpn.zip > /dev/null 2>&1; rm -rf openvpn.zip
mkdir -p config; rm -rf server; rm -rf client
chown -R root:root /etc/openvpn/ # >> Change permission on openvpn directory
mkdir -p /usr/lib/openvpn/; cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so
sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/tcp.conf" --output /etc/openvpn/tcp.conf
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/udp.conf" --output /etc/openvpn/udp.conf
rm -f /lib/systemd/system/openvpn*; rm -rf /etc/init.d/openvpn > /dev/null 2>&1
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/service/openvpn.service" --output /etc/systemd/system/openvpn@.service
systemctl daemon-reload; systemctl stop openvpn@tcp; systemctl disable openvpn@tcp; systemctl enable openvpn@tcp; systemctl start openvpn@tcp;
systemctl daemon-reload; systemctl stop openvpn@udp; systemctl disable openvpn@udp; systemctl enable openvpn@udp; systemctl start openvpn@udp;
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/tcp.ovpn" --output /etc/openvpn/config/tcp.ovpn
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/udp.ovpn" --output /etc/openvpn/config/udp.ovpn
cd /etc/openvpn/config; sed -i "s/ipnya/${IPGEO_IPADDR}/g" *.ovpn
for name_file in $(ls -lh | awk '{print $9}' | sed 's/ //g'); do
echo "<ca>" >> $name_file; cat /etc/openvpn/ca.crt >> $name_file; echo '</ca>' >> $name_file
done
zip all.zip tcp.ovpn udp.ovpn > /dev/null 2>&1; cp --force all.zip /etc/publproject/tuninstaller/webserver/ > /dev/null 2>&1
cp --force tcp.ovpn /etc/publproject/tuninstaller/webserver/ > /dev/null 2>&1
cp --force udp.ovpn /etc/publproject/tuninstaller/webserver/ > /dev/null 2>&1
chmod 775 /etc/publproject/tuninstaller/webserver/*

# >> Setting IP Tables to MASQUERADE
iptables -t nat -I POSTROUTING -s 15.15.10.1/24 -o $(cat /etc/publproject/tuninstaller/config/network.json | jq -r '.interface') -j MASQUERADE
iptables -t nat -I POSTROUTING -s 15.15.11.1/24 -o $(cat /etc/publproject/tuninstaller/config/network.json | jq -r '.interface') -j MASQUERADE
iptables-save > /etc/iptables.up.rules
chmod +x /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save > /dev/null 2>&1
netfilter-persistent reload > /dev/null 2>&1

# >> Adding Port To IPTables ( OpenVPN 1194 / TCP )
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 1194 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 1194 -j ACCEPT
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save > /dev/null 2>&1
netfilter-persistent reload > /dev/null 2>&1

# >> Adding Port To IPTables ( OpenVPN 1195 / UDP )
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 1195 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 1195 -j ACCEPT
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save > /dev/null 2>&1
netfilter-persistent reload > /dev/null 2>&1

# >> Download Vmess, Vless, Trojan config
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/vmess.json" --output /etc/publproject/tuninstaller/config/xray/vmess.json
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/vless.json" --output /etc/publproject/tuninstaller/config/xray/vless.json
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/config/trojan.json" --output /etc/publproject/tuninstaller/config/xray/trojan.json

# >> Starting service
systemctl daemon-reload; systemctl stop xray@vmess; systemctl disable xray@vmess; systemctl enable xray@vmess; systemctl start xray@vmess; systemctl restart xray@vmess
systemctl daemon-reload; systemctl stop xray@vless; systemctl disable xray@vless; systemctl enable xray@vless; systemctl start xray@vless; systemctl restart xray@vless
systemctl daemon-reload; systemctl stop xray@trojan; systemctl disable xray@trojan; systemctl enable xray@trojan; systemctl start xray@trojan; systemctl restart xray@trojan

# >> Installing API
apt install python3-pip -y; pip3 install flask
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/api/api-controller.py" --output /etc/publproject/tuninstaller/bin/api-controller.py
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/api/api-exec" --output /etc/publproject/tuninstaller/bin/api-exec
chmod +x /etc/publproject/tuninstaller/bin/api-exec
curl --silent --ipv4 --disable --no-buffer --url "https://raw.githubusercontent.com/publproject/tuninstaller/main/service/api.service" --output /etc/systemd/system/api.service
systemctl daemon-reload; systemctl stop api; systemctl disable api; systemctl enable api; systemctl start api
xray uuid > /etc/publproject/tuninstaller/auth-token.txt

cd /root/; rm -rf setup.sh
clear
echo "Installation Complete
this is ur API Keys : $(cat /etc/publproject/tuninstaller/auth-token.txt)"
