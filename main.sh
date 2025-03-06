#!/bin/bash

### Color
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}✓${FONT}"
ERROR="${RED}✗${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
BOLD="\033[1m"
UNDERLINE="\033[4m"
BLINK="\033[5m"
REVERSE="\033[7m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
WHITE="\033[0;37m"

### System Information
TANGGAL=$(date '+%Y-%m-%d')
TIMES="10"
NAMES=$(whoami)
IMP="wget -q -O"    
CHATID="@faizvpn"
LOCAL_DATE="/usr/bin/"
MYIP=$(wget -qO- ipinfo.io/ip)
CITY=$(curl -s ipinfo.io/city)
TIME=$(date +'%Y-%m-%d %H:%M:%S')
RAMMS=$(free -m | awk 'NR==2 {print $2}')
KEY="2145515560:AAE9WqfxZzQC-FYF1VUprICGNomVfv6OdTU"
URL="https://api.telegram.org/bot$KEY/sendMessage"
REPO="https://raw.githubusercontent.com/Abdofaiz/boxx/main/"
APT="apt-get -y install "
domain=$(cat /root/domain)
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
### Status
function print_ok() {
    echo -e "${BOLD}${OK} ${BLUE}$1${FONT}"
}

function print_install() {
    echo -e "\n${BOLD}${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${FONT}"
    echo -e "${BOLD}${CYAN}║${FONT} ${GREEN}📦 $1${FONT}"
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${FONT}\n"
    sleep 1
}

function print_error() {
    echo -e "\n${BOLD}${REDBG}╔════════════════════════════════════════════════════════════════════════════╗${FONT}"
    echo -e "${BOLD}${REDBG}║${FONT} ${ERROR} ${RED}$1${FONT}"
    echo -e "${BOLD}${REDBG}╚════════════════════════════════════════════════════════════════════════════╝${FONT}\n"
}

function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "\n${BOLD}${GREENBG}╔════════════════════════════════════════════════════════════════════════════╗${FONT}"
        echo -e "${BOLD}${GREENBG}║${FONT} ${OK} ${GREEN}$1 Successfully installed${FONT}"
        echo -e "${BOLD}${GREENBG}╚════════════════════════════════════════════════════════════════════════════╝${FONT}\n"
        sleep 2
    fi
}

function print_progress() {
    local percent=$1
    local width=50
    local filled=$((width * percent / 100))
    local empty=$((width - filled))
    local bar=""
    
    # Create progress bar
    for ((i=0; i<filled; i++)); do
        bar+="█"
    done
    for ((i=0; i<empty; i++)); do
        bar+="░"
    done
    
    echo -e "\n${BOLD}${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${FONT}"
    echo -e "${BOLD}${BLUE}║${FONT} ${GREEN}🔄 Installation Progress: ${percent}%${FONT}"
    echo -e "${BOLD}${BLUE}║${FONT} ${MAGENTA}[${bar}]${FONT}"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${FONT}\n"
}

function print_header() {
    clear
    echo -e "${BOLD}${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${FONT}"
    echo -e "${BOLD}${BLUE}║${FONT} ${GREEN}🚀 VPS MAX PREMIUM SERVER INSTALLATION${FONT}"
    echo -e "${BOLD}${BLUE}║${FONT} ${GRAY}Version: 1.0.0${FONT}"
    echo -e "${BOLD}${BLUE}║${FONT} ${GRAY}Author: @faizvpn${FONT}"
    echo -e "${BOLD}${BLUE}║${FONT} ${GRAY}Date: $(date '+%Y-%m-%d %H:%M:%S')${FONT}"
    echo -e "${BOLD}${BLUE}║${FONT} ${GRAY}IP: ${MYIP}${FONT}"
    echo -e "${BOLD}${BLUE}║${FONT} ${GRAY}Location: ${CITY}${FONT}"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${FONT}\n"
}

function print_footer() {
    echo -e "\n${BOLD}${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${FONT}"
    echo -e "${BOLD}${BLUE}║${FONT} ${GREEN}✨ Installation completed successfully!${FONT}"
    echo -e "${BOLD}${BLUE}║${FONT} ${GRAY}Time taken: $(secs_to_human "$(($(date +%s) - ${start}))")${FONT}"
    echo -e "${BOLD}${BLUE}║${FONT} ${GRAY}Server will reboot in 10 seconds...${FONT}"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${FONT}\n"
}

function print_welcome() {
    echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${FONT}"
    echo -e "${BOLD}${CYAN}║${FONT} ${GREEN}👋 Welcome to VPS MAX Premium Server Installation${FONT}"
    echo -e "${BOLD}${CYAN}║${FONT} ${GRAY}This script will install and configure your server${FONT}"
    echo -e "${BOLD}${CYAN}║${FONT} ${GRAY}Please make sure you have a stable internet connection${FONT}"
    echo -e "${BOLD}${CYAN}║${FONT} ${GRAY}The installation process may take several minutes${FONT}"
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${FONT}\n"
    sleep 3
}

### Check root
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
    fi

}

### Change Environment System
function first_setup(){
    timedatectl set-timezone Asia/Kuala_Lumpur
    wget -O /etc/banner ${REPO}config/banner >/dev/null 2>&1
    chmod +x /etc/banner
    wget -O /etc/ssh/sshd_config ${REPO}config/sshd_config >/dev/null 2>&1
    chmod 644 /etc/ssh/sshd_config

    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    
}

### Update and remove packages
function base_package() {
    # Remove unnecessary packages
    apt-get autoremove -y man-db apache2 ufw exim4 firewalld snapd* -y
    
    # Disable IPv6 for better performance
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
    
    # Add repository and update
    apt install software-properties-common -y
    add-apt-repository ppa:vbernat/haproxy-2.7 -y
    apt update && apt upgrade -y
    
    # Install only essential packages
    apt install -y --no-install-recommends \
        squid nginx zip pwgen openssl netcat bash-completion \
        curl socat xz-utils wget apt-transport-https dnsutils \
        tar ruby unzip p7zip-full python3-pip haproxy libc6 \
        msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent \
        netfilter-persistent net-tools jq openvpn easy-rsa \
        python3-certbot-nginx tuned fail2ban
    
    # Clean up
    apt-get clean all
    apt-get autoremove -y
    rm -rf /var/lib/apt/lists/*
    
    print_ok "Successfully installed the required package"
}

clear

### Create Xrays directory
function dir_xray() {
    print_install "Create Xrays directory"
    mkdir -p /etc/{xray,vmess,websocket,vless,trojan,shadowsocks}
    # mkdir -p /usr/sbin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html/
    mkdir -p /etc/nevermoressh/
#    chmod +x /var/log/xray
    touch /var/log/xray/{access.log,error.log}
    chmod 777 /var/log/xray/*.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/ssh/.ssh.db
    touch /etc/shadowsocks/.shadowsocks.db
    clear
}

### Add domain
function add_domain() {
    echo "`cat /etc/banner`"
    read -rp "Input Your Domain For This Server :" -e SUB_DOMAIN
    echo "Host : $SUB_DOMAIN"
    echo $SUB_DOMAIN > /root/domain
    cp /root/domain /etc/xray/domain
}

### Install SSL
function pasang_ssl() {
    print_install "Installing SSL on the domain"
    domain=$(cat /root/domain)
    if [ -z "$domain" ]; then
        print_error "Domain not set. Please set domain first."
        exit 1
    }
    
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh
    
    if ! systemctl stop $STOPWEBSERVER; then
        print_error "Failed to stop webserver"
        exit 1
    fi
    
    if ! systemctl stop nginx; then
        print_error "Failed to stop nginx"
        exit 1
    fi
    
    if ! curl https://raw.githubusercontent.com/Abdofaiz/boxx/main/acme.sh -o /root/.acme.sh/acme.sh; then
        print_error "Failed to download acme.sh"
        exit 1
    fi
    
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    
    if ! /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256; then
        print_error "Failed to issue SSL certificate"
        exit 1
    fi
    
    if ! ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc; then
        print_error "Failed to install SSL certificate"
        exit 1
    fi
    
    # Set more secure permissions
    chmod 644 /etc/xray/xray.crt
    chmod 600 /etc/xray/xray.key
    chown root:root /etc/xray/xray.crt
    chown root:root /etc/xray/xray.key
    
    print_success "SSL Certificate"
}

### Install Xray
function install_xray(){
    print_install "Installing the latest Xray module"
    curl -s ipinfo.io/city >> /etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /etc/xray/isp
    xray_latest="$(curl -s https://api.github.com/repos/dharak36/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    xraycore_link="https://github.com/Abdofaiz/boxx/releases/download/Xray-linux-64-v1.6.5.1/Xray-linux-64-v1.6.5.1"
    curl -sL "$xraycore_link" -o xray
#    unzip -q xray.zip && rm -rf xray.zip
    mv xray /usr/sbin/xray
    print_success "Xray Core"
    
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/xray.pem
    wget -O /etc/xray/config.json "${REPO}xray/config.json" >/dev/null 2>&1 
    #wget -O /usr/sbin/xray/ "${REPO}bin/xray" >/dev/null 2>&1
    wget -O /usr/sbin/websocket "${REPO}bin/ws" >/dev/null 2>&1
    wget -O /etc/websocket/tun.conf "${REPO}xray/tun.conf" >/dev/null 2>&1 
    wget -O /etc/systemd/system/ws.service "${REPO}xray/ws.service" >/dev/null 2>&1 
    wget -q -O /etc/ipserver "${REPO}server/ipserver" && bash /etc/ipserver >/dev/null 2>&1

    # > Set Permission
    chmod +x /usr/sbin/xray
    chmod +x /usr/sbin/websocket
    chmod 644 /etc/websocket/tun.conf
    chmod 644 /etc/systemd/system/ws.service

    # > Create Service
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/sbin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
print_success "Xray C0re"
}

### Install OpenVPN
function install_ovpn(){
    print_install "Install the Openvpn module"
    source <(curl -sL ${REPO}openvpn/openvpn)
    wget -O /etc/pam.d/common-password "${REPO}openvpn/common-password" >/dev/null 2>&1
    chmod +x /etc/pam.d/common-password
    # > BadVPN
    source <(curl -sL ${REPO}badvpn/setup.sh)
    print_success "OpenVPN"
}

### Install SlowDNS
function install_slowdns(){
    print_install "Installing the SlowDNS Server module"
    wget -q -O /tmp/nameserver "${REPO}slowdns/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
    print_success "SlowDNS"
}

### Install Rclone
function pasang_rclone() {
    print_install "Installing Rclone"
    print_success "Installing Rclone"
    curl "${REPO}bin/rclone" | bash >/dev/null 2>&1
    print_success "Rclone"
}

### Take Config
function download_config(){
    print_install "Install configuration package configuration"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    wget -O /etc/nginx/nginx.conf "${REPO}config/nginx.conf" >/dev/null 2>&1
    wget -q -O /etc/squid/squid.conf "${REPO}config/squid.conf" >/dev/null 2>&1
    echo "visible_hostname $(cat /etc/xray/domain)" /etc/squid/squid.conf
    mkdir -p /var/log/squid/cache/
    chmod 777 /var/log/squid/cache/
    echo "* - nofile 65535" >> /etc/security/limits.conf
    mkdir -p /etc/sysconfig/
    echo "ulimit -n 65535" >> /etc/sysconfig/squid

    # > Add Dropbear
    apt install dropbear -y
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear" >/dev/null 2>&1
    chmod 644 /etc/default/dropbear
    wget -q -O /etc/banner "${REPO}config/banner" >/dev/null 2>&1
    
    # > Add menu, thanks to NevermoreSSH <3
    wget -O /tmp/menu-master.zip "${REPO}config/menu.zip" >/dev/null 2>&1
    mkdir /tmp/menu
    7z e  /tmp/menu-master.zip -o/tmp/menu/ >/dev/null 2>&1
    chmod +x /tmp/menu/*
    mv /tmp/menu/* /usr/sbin/


    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

cat >/etc/cron.d/xp_all <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/bin/xp
EOF

chmod 644 /root/.profile

cat >/etc/cron.d/daily_reboot <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
EOF

echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
service cron restart
cat >/home/daily_reboot <<EOF
5
EOF

cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
    chmod +x /etc/rc.local
    print_ok "Konfigurasi file selesai"
}

### Additional
function tambahan(){
    print_install "Installing additional modules"
    
    # System tuning for better performance
    cat >/etc/sysctl.d/99-sysctl.conf <<EOF
# System limits
fs.file-max = 65535
fs.inotify.max_user_instances = 524288
fs.inotify.max_user_watches = 524288
fs.inotify.max_queued_events = 524288

# Network tuning
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fastopen = 1

# Memory tuning
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10
EOF

    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-sysctl.conf

    # Install speedtest
    wget -O /usr/sbin/speedtest "${REPO}bin/speedtest" >/dev/null 2>&1
    chmod +x /usr/sbin/speedtest

    # Install gotop
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1

    # Create swap file with better settings
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    
    # Add swap to fstab with better settings
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    
    # Configure swapiness
    echo 'vm.swappiness=10' >> /etc/sysctl.conf
    sysctl -p

    # Tuned profile for network latency
    tuned-adm profile network-latency

    # Configure msmtp with secure settings
    cat >/etc/msmtprc <<EOF
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user ${SMTP_USER:-taibabihutan17@gmail.com}
from ${SMTP_FROM:-taibabihutan17@gmail.com}
password ${SMTP_PASS:-romanisti}
logfile ~/.msmtp.log
EOF

    # Set proper permissions for msmtp
    chgrp mail /etc/msmtprc
    chmod 0600 /etc/msmtprc
    touch /var/log/msmtp.log
    chown syslog:adm /var/log/msmtp.log
    chmod 660 /var/log/msmtp.log
    
    # Create symlinks for sendmail
    ln -sf /usr/bin/msmtp /usr/sbin/sendmail
    ln -sf /usr/bin/msmtp /usr/bin/sendmail
    ln -sf /usr/bin/msmtp /usr/lib/sendmail

    print_ok "Additional modules installed successfully"
}


########## SETUP FROM HERE ##########
# ORIGINAL SCRIPT BY VPS MAX   #
#####################################
echo "INSTALLING SCRIPT..."

touch /root/.install.log
cat >/root/tmp <<-END
#!/bin/bash
#vps
### VPSMAX $TANGGAL $MYIP
END
####
VPSMAX() {
    data=($(cat /root/tmp | grep -E "^### " | awk '{print $2}'))
    for user in "${data[@]}"; do
        exp=($(grep -E "^### $user" "/root/tmp" | awk '{print $3}'))
        d1=($(date -d "$exp" +%s))
        d2=($(date -d "$Date_list" +%s))
        exp2=$(((d1 - d2) / 86400))
        if [[ "$exp2" -le "0" ]]; then
            echo $user >/etc/.$user.ini
        else
            rm -f /etc/.$user.ini
        fi
    done
    rm -f /root/tmp
}

function enable_services(){
    print_install "Restart servis"
    
    # Reload systemd daemon
    systemctl daemon-reload
    
    # Start and enable essential services
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now rc-local
    systemctl enable --now dropbear
    systemctl enable --now openvpn
    systemctl enable --now cron
    systemctl enable --now haproxy
    systemctl enable --now netfilter-persistent
    systemctl enable --now squid
    systemctl enable --now ws
    systemctl enable --now client
    systemctl enable --now server
    systemctl enable --now fail2ban
    
    # Configure service limits
    cat >/etc/systemd/system.conf <<EOF
DefaultLimitNOFILE=65535
DefaultLimitNPROC=65535
DefaultLimitNICE=-20
DefaultLimitCORE=infinity
EOF
    
    # Configure service timeouts
    cat >/etc/systemd/system.d/10-timeout.conf <<EOF
[Manager]
DefaultTimeoutStartSec=30s
DefaultTimeoutStopSec=30s
DefaultRestartSec=3s
EOF
    
    # Configure service memory limits
    cat >/etc/systemd/system.d/10-memory.conf <<EOF
[Manager]
DefaultMemoryLimit=infinity
DefaultMemorySwapLimit=infinity
EOF
    
    # Apply systemd changes
    systemctl daemon-reload
    
    # Configure Rclone
    wget -O /root/.config/rclone/rclone.conf "${REPO}rclone/rclone.conf" >/dev/null 2>&1
    
    print_ok "Services configured and enabled successfully"
}

function install_all() {
    # Show welcome message
    print_welcome
    
    # Show header
    print_header
    
    # Create log directory
    mkdir -p /var/log/installer
    LOG_FILE="/var/log/installer/install.log"
    
    # Function to log messages
    log_message() {
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
    }
    
    # Function to handle errors
    handle_error() {
        log_message "ERROR: $1"
        print_error "$1"
        exit 1
    }
    
    log_message "Starting installation process..."
    print_progress "0"
    
    # Base package installation
    log_message "Installing base packages..."
    print_install "Installing Base Packages"
    if ! base_package; then
        handle_error "Failed to install base packages"
    fi
    print_progress "20"
    
    # SSL installation
    log_message "Installing SSL certificate..."
    print_install "Installing SSL Certificate"
    if ! pasang_ssl; then
        handle_error "Failed to install SSL certificate"
    fi
    print_progress "40"
    
    # Xray installation
    log_message "Installing Xray..."
    print_install "Installing Xray Core"
    if ! install_xray; then
        handle_error "Failed to install Xray"
    fi
    print_progress "60"
    
    # OpenVPN installation
    log_message "Installing OpenVPN..."
    print_install "Installing OpenVPN"
    if ! install_ovpn; then
        handle_error "Failed to install OpenVPN"
    fi
    print_progress "70"
    
    # SlowDNS installation
    log_message "Installing SlowDNS..."
    print_install "Installing SlowDNS"
    if ! install_slowdns; then
        handle_error "Failed to install SlowDNS"
    fi
    print_progress "80"
    
    # Configuration download
    log_message "Downloading configurations..."
    print_install "Downloading Configurations"
    if ! download_config; then
        handle_error "Failed to download configurations"
    fi
    print_progress "85"
    
    # Service enablement
    log_message "Enabling services..."
    print_install "Enabling Services"
    if ! enable_services; then
        handle_error "Failed to enable services"
    fi
    print_progress "90"
    
    # Additional modules
    log_message "Installing additional modules..."
    print_install "Installing Additional Modules"
    if ! tambahan; then
        handle_error "Failed to install additional modules"
    fi
    print_progress "95"
    
    # Rclone installation
    log_message "Installing Rclone..."
    print_install "Installing Rclone"
    if ! pasang_rclone; then
        handle_error "Failed to install Rclone"
    fi
    print_progress "100"
    
    log_message "Installation completed successfully"
    print_success "All components installed successfully"
    print_footer
}

function finish(){
    TEXT="
<u>INFORMATION VPS INSTALL SC</u>
<code>TIME    : </code><code>${TIME}</code>
<code>IPVPS   : </code><code>${MYIP}</code>
<code>DOMAIN  : </code><code>${domain}</code>
<code>IP VPS  : </code><code>${MYIP}</code>
<code>LOKASI  : </code><code>${CITY}</code>
<code>USER    : </code><code>${NAMES}</code>
<code>RAM     : </code><code>${RAMMS}MB</code>
<code>LINUX   : </code><code>${OS}</code>
"
    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
    cp /etc/openvpn/*.ovpn /var/www/html/
    # sed -i "s/xxx/${domain}/g" /var/www/html/index.html
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${MYIP}/g" /etc/squid/squid.conf
    chown -R www-data:www-data /etc/msmtprc


    # > Bersihkan History
    alias bash2="bash --init-file <(echo '. ~/.bashrc; unset HISTFILE')"
    clear
    echo "    ┌─────────────────────────────────────────────────────┐"
    echo "    │       >>> Service & Port                            │"
    echo "    │   - Open SSH                : 443, 80, 22           │"
    echo "    │   - DNS (SLOWDNS)           : 443, 80, 53           │"
    echo "    │   - Dropbear                : 443, 109, 80          │"
    echo "    │   - Dropbear Websocket      : 443, 109              │"
    echo "    │   - SSH Websocket SSL       : 443                   │"
    echo "    │   - SSH Websocket           : 80                    │"
    echo "    │   - OpenVPN SSL             : 443                   │"
    echo "    │   - OpenVPN Websocket SSL   : 443                   │"
    echo "    │   - OpenVPN TCP             : 443, 1194             │"
    echo "    │   - OpenVPN UDP             : 2200                  │"
    echo "    │   - Nginx Webserver         : 443, 80, 81           │"
    echo "    │   - Haproxy Loadbalancer    : 443, 80               │"
    echo "    │   - DNS Server              : 443, 53               │"
    echo "    │   - DNS Client              : 443, 88               │"
    echo "    │   - XRAY DNS (SLOWDNS)      : 443, 80, 53           │"
    echo "    │   - XRAY Vmess TLS          : 443                   │"
    echo "    │   - XRAY Vmess gRPC         : 443                   │"
    echo "    │   - XRAY Vmess None TLS     : 80                    │"
    echo "    │   - XRAY Vless TLS          : 443                   │"
    echo "    │   - XRAY Vless gRPC         : 443                   │"
    echo "    │   - XRAY Vless None TLS     : 80                    │"
    echo "    │   - Trojan gRPC             : 443                   │"
    echo "    │   - Trojan WS               : 443                   │"
    echo "    │   - Shadowsocks WS          : 443                   │"
    echo "    │   - Shadowsocks gRPC        : 443                   │"
    echo "    │                                                     │"
    echo "    │      >>> Server Information & Other Features        │"
    echo "    │   - Autoreboot On           : $AUTOREB:00 $TIME_DATE GMT +8        │"
    echo "    │   - Auto Delete Expired Account                     │"
    echo "    │   - Fully automatic script                          │"
    echo "    │   - VPS settings                                    │"
    echo "    │   - Admin Control                                   │"
    echo "    │   - Restore Data                                    │"
    echo "    │                                                     │"
    echo "    └─────────────────────────────────────────────────────┘"
    secs_to_human "$(($(date +%s) - ${start}))"
    # echo -ne "         ${YELLOW}Please Reboot Your Vps${FONT} (y/n)? "
    # read REDDIR
    # if [ "$REDDIR" == "${REDDIR#[Yy]}" ]; then
    #     exit 0
    # else
    #     reboot
    # fi
}
cd /tmp
VPSMAX
first_setup
dir_xray
add_domain
install_all
finish  

rm ~/.bash_history
sleep 10
reboot
