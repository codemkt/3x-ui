#!/bin/bash
# x-ui + SSL + Nginx + Trojan auto installer (Ubuntu 18.04+ friendly)

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1

# Check OS and set release variable
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "Failed to check the system OS, please contact the author!" >&2
    exit 1
fi
echo "The OS release is: $release"

arch() {
    case "$(uname -m)" in
    x86_64 | x64 | amd64) echo 'amd64' ;;
    i*86 | x86) echo '386' ;;
    armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
    armv7* | armv7 | arm) echo 'armv7' ;;
    armv6* | armv6) echo 'armv6' ;;
    armv5* | armv5) echo 'armv5' ;;
    s390x) echo 's390x' ;;
    *) echo -e "${green}Unsupported CPU architecture! ${plain}" && rm -f install.sh && exit 1 ;;
    esac
}

echo "arch: $(arch)"

os_version=""
os_version=$(grep "^VERSION_ID" /etc/os-release | cut -d '=' -f2 | tr -d '"' | tr -d '.')

# OS version guard (Ubuntu 18.04+)
if [[ "${release}" == "ubuntu" ]]; then
    if [[ ${os_version} -lt 1804 ]]; then
        echo -e "${red} Please use Ubuntu 18.04 or higher version!${plain}\n" && exit 1
    fi
elif [[ "${release}" == "debian" ]]; then
    if [[ ${os_version} -lt 9 ]]; then
        echo -e "${red} Please use Debian 9 or higher ${plain}\n" && exit 1
    fi
elif [[ "${release}" == "centos" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red} Please use CentOS 8 or higher ${plain}\n" && exit 1
    fi
elif [[ "${release}" == "almalinux" ]]; then
    if [[ ${os_version} -lt 80 ]]; then
        echo -e "${red} Please use AlmaLinux 8.0 or higher ${plain}\n" && exit 1
    fi
elif [[ "${release}" == "rocky" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red} Please use Rocky Linux 8 or higher ${plain}\n" && exit 1
    fi
elif [[ "${release}" == "ol" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red} Please use Oracle Linux 8 or higher ${plain}\n" && exit 1
    fi
elif [[ "${release}" == "fedora" ]]; then
    if [[ ${os_version} -lt 36 ]]; then
        echo -e "${red} Please use Fedora 36 or higher version!${plain}\n" && exit 1
    fi
elif [[ "${release}" == "amzn" ]]; then
    if [[ ${os_version} != "2023" ]]; then
        echo -e "${red} Please use Amazon Linux 2023!${plain}\n" && exit 1
    fi
elif [[ "${release}" == "arch" ]]; then
    echo "Your OS is Arch Linux"
elif [[ "${release}" == "parch" ]]; then
    echo "Your OS is Parch Linux"
elif [[ "${release}" == "manjaro" ]]; then
    echo "Your OS is Manjaro"
elif [[ "${release}" == "armbian" ]]; then
    echo "Your OS is Armbian"
elif [[ "${release}" == "alpine" ]]; then
    echo "Your OS is Alpine Linux"
elif [[ "${release}" == "opensuse-tumbleweed" ]]; then
    echo "Your OS is OpenSUSE Tumbleweed"
elif [[ "${release}" == "openEuler" ]]; then
    if [[ ${os_version} -lt 2203 ]]; then
        echo -e "${red} Please use OpenEuler 22.03 or higher ${plain}\n" && exit 1
    fi
else
    echo -e "${red}Your operating system is not supported by this script.${plain}\n"
    echo "Please ensure you are using one of the following supported operating systems:"
    echo "- Ubuntu 18.04+"
    echo "- Debian 9+"
    echo "- CentOS 8+"
    echo "- OpenEuler 22.03+"
    echo "- Fedora 36+"
    echo "- Arch Linux"
    echo "- Parch Linux"
    echo "- Manjaro"
    echo "- Armbian"
    echo "- AlmaLinux 8.0+"
    echo "- Rocky Linux 8+"
    echo "- Oracle Linux 8+"
    echo "- OpenSUSE Tumbleweed"
    echo "- Amazon Linux 2023"
    exit 1
fi

install_base() {
    # Install required packages only (no upgrade)
    # Added dependencies: lsof, unzip, iproute2 (ss), ca-certificates
    case "${release}" in
    ubuntu | debian | armbian)
        DEBIAN_FRONTEND=noninteractive apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q wget curl tar tzdata socat lsof unzip iproute2 ca-certificates
        ;;
    centos | almalinux | rocky | ol)
        # (Optional) switch repo mirror if official unreachable (kept as-is)
        if ! curl -s --connect-timeout 3 http://mirror.centos.org/centos/8/os/x86_64/repodata/repomd.xml >/dev/null; then
            echo -e "${yellow}The official CentOS mirror is unavailable, trying to switch to Tsinghua or Aliyun mirror...${plain}"
            echo -e "${yellow}检测到官方源不可用，尝试切换到清华或阿里云镜像源...${plain}"
            if curl -s --connect-timeout 3 https://mirrors.tuna.tsinghua.edu.cn/centos/8/os/x86_64/repodata/repomd.xml >/dev/null; then
                sed -e 's|^mirrorlist=|#mirrorlist=|g' \
                    -e 's|^#baseurl=http://mirror.centos.org|baseurl=https://mirrors.tuna.tsinghua.edu.cn|g' \
                    -i.bak \
                    /etc/yum.repos.d/CentOS-*.repo
                echo -e "${green}Switched to Tsinghua mirror.${plain}"
                echo -e "${green}已切换到清华镜像源${plain}"
            else
                sed -e 's|^mirrorlist=|#mirrorlist=|g' \
                    -e 's|^#baseurl=http://mirror.centos.org|baseurl=https://mirrors.aliyun.com|g' \
                    -i.bak \
                    /etc/yum.repos.d/CentOS-*.repo
                echo -e "${green}Switched to Aliyun mirror.${plain}"
                echo -e "${green}已切换到阿里云镜像源${plain}"
            fi
            dnf clean all || true
            dnf makecache || true
        fi
        yum install -y wget curl tar socat tzdata lsof unzip iproute ca-certificates
        ;;
    fedora | amzn)
        dnf install -y -q wget curl tar tzdata socat lsof unzip iproute ca-certificates
        ;;
    arch | manjaro | parch)
        pacman -Sy --noconfirm wget curl tar tzdata socat lsof unzip iproute2 ca-certificates
        ;;
    opensuse-tumbleweed)
        zypper -n install wget curl tar timezone socat lsof unzip iproute2 ca-certificates
        ;;
    *)
        # fallback
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q wget curl tar tzdata socat lsof unzip iproute2 ca-certificates
        fi
        ;;
    esac
}

gen_random_string() {
    local length="$1"
    local random_string
    random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)
    echo "$random_string"
}

config_after_install() {
    local existing_username existing_password existing_webBasePath existing_port server_ip
    existing_username=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'username: .+' | awk '{print $2}')
    existing_password=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'password: .+' | awk '{print $2}')
    existing_webBasePath=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    existing_port=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'port: .+' | awk '{print $2}')
    server_ip=$(curl -s https://api.ipify.org)

    # Fix port = 0 / empty
    if [[ -z "$existing_port" || "$existing_port" == "0" ]]; then
        if [[ -f /usr/local/x-ui/data/config.json ]]; then
            existing_port=$(grep -o '"port":[ ]*[0-9]\+' /usr/local/x-ui/data/config.json | head -n1 | grep -o '[0-9]\+')
        fi
        if [[ -z "$existing_port" || "$existing_port" == "0" ]]; then
            existing_port="54321"
        fi
    fi

    local panel_domain=""
    if [[ -f /tmp/xui_panel_domain ]]; then
        panel_domain=$(cat /tmp/xui_panel_domain)
    fi

    if [[ ${#existing_webBasePath} -lt 4 ]]; then
        if [[ "$existing_username" == "admin" && "$existing_password" == "admin" ]]; then
            local config_webBasePath config_username config_password
            config_webBasePath=$(gen_random_string 15)
            config_username=$(gen_random_string 10)
            config_password=$(gen_random_string 10)

            read -p "Would you like to customize the Panel Port settings? (If not, a random port will be applied) [y/n]: " config_confirm
            if [[ "${config_confirm}" == "y" || "${config_confirm}" == "Y" ]]; then
                read -p "Please set up the panel port: " config_port
                echo -e "${yellow}Your Panel Port is: ${config_port}${plain}"
            else
                config_port=$(shuf -i 1024-62000 -n 1)
                echo -e "${yellow}Generated random port: ${config_port}${plain}"
            fi

            /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}" -port "${config_port}" -webBasePath "${config_webBasePath}"
            existing_port="${config_port}"

            {
                echo "###############################################"
                echo -e "${green}Username: ${config_username}${plain}"
                echo -e "${green}Password: ${config_password}${plain}"
                echo -e "${green}Port: ${config_port}${plain}"
                echo -e "${green}WebBasePath: ${config_webBasePath}${plain}"
                if [[ -n "$panel_domain" ]]; then
                    echo -e "${green}Access URL: http://${panel_domain}:${config_port}/${config_webBasePath}${plain}"
                else
                    echo -e "${green}Access URL: http://${server_ip}:${config_port}/${config_webBasePath}${plain}"
                fi
                echo "###############################################"
            } > /tmp/xui_install_info

            echo -e "This is a fresh installation, generating random login info for security concerns:"
            echo -e "###############################################"
            echo -e "${green}Username: ${config_username}${plain}"
            echo -e "${green}Password: ${config_password}${plain}"
            echo -e "${green}Port: ${config_port}${plain}"
            echo -e "${green}WebBasePath: ${config_webBasePath}${plain}"
            if [[ -n "$panel_domain" ]]; then
                echo -e "${green}Access URL: http://${panel_domain}:${config_port}/${config_webBasePath}${plain}"
            else
                echo -e "${green}Access URL: http://${server_ip}:${config_port}/${config_webBasePath}${plain}"
            fi
            echo -e "###############################################"
            echo -e "${yellow}If you forgot your login info, you can type 'x-ui settings' to check${plain}"
        else
            local config_webBasePath
            config_webBasePath=$(gen_random_string 15)
            echo -e "${yellow}WebBasePath is missing or too short. Generating a new one...${plain}"
            /usr/local/x-ui/x-ui setting -webBasePath "${config_webBasePath}"

            {
                echo "###############################################"
                echo -e "${green}WebBasePath: ${config_webBasePath}${plain}"
                if [[ -n "$panel_domain" ]]; then
                    echo -e "${green}Access URL: http://${panel_domain}:${existing_port}/${config_webBasePath}${plain}"
                else
                    echo -e "${green}Access URL: http://${server_ip}:${existing_port}/${config_webBasePath}${plain}"
                fi
                echo "###############################################"
            } > /tmp/xui_install_info
        fi
    else
        if [[ "$existing_username" == "admin" && "$existing_password" == "admin" ]]; then
            local config_username config_password
            config_username=$(gen_random_string 10)
            config_password=$(gen_random_string 10)

            echo -e "${yellow}Default credentials detected. Security update required...${plain}"
            /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}"

            {
                echo "###############################################"
                echo -e "${green}Username: ${config_username}${plain}"
                echo -e "${green}Password: ${config_password}${plain}"
                echo "###############################################"
            } > /tmp/xui_install_info
            echo -e "${yellow}If you forgot your login info, you can type 'x-ui settings' to check${plain}"
        else
            echo -e "${green}Username, Password, and WebBasePath are properly set. Exiting...${plain}"
            {
                echo "###############################################"
                echo -e "${green}Username, Password, and WebBasePath are properly set.${plain}"
                echo "###############################################"
            } > /tmp/xui_install_info
        fi
    fi
    /usr/local/x-ui/x-ui migrate
}

install_x-ui() {
    cd /usr/local/ || exit 1

    if [ $# == 0 ]; then
        tag_version=$(curl -Ls "https://api.github.com/repos/codemkt/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$tag_version" ]]; then
            echo -e "${red}Failed to fetch x-ui version, it may be due to GitHub API restrictions, please try it later${plain}"
            exit 1
        fi
        echo -e "Got x-ui latest version: ${tag_version}, beginning the installation..."
        if command -v wget >/dev/null 2>&1; then
            wget -N --no-check-certificate -O /usr/local/x-ui-linux-$(arch).tar.gz https://github.com/codemkt/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        elif command -v curl >/dev/null 2>&1; then
            curl -Lso /usr/local/x-ui-linux-$(arch).tar.gz https://github.com/codemkt/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        else
            echo -e "${red}Neither wget nor curl is available, please install one of them first.${plain}"
            echo -e "${yellow}你可以手动下载以下链接并上传到 /usr/local/ 目录：${plain}"
            echo "https://github.com/codemkt/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"
            exit 1
        fi
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Downloading x-ui failed, please be sure that your server can access GitHub ${plain}"
            echo -e "${yellow}你可以手动下载以下链接并上传到 /usr/local/ 目录：${plain}"
            echo "https://github.com/codemkt/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"
            exit 1
        fi
    else
        tag_version=$1
        tag_version_numeric=${tag_version#v}
        min_version="2.3.5"

        if [[ "$(printf '%s\n' "$min_version" "$tag_version_numeric" | sort -V | head -n1)" != "$min_version" ]]; then
            echo -e "${red}Please use a newer version (at least v2.3.5). Exiting installation.${plain}"
            exit 1
        fi

        url="https://github.com/codemkt/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"
        echo -e "Beginning to install x-ui $1"
        if command -v wget >/dev/null 2>&1; then
            wget -N --no-check-certificate -O /usr/local/x-ui-linux-$(arch).tar.gz ${url}
        elif command -v curl >/dev/null 2>&1; then
            curl -Lso /usr/local/x-ui-linux-$(arch).tar.gz ${url}
        else
            echo -e "${red}Neither wget nor curl is available, please install one of them first.${plain}"
            echo -e "${yellow}你可以手动下载以下链接并上传到 /usr/local/ 目录：${plain}"
            echo "${url}"
            exit 1
        fi
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Download x-ui $1 failed, please check if the version exists ${plain}"
            echo -e "${yellow}你可以手动下载以下链接并上传到 /usr/local/ 目录：${plain}"
            echo "${url}"
            exit 1
        fi
    fi

    if [[ -e /usr/local/x-ui/ ]]; then
        systemctl stop x-ui 2>/dev/null || true
        rm /usr/local/x-ui/ -rf
    fi

    tar zxvf x-ui-linux-$(arch).tar.gz
    rm x-ui-linux-$(arch).tar.gz -f
    cd x-ui || exit 1
    chmod +x x-ui

    if [[ $(arch) == "armv5" || $(arch) == "armv6" || $(arch) == "armv7" ]]; then
        mv bin/xray-linux-$(arch) bin/xray-linux-arm
        chmod +x bin/xray-linux-arm
    fi

    chmod +x x-ui bin/xray-linux-$(arch)
    cp -f x-ui.service /etc/systemd/system/

    # install management script
    wget --no-check-certificate -O /usr/bin/x-ui https://raw.githubusercontent.com/codemkt/3x-ui/main/x-ui.sh
    chmod +x /usr/bin/x-ui  # FIX: correct path (was /usr/local/x-ui/x-ui.sh)

    config_after_install

    systemctl daemon-reload
    systemctl enable x-ui
    systemctl start x-ui

    echo -e "${green}x-ui ${tag_version}${plain} installation finished, it is running now..."
    echo -e ""
    echo -e "┌───────────────────────────────────────────────────────┐
│  ${blue}x-ui control menu usages (subcommands):${plain}              │
│                                                       │
│  ${blue}x-ui${plain}              - Admin Management Script          │
│  ${blue}x-ui start${plain}        - Start                            │
│  ${blue}x-ui stop${plain}         - Stop                             │
│  ${blue}x-ui restart${plain}      - Restart                          │
│  ${blue}x-ui status${plain}       - Current Status                   │
│  ${blue}x-ui settings${plain}     - Current Settings                 │
│  ${blue}x-ui enable${plain}       - Enable Autostart on OS Startup   │
│  ${blue}x-ui disable${plain}      - Disable Autostart on OS Startup  │
│  ${blue}x-ui log${plain}          - Check logs                       │
│  ${blue}x-ui banlog${plain}       - Check Fail2ban ban logs          │
│  ${blue}x-ui update${plain}       - Update                           │
│  ${blue}x-ui legacy${plain}       - legacy version                   │
│  ${blue}x-ui install${plain}      - Install                          │
│  ${blue}x-ui uninstall${plain}    - Uninstall                        │
└───────────────────────────────────────────────────────┘"

    # Always show login info
    echo -e "${yellow}Current x-ui login information:${plain}"
    if command -v /usr/local/x-ui/x-ui >/dev/null 2>&1; then
        info=$(/usr/local/x-ui/x-ui setting -show true)
        username=$(echo "$info" | grep -Eo 'username: .+' | awk '{print $2}')
        password=$(echo "$info" | grep -Eo 'password: .+' | awk '{print $2}')
        port=$(echo "$info" | grep -Eo 'port: .+' | awk '{print $2}')
        webBasePath=$(echo "$info" | grep -Eo 'webBasePath: .+' | awk '{print $2}')
        server_ip=$(curl -s https://api.ipify.org)
        panel_domain=""
        if [[ -f /tmp/xui_panel_domain ]]; then
            panel_domain=$(cat /tmp/xui_panel_domain)
        fi
        webBasePathClean=$(echo "$webBasePath" | sed 's#^/*##;s#/*$##')
        echo "---------------------------------------------"
        echo -e "${green}Username: ${username}${plain}"
        echo -e "${green}Password: ${password}${plain}"
        echo -e "${green}Port: ${port}${plain}"
        echo -e "${green}WebBasePath: ${webBasePathClean}${plain}"
        echo -e "${green}Access URL: http://${server_ip}:${port}/${webBasePathClean}${plain}"
        echo -e "${green}IP 访问链接（不安全，请使用https://方式！）: http://${server_ip}:${port}/${webBasePathClean}${plain}"
        echo -e "${yellow}It is not safe to access VPN using only IP address. Please use https domain name to increase security. Next, please prepare domain name and email to apply for acme SSL certificate!${plain}"
        if [[ -n "$panel_domain" ]]; then
            echo -e "${green}Access URL: http://${panel_domain}:${port}/${webBasePathClean}${plain}"
        fi
        echo "---------------------------------------------"
    else
        echo -e "${red}x-ui binary not found, cannot show login info.${plain}"
    fi
}

check_firewall_ports() {
    # Open required ports; DO NOT remove/close other existing allow rules.
    local panel_port ssh_port open_ports fw_hint

    panel_port=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'port: .+' | awk '{print $2}')
    [[ -z "$panel_port" ]] && panel_port="54321"

    # Detect SSH port
    ssh_port=$(ss -tnlp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' | head -n1)
    [[ -z "$ssh_port" ]] && ssh_port=22

    # Read trojan port from temp file if present
    if [[ -z "$trojan_port" && -f /tmp/xui_trojan_port ]]; then
        trojan_port=$(cat /tmp/xui_trojan_port 2>/dev/null)
    fi

    open_ports="80 443 $panel_port $ssh_port"
    if [[ -n "$trojan_port" ]]; then
        open_ports="$open_ports $trojan_port"
        echo -e "${green}将开放 Trojan 入站端口: ${trojan_port}${plain}"
        echo -e "${green}Opening Trojan inbound port: ${trojan_port}${plain}"
    fi

    # firewalld
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        for port in $open_ports; do
            firewall-cmd --permanent --add-port=${port}/tcp
        done
        firewall-cmd --reload
        echo -e "${green}已开放端口: ${open_ports}${plain}"
        echo -e "${green}Open ports: ${open_ports}${plain}"
        fw_hint="firewall-cmd --permanent --add-port=端口号(Port Number)/tcp && firewall-cmd --reload"
    elif command -v ufw &>/dev/null; then
        for port in $open_ports; do
            ufw allow $port/tcp
        done
        ufw --force enable
        echo -e "${green}已开放端口: ${open_ports}${plain}"
        echo -e "${green}Open ports: ${open_ports}${plain}"
        fw_hint="ufw allow 端口号(Port Number)/tcp"
    fi

    if [[ -n "$fw_hint" ]]; then
        echo -e "${yellow}如果增加trojan inbound线路，请自行开启对应的防火墙端口！开启命令为：${plain}"
        echo -e "${yellow}${fw_hint}${plain}"
        echo -e "${yellow}If you add a trojan inbound, please open the corresponding firewall port manually! Command:${plain}"
        echo -e "${yellow}${fw_hint}${plain}"
    fi

    # SSH hardening
    sshd_config="/etc/ssh/sshd_config"
    if [[ -f "$sshd_config" ]]; then
        sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 5/' "$sshd_config"
        sed -i 's/^#*MaxSessions.*/MaxSessions 5/' "$sshd_config"
        sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' "$sshd_config"
        grep -q '^MaxAuthTries' "$sshd_config" || echo "MaxAuthTries 5" >> "$sshd_config"
        grep -q '^MaxSessions' "$sshd_config" || echo "MaxSessions 5" >> "$sshd_config"
        grep -q '^LoginGraceTime' "$sshd_config" || echo "LoginGraceTime 60" >> "$sshd_config"
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        echo -e "${green}已配置SSH防护: MaxAuthTries=5, MaxSessions=5, LoginGraceTime=60${plain}"
        echo -e "${green}SSH security configured: MaxAuthTries=5, MaxSessions=5, LoginGraceTime=60${plain}"
    fi

    # Fail2Ban install & enable
    if ! command -v fail2ban-server &>/dev/null; then
        if [[ "${release}" =~ ^(centos|almalinux|rocky|ol)$ ]]; then
            yum install -y epel-release
            yum install -y fail2ban
        elif [[ "${release}" =~ ^(fedora|amzn)$ ]]; then
            dnf install -y fail2ban
        elif [[ "${release}" =~ ^(ubuntu|debian|armbian)$ ]]; then
            apt-get install -y fail2ban
        elif [[ "${release}" =~ ^(arch|manjaro|parch)$ ]]; then
            pacman -Sy --noconfirm fail2ban
        elif [[ "${release}" == "opensuse-tumbleweed" ]]; then
            zypper install -y fail2ban
        fi
        echo -e "${green}Fail2Ban 已安装 (Fail2Ban installed)${plain}"
    fi

    if [[ -f /etc/fail2ban/jail.conf ]]; then
        cp -n /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        jail_local="/etc/fail2ban/jail.local"
        if ! grep -q "^\[sshd\]" "$jail_local"; then
            echo -e "\n[sshd]" >> "$jail_local"
            echo "enabled = true" >> "$jail_local"
            echo "port = ssh" >> "$jail_local"
            echo "filter = sshd" >> "$jail_local"
            if [[ "${release}" =~ ^(centos|almalinux|rocky|ol|fedora|amzn)$ ]]; then
                echo "logpath = /var/log/secure" >> "$jail_local"
            else
                echo "logpath = /var/log/auth.log" >> "$jail_local"
            fi
            echo "maxretry = 5" >> "$jail_local"
            echo "bantime = 3600" >> "$jail_local"
            echo "findtime = 600" >> "$jail_local"
        fi
        systemctl enable fail2ban
        systemctl restart fail2ban
        echo -e "${green}Fail2Ban已配置SSH防护，已启动并设置开机自启。${plain}"
        echo -e "${green}Fail2Ban SSH protection enabled, started and enabled on boot.${plain}"
    fi

    # Auto update & reboot schedule (kept as-is)
    if ! crontab -l 2>/dev/null | grep -q "auto-update"; then
        (crontab -l 2>/dev/null; echo "0 3 * * * if command -v apt-get >/dev/null; then apt-get update && apt-get upgrade -y; elif command -v dnf >/dev/null; then dnf update -y; fi # auto-update") | crontab -
        (crontab -l 2>/dev/null; echo "0 4 * * * if [[ -f /var/run/reboot-required ]]; then /sbin/reboot; elif command -v needs-restarting >/dev/null; then /usr/bin/needs-restarting -r &>/dev/null && /sbin/reboot; fi # auto-reboot-4am") | crontab -
        echo -e "${green}已设置每日凌晨3点自动更新系统,凌晨4点检查并按需重启。${plain}"
        echo -e "${green}Scheduled system update at 3am and reboot check at 4am daily if needed.${plain}"
    fi
}

install_acme() {
    # Ensure cron
    if ! command -v crontab >/dev/null 2>&1; then
        echo -e "${yellow}Installing cron service...${plain}"
        echo -e "${yellow}正在安装 cron 服务...${plain}"
        if [[ "${release}" =~ ^(ubuntu|debian|armbian)$ ]]; then
            apt-get update && apt-get install -y cron
        elif [[ "${release}" =~ ^(centos|almalinux|rocky|ol)$ ]]; then
            yum install -y cronie
        elif [[ "${release}" =~ ^(fedora|amzn)$ ]]; then
            dnf install -y cronie
        elif [[ "${release}" =~ ^(arch|manjaro|parch)$ ]]; then
            pacman -Sy --noconfirm cronie
        elif [[ "${release}" == "opensuse-tumbleweed" ]]; then
            zypper install -y cron
        else
            apt-get install -y cron || yum install -y cronie
        fi

        systemctl enable cron 2>/dev/null || systemctl enable crond 2>/dev/null
        systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null
    fi

    # tar check (warn only)
    if ! command -v tar >/dev/null 2>&1; then
        echo -e "${red}tar not detected, acme.sh and certificate features will not work.${plain}"
        echo -e "${red}未检测到 tar，acme.sh 及证书功能将无法使用。${plain}"
        echo -e "${yellow}Please install tar manually and rerun this script, or refer to the acme.sh official documentation:${plain}"
        echo -e "${yellow}请手动安装 tar 后再运行本脚本，或参考 acme.sh 官方文档：${plain}"
        echo "https://github.com/acmesh-official/acme.sh/wiki/Install-in-China"
    fi

    # Ensure socat
    if ! command -v socat >/dev/null 2>&1; then
        echo -e "${yellow}socat not detected, trying to install socat automatically...${plain}"
        if [[ "${release}" =~ ^(ubuntu|debian|armbian)$ ]]; then
            apt-get update && apt-get install -y socat
        elif [[ "${release}" =~ ^(centos|almalinux|rocky|ol)$ ]]; then
            yum install -y socat
        elif [[ "${release}" =~ ^(fedora|amzn)$ ]]; then
            dnf install -y socat
        elif [[ "${release}" =~ ^(arch|manjaro|parch)$ ]]; then
            pacman -Sy --noconfirm socat
        elif [[ "${release}" == "opensuse-tumbleweed" ]]; then
            zypper install -y socat
        else
            apt-get install -y socat
        fi
    fi

    if ! command -v socat >/dev/null 2>&1; then
        if command -v busybox >/dev/null 2>&1 && busybox | grep -q socat; then
            alias socat='busybox socat'
            echo -e "${yellow}System socat not detected, trying to use busybox socat as a replacement.${plain}"
            echo -e "${yellow}未检测到系统 socat，尝试使用 busybox socat 兼容。${plain}"
        else
            echo -e "${red}socat not detected, acme.sh certificate issuance will not work in standalone mode.${plain}"
            echo -e "${red}未检测到 socat，acme.sh 证书申请将无法使用 standalone 模式。${plain}"
            echo -e "${yellow}Please install socat manually, otherwise certificate issuance will fail.${plain}"
            echo -e "${yellow}请手动安装 socat，否则证书签发会失败。${plain}"
            echo -e "${yellow}If you cannot install socat, you can try DNS mode to apply for a certificate, refer to:${plain}"
            echo -e "${yellow}如无法安装 socat，可尝试 DNS 模式申请证书，参考：https://github.com/acmesh-official/acme.sh/wiki/dnsapi${plain}"
        fi
    fi

    # FIX: don't use command -v with ~; just check file exists
    if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        echo -e "${green}acme.sh is already installed.${plain}"
        echo -e "${green}acme.sh 已安装${plain}"
        return 0
    fi

    echo -e "${yellow}Installing acme.sh...${plain}"
    echo -e "${yellow}正在安装 acme.sh...${plain}"
    curl -s https://get.acme.sh | sh

    if [ $? -ne 0 ] || [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
        echo -e "${red}acme.sh official script installation failed, trying jsdelivr China mirror...${plain}"
        echo -e "${red}acme.sh 官方脚本安装失败，尝试使用 jsdelivr 国内镜像源...${plain}"
        curl -s https://cdn.jsdelivr.net/gh/acmesh-official/acme.sh@master/acme.sh > acme.sh && chmod +x acme.sh
        if [ ! -f acme.sh ]; then
            echo -e "${red}jsdelivr mirror failed, trying fastgit global mirror...${plain}"
            echo -e "${red}jsdelivr 镜失败，尝试使用 fastgit 全球镜像源...${plain}"
            curl -s https://raw.fastgit.org/acmesh-official/acme.sh/master/acme.sh > acme.sh && chmod +x acme.sh
        fi
        if [ -f acme.sh ]; then
            mkdir -p "$HOME/.acme.sh"
            mv acme.sh "$HOME/.acme.sh/"
            ln -sf "$HOME/.acme.sh/acme.sh" /usr/local/bin/acme.sh
            echo -e "${green}acme.sh downloaded via mirror, please initialize manually: ~/.acme.sh/acme.sh --install${plain}"
            echo -e "${green}已通过镜像源下载 acme.sh，请手动初始化：~/.acme.sh/acme.sh --install${plain}"
        else
            echo -e "${red}All acme.sh mirrors failed, please refer to: https://github.com/acmesh-official/acme.sh/wiki/Install-in-China${plain}"
            echo -e "${red}acme.sh 所有镜像源下载均失败，请参考：https://github.com/acmesh-official/acme.sh/wiki/Install-in-China${plain}"
        fi
    fi
    return 0
}

generate_default_site() {
    local domain="$1"
    local site_dir="/var/www/default_site"
    mkdir -p "$site_dir"

    local webzip_url="https://github.com/codemkt/3x-ui/releases/download/v2.6.0/web.zip"
    if curl --head --silent --fail "$webzip_url" >/dev/null; then
        tmpzip="/tmp/web.zip"
        curl -Lso "$tmpzip" "$webzip_url"
        if command -v unzip &>/dev/null; then
            unzip -o "$tmpzip" -d "$site_dir"
        else
            # install unzip if missing
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update && apt-get install -y unzip
            elif command -v yum >/dev/null 2>&1; then
                yum install -y unzip
            fi
            unzip -o "$tmpzip" -d "$site_dir"
        fi
        rm -f "$tmpzip"
    else
        cat >"$site_dir/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to $domain</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>Welcome to $domain</h1>
    <p>This is a default site for camouflage.</p>
</body>
</html>
EOF
    fi
}

install_nginx_with_cert() {
    local domain="$1"
    local cert="$2"
    local key="$3"

    local webBasePath panel_port
    webBasePath=$(/usr/local/x-ui/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    panel_port=$(/usr/local/x-ui/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')

    webBasePath="${webBasePath#/}"
    webBasePath="${webBasePath%/}"

    if ! command -v nginx &>/dev/null; then
        case "${release}" in
        ubuntu | debian | armbian)
            apt update && apt install -y nginx
            ;;
        centos | almalinux | rocky | ol)
            yum install -y nginx
            ;;
        fedora | amzn)
            dnf install -y nginx
            ;;
        arch | manjaro | parch)
            pacman -Sy --noconfirm nginx
            ;;
        *)
            echo -e "${red}Unsupported systems, please install nginx manually.不支持的系统，请手动安装 nginx${plain}"
            return 1
            ;;
        esac
    fi

    generate_default_site "$domain"

    cat >/etc/nginx/conf.d/default_site.conf <<EOF
server {
    listen 80;
    server_name $domain;
    location / {
        root /var/www/default_site;
        index index.html;
    }
}
server {
    listen 443 ssl;
    server_name $domain;
    ssl_certificate     $cert;
    ssl_certificate_key $key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        root /var/www/default_site;
        index index.html;
    }

    location /${webBasePath}/ {
        proxy_pass http://127.0.0.1:${panel_port}/${webBasePath}/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    mkdir -p /var/www/default_site
    systemctl enable nginx
    systemctl restart nginx
}

auto_ssl_and_nginx() {
    echo -e "${yellow}开始配置SSL证书和Nginx... Starting SSL certificate and Nginx configuration...${plain}"

    if [[ ! -f /tmp/xui_panel_domain || ! -f /tmp/xui_panel_email ]]; then
        echo -e "${red}错误: 未找到域名或邮箱配置 Error: Domain or email configuration not found${plain}"
        return 1
    fi

    domain=$(cat /tmp/xui_panel_domain)
    email=$(cat /tmp/xui_panel_email)

    echo -e "${yellow}使用域名 Using domain: ${domain}${plain}"
    echo -e "${yellow}使用邮箱 Using email: ${email}${plain}"

    echo -e "${yellow}开始安装 acme.sh... Installing acme.sh...${plain}"
    install_acme
    if [[ ! -f "$HOME/.acme.sh/acme.sh" ]]; then
        echo -e "${red}acme.sh 安装失败 Installation failed${plain}"
        return 1
    fi
    echo -e "${green}acme.sh 安装成功 Installation successful${plain}"

    # Ensure ports 80/443 free
    for port in 80 443; do
        if lsof -i ":$port" >/dev/null 2>&1; then
            echo -e "${yellow}停止占用端口 ${port} 的服务 Stopping service using port ${port}${plain}"
            systemctl stop nginx 2>/dev/null || true
            systemctl stop apache2 2>/dev/null || true
            systemctl stop httpd 2>/dev/null || true
            sleep 1
        fi
    done

    echo -e "${yellow}开始申请SSL证书 Starting SSL certificate application${plain}"
    "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt
    "$HOME/.acme.sh/acme.sh" --register-account -m "$email" || true
    "$HOME/.acme.sh/acme.sh" --issue -d "$domain" --standalone --force

    if [ $? -ne 0 ]; then
        echo -e "${red}证书申请失败 Certificate application failed${plain}"
        return 1
    fi

    cert_dir="/root/cert/${domain}"
    mkdir -p "$cert_dir"
    "$HOME/.acme.sh/acme.sh" --installcert -d "$domain" \
        --key-file "$cert_dir/privkey.pem" \
        --fullchain-file "$cert_dir/fullchain.pem"

    if [[ -f "$cert_dir/fullchain.pem" && -f "$cert_dir/privkey.pem" ]]; then
        echo -e "${green}证书安装成功 Certificate installation successful${plain}"
        cert_file="$cert_dir/fullchain.pem"
        key_file="$cert_dir/privkey.pem"

        /usr/local/x-ui/x-ui cert -webCert "$cert_file" -webCertKey "$key_file"
        /usr/local/x-ui/x-ui setting -subCertFile "$cert_file" -subKeyFile "$key_file"

        if ! crontab -l 2>/dev/null | grep -q 'acme.sh --cron'; then
            echo -e "${yellow}配置证书自动续期 Configuring certificate auto-renewal${plain}"
            (crontab -l 2>/dev/null; echo "0 2 1 */2 * $HOME/.acme.sh/acme.sh --cron --home $HOME/.acme.sh > /dev/null") | crontab -
            echo -e "${green}已设置证书每2个月自动续期 Certificate auto-renewal scheduled every 2 months${plain}"
        fi

        echo -e "${yellow}开始配置Nginx Starting Nginx configuration${plain}"
        install_nginx_with_cert "$domain" "$cert_file" "$key_file"

        # Auto add trojan inbound
        if [[ -n "$cert_file" && -n "$key_file" ]]; then
            trojan_port=$(shuf -i 10000-60000 -n 1)
            trojan_pass=$(gen_random_string 16)
            remark="Tr_$(date +%y%m%d%H%M%S)$(gen_random_string 2)"
            protocol="trojan"

            trojan_url="trojan://${trojan_pass}@${domain}:${trojan_port}?type=tcp&security=tls&fp=chrome&allowInsecure=0#${remark}"

            echo -e "${yellow}正在添加 Trojan 入站...${plain}"
            add_output=$(/usr/local/x-ui/x-ui setting -AddInbound "$trojan_url" 2>&1)
            add_status=$?
            if [[ $add_status -eq 0 ]]; then
                # Persist trojan info for later steps
                echo "$trojan_port" > /tmp/xui_trojan_port
                echo "$trojan_pass" > /tmp/xui_trojan_pass
                echo "$remark" > /tmp/xui_trojan_remark
                echo "$trojan_url" > /tmp/xui_trojan_url
                echo "$domain" > /tmp/xui_trojan_domain

                echo -e "${green}Trojan 入站已自动添加，信息如下：${plain}"
                echo "---------------------------------------------"
                echo "Remark: $remark"
                echo "Protocol: $protocol"
                echo "Port: $trojan_port"
                echo "Password: $trojan_pass"
                echo "TLS: enabled"
                echo "Certificate: $cert_file"
                echo "Key: $key_file"
                echo "---------------------------------------------"
                echo -e "${green}Trojan 客户端导入链接：${plain}"
                echo "$trojan_url"

                # Open Trojan port
                if command -v firewall-cmd >/dev/null 2>&1; then
                    firewall-cmd --permanent --add-port=${trojan_port}/tcp
                    firewall-cmd --reload
                elif command -v ufw >/dev/null 2>&1; then
                    ufw allow ${trojan_port}/tcp
                fi

                systemctl restart x-ui
            else
                echo -e "${red}Trojan 入站添加失败：${plain}"
                echo "$add_output"
            fi
        fi
    else
        echo -e "${red}证书文件不存在 Certificate files do not exist${plain}"
        return 1
    fi
}

pre_check_input() {
    echo -e "${yellow}开始安装 x-ui 面板 Starting x-ui panel installation${plain}"
    echo "---------------------------------------------"

    domain=""
    email=""
    retry=0
    max_retries=3

    while [[ $retry -lt $max_retries ]]; do
        echo -e "${yellow}请输入用于申请SSL证书的域名 (如 example.com)：${plain}"
        echo -e "${yellow}Please enter the domain name for SSL certificate application (e.g. example.com):${plain}"
        read domain < /dev/tty

        if [[ -z "$domain" ]]; then
            echo -e "${red}域名不能为空 Domain cannot be empty${plain}"
            ((retry++))
            continue
        fi

        if [[ ! $domain =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "${red}域名格式不正确 Invalid domain format${plain}"
            ((retry++))
            continue
        fi

        break
    done

    if [[ $retry -eq $max_retries ]]; then
        echo -e "${red}已达到最大重试次数,退出安装 Maximum retries reached, exiting installation${plain}"
        exit 1
    fi

    retry=0
    while [[ $retry -lt $max_retries ]]; do
        echo -e "${yellow}请输入用于申请SSL证书的邮箱 (如 admin@example.com)：${plain}"
        echo -e "${yellow}Please enter the email for SSL certificate application (e.g. admin@example.com):${plain}"
        read email < /dev/tty

        if [[ -z "$email" ]]; then
            echo -e "${red}邮箱不能为空 Email cannot be empty${plain}"
            ((retry++))
            continue
        fi

        if [[ ! $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "${red}邮箱格式不正确 Invalid email format${plain}"
            ((retry++))
            continue
        fi

        break
    done

    if [[ $retry -eq $max_retries ]]; then
        echo -e "${red}已达到最大重试次数,退出安装 Maximum retries reached, exiting installation${plain}"
        exit 1
    fi

    echo "$domain" > /tmp/xui_panel_domain
    echo "$email" > /tmp/xui_panel_email

    echo -e "${green}域名 Domain: ${domain}${plain}"
    echo -e "${green}邮箱 Email: ${email}${plain}"
    echo "---------------------------------------------"
}

show_installation_info() {
    echo -e "\n${yellow}=== 安装完成 Installation Complete ===${plain}"
    echo -e "\n${green}=== 面板登录信息 Panel Login Info ===${plain}"
    echo -e "---------------------------------------------"
    info=$(/usr/local/x-ui/x-ui setting -show true)
    username=$(echo "$info" | grep -Eo 'username: .+' | awk '{print $2}')
    password=$(echo "$info" | grep -Eo 'password: .+' | awk '{print $2}')
    port=$(echo "$info" | grep -Eo 'port: .+' | awk '{print $2}')
    webBasePath=$(echo "$info" | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    webBasePathClean=$(echo "$webBasePath" | sed 's#^/*##;s#/*$##')
    server_ip=$(curl -s https://api.ipify.org)

    panel_domain=""
    if [[ -f /tmp/xui_panel_domain ]]; then
        panel_domain=$(cat /tmp/xui_panel_domain)
    fi

    echo -e "---------------------------------------------"
    echo -e "${green}用户名 Username: ${username}${plain}"
    echo -e "${green}密码 Password: ${password}${plain}"

    if [[ -n "$panel_domain" ]]; then
        echo -e "\n${green}=== 面板访问链接 Panel Access URLs ===${plain}"
        echo -e "${yellow}请优先使用 HTTPS 链接访问面板 Please use HTTPS URL:${plain}"
        echo -e "${green}https://${panel_domain}:${port}/${webBasePathClean}${plain}"
    else
        echo -e "\n${yellow}未配置域名,当前仅支持IP访问(不安全) No domain configured, only IP access available (Not secure):${plain}"
        echo -e "${red}http://${server_ip}:${port}/${webBasePathClean}${plain}"
    fi
    echo -e "---------------------------------------------"

    # Trojan inbound info (read from temp file)
    if [[ -f /tmp/xui_trojan_port && -f /tmp/xui_trojan_pass && -f /tmp/xui_trojan_url ]]; then
        trojan_port=$(cat /tmp/xui_trojan_port 2>/dev/null)
        trojan_pass=$(cat /tmp/xui_trojan_pass 2>/dev/null)
        remark=$(cat /tmp/xui_trojan_remark 2>/dev/null)
        trojan_url=$(cat /tmp/xui_trojan_url 2>/dev/null)

        echo -e "\n${green}=== Trojan 入站信息 Trojan Inbound Info ===${plain}"
        echo -e "${green}端口 Port: ${trojan_port}${plain}"
        echo -e "${green}密码 Password: ${trojan_pass}${plain}"
        echo -e "${green}备注 Remark: ${remark}${plain}"
        echo -e "\n${yellow}Trojan 一键导入链接 Import URL:${plain}"
        echo -e "${green}${trojan_url}${plain}"
    fi

    echo -e "\n${yellow}=== 安全提示 Security Notes ===${plain}"
    echo -e "${yellow}1. 请立即保存上述信息,此信息仅显示一次!${plain}"
    echo -e "${yellow}1. Please save the above information now, it will only be shown once!${plain}"
    echo -e "${yellow}2. 如需重新查看面板配置,请使用命令:${plain}"
    echo -e "${yellow}2. To view panel settings again, use command:${plain}"
    echo -e "${green}   x-ui settings${plain}"
    echo -e "---------------------------------------------"
}

main() {
    pre_check_input
    install_base
    install_x-ui $1

    echo -e "${yellow}正在配置SSL证书...${plain}"
    echo -e "${yellow}Configuring SSL certificate...${plain}"
    auto_ssl_and_nginx

    check_firewall_ports
    show_installation_info
}

main "$@"
