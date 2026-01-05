#!/bin/bash
# 3X-UI + SSL + Nginx + Trojan + (optional) VLESS/REALITY auto installer
# Based on user's script; enhanced:
# - Time sync & optional timezone set (Asia/Shanghai or keep system default)
# - Generate REALITY x25519 keypair and ShortID
# - Attempt auto-add VLESS+REALITY inbound (best-effort; falls back to printing params)

set -euo pipefail

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
    # Added dependencies: lsof, unzip, iproute2 (ss), ca-certificates, openssl
    case "${release}" in
    ubuntu | debian | armbian)
        DEBIAN_FRONTEND=noninteractive apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q wget curl tar tzdata socat lsof unzip iproute2 ca-certificates openssl
        ;;
    centos | almalinux | rocky | ol)
        if ! curl -s --connect-timeout 3 http://mirror.centos.org/centos/8/os/x86_64/repodata/repomd.xml >/dev/null; then
            echo -e "${yellow}The official CentOS mirror is unavailable, trying to switch mirror...${plain}"
            echo -e "${yellow}检测到官方源不可用，尝试切换镜像源...${plain}"
            if curl -s --connect-timeout 3 https://mirrors.tuna.tsinghua.edu.cn/centos/8/os/x86_64/repodata/repomd.xml >/dev/null; then
                sed -e 's|^mirrorlist=|#mirrorlist=|g' \
                    -e 's|^#baseurl=http://mirror.centos.org|baseurl=https://mirrors.tuna.tsinghua.edu.cn|g' \
                    -i.bak \
                    /etc/yum.repos.d/CentOS-*.repo
                echo -e "${green}Switched to Tsinghua mirror.${plain}"
            else
                sed -e 's|^mirrorlist=|#mirrorlist=|g' \
                    -e 's|^#baseurl=http://mirror.centos.org|baseurl=https://mirrors.aliyun.com|g' \
                    -i.bak \
                    /etc/yum.repos.d/CentOS-*.repo
                echo -e "${green}Switched to Aliyun mirror.${plain}"
            fi
            dnf clean all || true
            dnf makecache || true
        fi
        yum install -y wget curl tar socat tzdata lsof unzip iproute ca-certificates openssl
        ;;
    fedora | amzn)
        dnf install -y -q wget curl tar tzdata socat lsof unzip iproute ca-certificates openssl
        ;;
    arch | manjaro | parch)
        pacman -Sy --noconfirm wget curl tar tzdata socat lsof unzip iproute2 ca-certificates openssl
        ;;
    opensuse-tumbleweed)
        zypper -n install wget curl tar timezone socat lsof unzip iproute2 ca-certificates openssl
        ;;
    *)
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q wget curl tar tzdata socat lsof unzip iproute2 ca-certificates openssl
        fi
        ;;
    esac
}

gen_random_string() {
    local length="$1"
    LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1
}

gen_hex() {
    local bytes="${1:-8}"
    # 8 bytes -> 16 hex chars
    openssl rand -hex "$bytes"
}

# --------- NEW: time sync & timezone ----------
sync_time_and_tz() {
    echo -e "${yellow}=== Time sync & timezone (时间同步与时区) ===${plain}"
    echo -e "${yellow}说明：你可以把服务器时区设置为 Asia/Shanghai（即使是国外服务器也可以）——这只影响“显示/日志时间”，不会改变实际 UTC 时间基准；NTP 同步会保持时间准确。${plain}"
    echo -e "${yellow}Note: Setting timezone to Asia/Shanghai is OK even for overseas servers; it only affects displayed local time/logs. NTP keeps clock accurate.${plain}"

    local tz_choice=""

    # default: keep current timezone
    echo -e "${yellow}Choose timezone option:${plain}"
    echo -e "${yellow}[1] Keep current timezone (recommended if you want local server time)${plain}"
    echo -e "${yellow}[2] Set timezone to Asia/Shanghai (recommended if you operate in China time)${plain}"
    read -p "Select [1/2] (default 2): " tz_choice </dev/tty || true
    [[ -z "$tz_choice" ]] && tz_choice="2"

    if command -v timedatectl >/dev/null 2>&1; then
        if [[ "$tz_choice" == "2" ]]; then
            timedatectl set-timezone Asia/Shanghai || true
        fi
        timedatectl set-ntp true || true
    else
        # fallback
        if [[ "$tz_choice" == "2" ]]; then
            ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime || true
        fi
    fi

    # Ensure an NTP service is present (best effort, no heavy upgrades)
    if ! (systemctl is-active --quiet systemd-timesyncd 2>/dev/null || systemctl is-active --quiet chrony 2>/dev/null || systemctl is-active --quiet chronyd 2>/dev/null || systemctl is-active --quiet ntp 2>/dev/null); then
        echo -e "${yellow}No active NTP service detected. Trying to install chrony...${plain}"
        case "${release}" in
        ubuntu | debian | armbian)
            apt-get update -y
            apt-get install -y -q chrony || true
            systemctl enable chrony 2>/dev/null || true
            systemctl restart chrony 2>/dev/null || true
            ;;
        centos | almalinux | rocky | ol | fedora | amzn)
            (yum install -y chrony || dnf install -y chrony) || true
            systemctl enable chronyd 2>/dev/null || true
            systemctl restart chronyd 2>/dev/null || true
            ;;
        arch | manjaro | parch)
            pacman -Sy --noconfirm chrony || true
            systemctl enable chronyd 2>/dev/null || true
            systemctl restart chronyd 2>/dev/null || true
            ;;
        opensuse-tumbleweed)
            zypper -n install chrony || true
            systemctl enable chronyd 2>/dev/null || true
            systemctl restart chronyd 2>/dev/null || true
            ;;
        *)
            ;;
        esac
    fi

    echo -e "${green}Current time status:${plain}"
    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl status | sed -n '1,15p' || true
    else
        date || true
    fi
}

# --------- NEW: reality keypair generation ----------
gen_reality_keypair() {
    local xray_bin=""
    # candidates (3x-ui bundles xray in bin/)
    local cand1="/usr/local/x-ui/bin/xray-linux-$(arch)"
    local cand2="/usr/local/x-ui/bin/xray"
    local cand3="/usr/local/x-ui/xray"
    local cand4="$(command -v xray || true)"

    for c in "$cand1" "$cand2" "$cand3" "$cand4"; do
        if [[ -n "$c" && -x "$c" ]]; then
            xray_bin="$c"
            break
        fi
    done

    if [[ -z "$xray_bin" ]]; then
        echo -e "${red}Xray binary not found; cannot auto-generate REALITY keys.${plain}"
        return 1
    fi

    # Xray: `xray x25519`
    local out
    out=$("$xray_bin" x25519 2>/dev/null || true)

    local priv pub
    priv=$(echo "$out" | grep -i "Private key" | awk -F: '{print $2}' | xargs || true)
    pub=$(echo "$out" | grep -i "Public key"  | awk -F: '{print $2}' | xargs || true)

    if [[ -z "$priv" || -z "$pub" ]]; then
        echo -e "${red}Failed to parse x25519 output. Output was:${plain}\n$out"
        return 1
    fi

    echo "$priv|$pub"
    return 0
}

config_after_install() {
    local existing_username existing_password existing_webBasePath existing_port server_ip
    existing_username=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'username: .+' | awk '{print $2}' || true)
    existing_password=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'password: .+' | awk '{print $2}' || true)
    existing_webBasePath=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'webBasePath: .+' | awk '{print $2}' || true)
    existing_port=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'port: .+' | awk '{print $2}' || true)
    server_ip=$(curl -s https://api.ipify.org || echo "YOUR_SERVER_IP")

    # Fix port = 0 / empty
    if [[ -z "$existing_port" || "$existing_port" == "0" ]]; then
        if [[ -f /usr/local/x-ui/data/config.json ]]; then
            existing_port=$(grep -o '"port":[ ]*[0-9]\+' /usr/local/x-ui/data/config.json | head -n1 | grep -o '[0-9]\+' || true)
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

            read -p "Would you like to customize the Panel Port settings? (If not, a random port will be applied) [y/n]: " config_confirm </dev/tty || true
            if [[ "${config_confirm}" == "y" || "${config_confirm}" == "Y" ]]; then
                read -p "Please set up the panel port: " config_port </dev/tty
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

            echo -e "Fresh installation: generated random login info:"
            cat /tmp/xui_install_info
            echo -e "${yellow}If you forgot your login info, type: x-ui settings${plain}"
        else
            local config_webBasePath
            config_webBasePath=$(gen_random_string 15)
            echo -e "${yellow}WebBasePath is missing/short. Generating a new one...${plain}"
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

            echo -e "${yellow}Default credentials detected. Updating...${plain}"
            /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}"

            {
                echo "###############################################"
                echo -e "${green}Username: ${config_username}${plain}"
                echo -e "${green}Password: ${config_password}${plain}"
                echo "###############################################"
            } > /tmp/xui_install_info
            echo -e "${yellow}If you forgot your login info, type: x-ui settings${plain}"
        else
            echo -e "${green}Username/Password/WebBasePath OK. Skipping credential update.${plain}"
            {
                echo "###############################################"
                echo -e "${green}Username, Password, and WebBasePath are properly set.${plain}"
                echo "###############################################"
            } > /tmp/xui_install_info
        fi
    fi
    /usr/local/x-ui/x-ui migrate || true
}

install_x-ui() {
    cd /usr/local/ || exit 1

    if [ $# == 0 ]; then
        tag_version=$(curl -Ls "https://api.github.com/repos/codemkt/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$tag_version" ]]; then
            echo -e "${red}Failed to fetch x-ui version (GitHub API). Try later.${plain}"
            exit 1
        fi
        echo -e "Got 3x-ui latest version: ${tag_version}, beginning installation..."
        if command -v wget >/dev/null 2>&1; then
            wget -N --no-check-certificate -O /usr/local/x-ui-linux-$(arch).tar.gz https://github.com/codemkt/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        elif command -v curl >/dev/null 2>&1; then
            curl -Lso /usr/local/x-ui-linux-$(arch).tar.gz https://github.com/codemkt/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        else
            echo -e "${red}Neither wget nor curl available.${plain}"
            exit 1
        fi
    else
        tag_version=$1
        url="https://github.com/codemkt/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"
        echo -e "Beginning to install 3x-ui $1"
        if command -v wget >/dev/null 2>&1; then
            wget -N --no-check-certificate -O /usr/local/x-ui-linux-$(arch).tar.gz ${url}
        elif command -v curl >/dev/null 2>&1; then
            curl -Lso /usr/local/x-ui-linux-$(arch).tar.gz ${url}
        else
            echo -e "${red}Neither wget nor curl available.${plain}"
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

    chmod +x x-ui bin/xray-linux-$(arch) 2>/dev/null || true
    cp -f x-ui.service /etc/systemd/system/

    # install management script
    wget --no-check-certificate -O /usr/bin/x-ui https://raw.githubusercontent.com/codemkt/3x-ui/main/x-ui.sh
    chmod +x /usr/bin/x-ui

    config_after_install

    systemctl daemon-reload
    systemctl enable x-ui
    systemctl start x-ui

    echo -e "${green}3x-ui ${tag_version}${plain} installation finished, running now..."
}

# --------- NEW: best-effort auto-add VLESS+REALITY inbound ----------
auto_add_reality_inbound() {
    echo -e "${yellow}=== Optional: Auto add VLESS + REALITY inbound (可选：自动添加 VLESS+REALITY 入站) ===${plain}"

    local enable=""
    read -p "Auto add VLESS+REALITY inbound now? [y/N]: " enable </dev/tty || true
    enable="${enable:-N}"
    if [[ "$enable" != "y" && "$enable" != "Y" ]]; then
        echo -e "${yellow}Skip auto-add REALITY inbound.${plain}"
        return 0
    fi

    local domain=""
    if [[ -f /tmp/xui_panel_domain ]]; then
        domain=$(cat /tmp/xui_panel_domain)
    fi
    if [[ -z "$domain" ]]; then
        echo -e "${red}Domain not found (/tmp/xui_panel_domain). Cannot build VLESS URL. You can still add inbound in panel manually.${plain}"
        return 1
    fi

    local uuid remark listen_port sni dest fp sid
    uuid=$(cat /proc/sys/kernel/random/uuid)
    remark="VR_$(date +%y%m%d%H%M%S)$(gen_random_string 2)"
    listen_port="443"
    sni="www.cloudflare.com"
    dest="${sni}:443"
    fp="chrome"
    sid="$(gen_hex 8)"  # 16 hex chars

    local kp
    if ! kp="$(gen_reality_keypair)"; then
        echo -e "${red}Cannot generate REALITY keypair automatically. Add inbound manually in 3x-ui panel.${plain}"
        return 1
    fi
    local private_key public_key
    private_key="${kp%%|*}"
    public_key="${kp##*|}"

    # Save params for later display
    echo "$uuid" > /tmp/xui_vless_uuid
    echo "$remark" > /tmp/xui_vless_remark
    echo "$listen_port" > /tmp/xui_vless_port
    echo "$sni" > /tmp/xui_reality_sni
    echo "$dest" > /tmp/xui_reality_dest
    echo "$fp" > /tmp/xui_reality_fp
    echo "$sid" > /tmp/xui_reality_sid
    echo "$private_key" > /tmp/xui_reality_private
    echo "$public_key" > /tmp/xui_reality_public

    # Build standard VLESS REALITY import URL (client side)
    local vless_url
    vless_url="vless://${uuid}@${domain}:${listen_port}?type=tcp&security=reality&encryption=none&fp=${fp}&sni=${sni}&pbk=${public_key}&sid=${sid}#${remark}"
  echo "$vless_url" > /tmp/xui_vless_url
    echo "$vless_url" > /tmp/xui_vless_url

    echo -e "${green}Generated REALITY parameters:${plain}"
    echo "---------------------------------------------"
    echo "UUID:        $uuid"
    echo "Port:        $listen_port"
    echo "SNI:         $sni"
    echo "Dest:        $dest"
    echo "FP:          $fp"
    echo "ShortID:     $sid"
    echo "PrivateKey:  $private_key"
    echo "PublicKey:   $public_key"
    echo "Remark:      $remark"
    echo "VLESS URL:   $vless_url"
    echo "---------------------------------------------"

    # Best-effort: try x-ui cli AddInbound with the URL (may or may not support REALITY on your 3x-ui build)
    echo -e "${yellow}Trying to add inbound via CLI (best effort)...${plain}"
    set +e
    add_output=$(/usr/local/x-ui/x-ui setting -AddInbound "$vless_url" 2>&1)
    add_status=$?
    set -e
    if [[ $add_status -eq 0 ]]; then
        echo -e "${green}VLESS+REALITY inbound added via CLI successfully.${plain}"
        # Ensure port open
        if command -v firewall-cmd >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port=${listen_port}/tcp
            firewall-cmd --reload
        elif command -v ufw >/dev/null 2>&1; then
            ufw allow ${listen_port}/tcp || true
        fi
        systemctl restart x-ui || true
        return 0
    fi

    echo -e "${yellow}CLI auto-add did not succeed on this build (this is normal on some 3x-ui versions).${plain}"
    echo -e "${yellow}You can add it manually in the panel using the generated params above, or simply import the VLESS URL into client and then create inbound in panel as needed.${plain}"
    echo -e "${yellow}CLI output:${plain}\n$add_output"
    return 0
}

# -------------- Your existing functions below (kept with minimal changes) --------------

install_acme() {
    if ! command -v crontab >/dev/null 2>&1; then
        echo -e "${yellow}Installing cron service...${plain}"
        if [[ "${release}" =~ ^(ubuntu|debian|armbian)$ ]]; then
            apt-get update && apt-get install -y cron
        elif [[ "${release}" =~ ^(centos|almalinux|rocky|ol)$ ]]; then
            yum install -y cronie
        elif [[ "${release}" =~ ^(fedora|amzn)$ ]]; then
            dnf install -y cronie
        elif [[ "${release}" =~ ^(arch|manjaro|parch)$ ]]; then
            pacman -Sy --noconfirm cronie
        elif [[ "${release}" == "opensuse-tumbleweed" ]]; then
            zypper -n install cron
        else
            apt-get install -y cron || yum install -y cronie
        fi
        systemctl enable cron 2>/dev/null || systemctl enable crond 2>/dev/null
        systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null
    fi

    if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        echo -e "${green}acme.sh is already installed.${plain}"
        return 0
    fi

    echo -e "${yellow}Installing acme.sh...${plain}"
    curl -s https://get.acme.sh | sh || true

    if [[ ! -f "$HOME/.acme.sh/acme.sh" ]]; then
        echo -e "${red}acme.sh installation failed. Please install manually.${plain}"
        return 1
    fi
    return 0
}

generate_default_site() {
    local domain="$1"
    local site_dir="/var/www/default_site"
    mkdir -p "$site_dir"

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
            apt-get update && apt-get install -y nginx
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
            echo -e "${red}Unsupported system for nginx auto-install. Please install nginx manually.${plain}"
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
    echo -e "${yellow}开始配置SSL证书和Nginx...${plain}"

    if [[ ! -f /tmp/xui_panel_domain || ! -f /tmp/xui_panel_email ]]; then
        echo -e "${red}错误: 未找到域名或邮箱配置${plain}"
        return 1
    fi

    domain=$(cat /tmp/xui_panel_domain)
    email=$(cat /tmp/xui_panel_email)

    install_acme || true
    if [[ ! -f "$HOME/.acme.sh/acme.sh" ]]; then
        echo -e "${red}acme.sh 安装失败${plain}"
        return 1
    fi

    for port in 80 443; do
        if lsof -i ":$port" >/dev/null 2>&1; then
            systemctl stop nginx 2>/dev/null || true
            systemctl stop apache2 2>/dev/null || true
            systemctl stop httpd 2>/dev/null || true
            sleep 1
        fi
    done

    "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt || true
    "$HOME/.acme.sh/acme.sh" --register-account -m "$email" || true
    "$HOME/.acme.sh/acme.sh" --issue -d "$domain" --standalone --force

    if [[ $? -ne 0 ]]; then
        echo -e "${red}证书申请失败${plain}"
        return 1
    fi

    cert_dir="/root/cert/${domain}"
    mkdir -p "$cert_dir"
    "$HOME/.acme.sh/acme.sh" --installcert -d "$domain" \
        --key-file "$cert_dir/privkey.pem" \
        --fullchain-file "$cert_dir/fullchain.pem"

    if [[ -f "$cert_dir/fullchain.pem" && -f "$cert_dir/privkey.pem" ]]; then
        cert_file="$cert_dir/fullchain.pem"
        key_file="$cert_dir/privkey.pem"

        /usr/local/x-ui/x-ui cert -webCert "$cert_file" -webCertKey "$key_file" || true
# Compatibility: some 3x-ui builds do NOT support -subCertFile/-subKeyFile (it would exit the script under set -e).
if /usr/local/x-ui/x-ui setting -h 2>&1 | grep -q -- "-subCertFile"; then
    /usr/local/x-ui/x-ui setting -subCertFile "$cert_file" -subKeyFile "$key_file" || true
else
    echo -e "${yellow}[WARN] 当前 3x-ui 不支持 -subCertFile/-subKeyFile，已跳过该步骤（不影响面板 HTTPS）。${plain}"
fi

        if ! crontab -l 2>/dev/null | grep -q 'acme.sh --cron'; then
            (crontab -l 2>/dev/null; echo "0 2 1 */2 * $HOME/.acme.sh/acme.sh --cron --home $HOME/.acme.sh > /dev/null") | crontab -
        fi

        install_nginx_with_cert "$domain" "$cert_file" "$key_file"
    else
        echo -e "${red}证书文件不存在${plain}"
        return 1
    fi
}

check_firewall_ports() {
    local panel_port ssh_port open_ports

    panel_port=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'port: .+' | awk '{print $2}' || true)
    [[ -z "$panel_port" ]] && panel_port="54321"

    ssh_port=$(ss -tnlp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' | head -n1 || true)
    [[ -z "$ssh_port" ]] && ssh_port=22

    open_ports="80 443 $panel_port $ssh_port"

    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        for port in $open_ports; do
            firewall-cmd --permanent --add-port=${port}/tcp || true
        done
        firewall-cmd --reload || true
    elif command -v ufw &>/dev/null; then
        for port in $open_ports; do
            ufw allow $port/tcp || true
        done
        ufw --force enable || true
    fi
}

pre_check_input() {
    echo -e "${yellow}开始安装 3x-ui 面板...${plain}"
    echo "---------------------------------------------"

    domain=""
    email=""
    retry=0
    max_retries=3

    while [[ $retry -lt $max_retries ]]; do
        echo -e "${yellow}请输入用于申请SSL证书的域名 (如 example.com)：${plain}"
        read domain < /dev/tty

        if [[ -z "$domain" ]]; then
            echo -e "${red}域名不能为空${plain}"
            ((retry++))
            continue
        fi

        if [[ ! $domain =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "${red}域名格式不正确${plain}"
            ((retry++))
            continue
        fi
        break
    done

    if [[ $retry -eq $max_retries ]]; then
        echo -e "${red}已达到最大重试次数,退出安装${plain}"
        exit 1
    fi

    retry=0
    while [[ $retry -lt $max_retries ]]; do
        echo -e "${yellow}请输入用于申请SSL证书的邮箱 (如 admin@example.com)：${plain}"
        read email < /dev/tty

        if [[ -z "$email" ]]; then
            echo -e "${red}邮箱不能为空${plain}"
            ((retry++))
            continue
        fi

        if [[ ! $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "${red}邮箱格式不正确${plain}"
            ((retry++))
            continue
        fi
        break
    done

    if [[ $retry -eq $max_retries ]]; then
        echo -e "${red}已达到最大重试次数,退出安装${plain}"
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

    info=$(/usr/local/x-ui/x-ui setting -show true || true)
    username=$(echo "$info" | grep -Eo 'username: .+' | awk '{print $2}' || true)
    password=$(echo "$info" | grep -Eo 'password: .+' | awk '{print $2}' || true)
    port=$(echo "$info" | grep -Eo 'port: .+' | awk '{print $2}' || true)
    webBasePath=$(echo "$info" | grep -Eo 'webBasePath: .+' | awk '{print $2}' || true)
    webBasePathClean=$(echo "$webBasePath" | sed 's#^/*##;s#/*$##')
    server_ip=$(curl -s https://api.ipify.org || echo "YOUR_SERVER_IP")
    panel_domain=$(cat /tmp/xui_panel_domain 2>/dev/null || true)

    echo -e "\n${green}=== 面板登录信息 Panel Login Info ===${plain}"
    echo -e "${green}用户名 Username: ${username}${plain}"
    echo -e "${green}密码 Password: ${password}${plain}"
    echo -e "${green}Port: ${port}${plain}"
    echo -e "${green}WebBasePath: ${webBasePathClean}${plain}"

    if [[ -n "$panel_domain" ]]; then
        echo -e "${yellow}Panel URL (HTTPS):${plain}"
        echo -e "${green}https://${panel_domain}:${port}/${webBasePathClean}${plain}"
    else
        echo -e "${yellow}Panel URL (HTTP, not secure):${plain}"
        echo -e "${green}http://${server_ip}:${port}/${webBasePathClean}${plain}"
    fi

    if [[ -f /tmp/xui_vless_url ]]; then
        echo -e "\n${green}=== VLESS + REALITY (Client Import) ===${plain}"
        echo -e "${yellow}VLESS 一键导入链接：${plain}"
        cat /tmp/xui_vless_url
    fi

    echo -e "\n${yellow}提示：若需再次查看面板设置：x-ui settings${plain}"
}

main() {
    pre_check_input
    install_base

    # NEW: time sync earlier to reduce ACME / TLS / log drift issues
    sync_time_and_tz

    install_x-ui "${1:-}"

    echo -e "${yellow}正在配置SSL证书...${plain}"
    auto_ssl_and_nginx || true

    # NEW: optional reality inbound
    auto_add_reality_inbound || true

    check_firewall_ports
    show_installation_info
}

main "$@"
