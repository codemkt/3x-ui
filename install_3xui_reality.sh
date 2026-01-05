#!/bin/bash
# 3x-ui + SSL (acme standalone) + Nginx(ONLY 80) + (optional) VLESS/REALITY on 443
# Goals:
# - REALITY uses 443 (no nginx on 443)
# - Panel uses HTTPS on 8443 when REALITY enabled (recommended)
# - If REALITY enabled, ALWAYS generate client import link + params (even if not auto-add inbound)
# - Fix GitHub tag fetch empty -> 404
# - Keep installs lightweight; avoid full system upgrade

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
    *) echo -e "${green}Unsupported CPU architecture! ${plain}" && exit 1 ;;
    esac
}
echo "arch: $(arch)"

os_version=""
os_version=$(grep "^VERSION_ID" /etc/os-release | cut -d '=' -f2 | tr -d '"' | tr -d '.')

# OS version guard
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
elif [[ "${release}" == "arch" || "${release}" == "parch" || "${release}" == "manjaro" || "${release}" == "armbian" || "${release}" == "alpine" || "${release}" == "opensuse-tumbleweed" || "${release}" == "openEuler" ]]; then
    :
else
    echo -e "${red}Your operating system is not supported by this script.${plain}\n"
    exit 1
fi

install_base() {
    # Install required packages only (no upgrade)
    case "${release}" in
    ubuntu | debian | armbian)
        DEBIAN_FRONTEND=noninteractive apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q wget curl tar tzdata socat lsof unzip iproute2 ca-certificates openssl dnsutils
        ;;
    centos | almalinux | rocky | ol)
        yum install -y wget curl tar socat tzdata lsof unzip iproute ca-certificates openssl bind-utils
        ;;
    fedora | amzn)
        dnf install -y -q wget curl tar tzdata socat lsof unzip iproute ca-certificates openssl bind-utils
        ;;
    arch | manjaro | parch)
        pacman -Sy --noconfirm wget curl tar tzdata socat lsof unzip iproute2 ca-certificates openssl bind
        ;;
    opensuse-tumbleweed)
        zypper -n install wget curl tar timezone socat lsof unzip iproute2 ca-certificates openssl bind-utils
        ;;
    *)
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q wget curl tar tzdata socat lsof unzip iproute2 ca-certificates openssl dnsutils
        fi
        ;;
    esac
}

gen_random_string() {
    local length="$1"
    LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1
}

gen_hex() {
    local bytes="${1:-8}"  # 8 bytes -> 16 hex chars
    openssl rand -hex "$bytes"
}

get_public_ip() {
    curl -fsSL --connect-timeout 6 --max-time 10 https://api.ipify.org 2>/dev/null || true
}

dns_check() {
    local domain="$1"
    echo -e "${yellow}=== DNS 解析检查 (DNS check) ===${plain}"
    local myip=""
    myip="$(get_public_ip)"
    if [[ -z "$myip" ]]; then
        echo -e "${yellow}[WARN] 无法获取本机公网 IP（api.ipify.org 失败）。仍将继续，但申请证书可能失败。${plain}"
    else
        echo -e "${green}本机公网 IP: ${myip}${plain}"
    fi

    local resolved=""
    # prefer dig
    if command -v dig >/dev/null 2>&1; then
        resolved="$(dig +short A "$domain" | head -n1 || true)"
        if [[ -z "$resolved" ]]; then
            resolved="$(dig +short AAAA "$domain" | head -n1 || true)"
        fi
    elif command -v nslookup >/dev/null 2>&1; then
        resolved="$(nslookup "$domain" 2>/dev/null | awk '/^Address: /{print $2}' | tail -n1 || true)"
    fi

    echo -e "${green}域名: ${domain}${plain}"
    echo -e "${green}解析到的 IP: ${resolved:-<empty>}${plain}"
    echo -e "${yellow}说明：申请证书(standalone)要求域名 A/AAAA 记录解析到当前服务器公网 IP，并且 80 端口可从公网访问。${plain}"

    if [[ -z "$resolved" ]]; then
        echo -e "${red}[WARN] 未解析到任何 A/AAAA 记录（resolved=<empty>）。${plain}"
        echo -e "${yellow}这通常表示 DNS 还未生效/未设置记录，申请证书大概率失败。建议先在 DNS 控制台添加 A/AAAA 并等待生效。${plain}"
    elif [[ -n "$myip" && "$resolved" != "$myip" ]]; then
        echo -e "${red}[WARN] 解析 IP 与本机公网 IP 不一致：${resolved} != ${myip}${plain}"
        echo -e "${yellow}继续安装不会阻止，但证书申请大概率失败。请先修正 DNS A/AAAA 记录。${plain}"
    else
        echo -e "${green}DNS 看起来已正确解析到当前服务器（或无法验证公网 IP）。${plain}"
    fi
}

sync_time_and_tz() {
    echo -e "${yellow}=== 时区设置 (最后一步输入) ===${plain}"
    echo -e "${yellow}[1] 保持当前时区${plain}"
    echo -e "${yellow}[2] 设置为 Asia/Shanghai${plain}"
    local tz_choice=""
    read -p "选择 [1/2] (默认 2): " tz_choice </dev/tty || true
    [[ -z "$tz_choice" ]] && tz_choice="2"

    if command -v timedatectl >/dev/null 2>&1; then
        if [[ "$tz_choice" == "2" ]]; then
            timedatectl set-timezone Asia/Shanghai || true
        fi
        timedatectl set-ntp true || true
    else
        if [[ "$tz_choice" == "2" ]]; then
            ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime || true
        fi
    fi

    echo -e "${yellow}=== 时间同步与时区 ===${plain}"
    echo -e "${yellow}说明：时区只影响显示/日志时间；NTP 同步保证系统时间准确。${plain}"
    echo -e "${yellow}当前时间状态：${plain}"
    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl status | sed -n '1,15p' || true
    else
        date || true
    fi
}

# --------- REALITY keypair generation ----------
gen_reality_keypair() {
    local xray_bin=""
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

    local out priv pub
    out=$("$xray_bin" x25519 2>/dev/null || true)
    priv=$(echo "$out" | grep -i "Private key" | awk -F: '{print $2}' | xargs || true)
    pub=$(echo "$out"  | grep -i "Public key"  | awk -F: '{print $2}' | xargs || true)

    if [[ -z "$priv" || -z "$pub" ]]; then
        echo -e "${red}Failed to parse x25519 output. Output was:${plain}\n$out"
        return 1
    fi
    echo "$priv|$pub"
}

xui_setting_show() {
    /usr/local/x-ui/x-ui setting -show true 2>/dev/null || true
}

xui_get_value() {
    local key="$1"
    xui_setting_show | grep -Eo "${key}: .+" | awk '{print $2}' | head -n1 || true
}

config_after_install() {
    local existing_username existing_password existing_webBasePath existing_port server_ip
    existing_username=$(xui_get_value "username")
    existing_password=$(xui_get_value "password")
    existing_webBasePath=$(xui_get_value "webBasePath")
    existing_port=$(xui_get_value "port")
    server_ip=$(get_public_ip); [[ -z "$server_ip" ]] && server_ip="YOUR_SERVER_IP"

    # Fix port = 0 / empty
    if [[ -z "$existing_port" || "$existing_port" == "0" ]]; then
        if [[ -f /usr/local/x-ui/data/config.json ]]; then
            existing_port=$(grep -o '"port":[ ]*[0-9]\+' /usr/local/x-ui/data/config.json | head -n1 | grep -o '[0-9]\+' || true)
        fi
        [[ -z "$existing_port" || "$existing_port" == "0" ]] && existing_port="54321"
    fi

    local enable_reality="N"
    if [[ -f /tmp/xui_enable_reality ]]; then
        enable_reality="$(cat /tmp/xui_enable_reality || echo N)"
    fi

    # If REALITY enabled, recommend panel 8443 (avoid random port)
    if [[ "$enable_reality" == "y" || "$enable_reality" == "Y" ]]; then
        /usr/local/x-ui/x-ui setting -port 8443 >/dev/null 2>&1 || true
        existing_port="8443"
    fi

    local panel_domain=""
    [[ -f /tmp/xui_panel_domain ]] && panel_domain="$(cat /tmp/xui_panel_domain)"

    # If webBasePath short/missing, generate; if default creds, rotate
    if [[ ${#existing_webBasePath} -lt 4 ]]; then
        local new_webBasePath new_username new_password
        new_webBasePath=$(gen_random_string 15)
        /usr/local/x-ui/x-ui setting -webBasePath "${new_webBasePath}" >/dev/null 2>&1 || true
        existing_webBasePath="$new_webBasePath"
    fi

    if [[ "$existing_username" == "admin" && "$existing_password" == "admin" ]]; then
        local newu newp
        newu=$(gen_random_string 10)
        newp=$(gen_random_string 12)
        /usr/local/x-ui/x-ui setting -username "$newu" -password "$newp" >/dev/null 2>&1 || true
        existing_username="$newu"
        existing_password="$newp"
    fi

    local webBasePathClean
    webBasePathClean="$(echo "$existing_webBasePath" | sed 's#^/*##;s#/*$##')"

    {
        echo "###############################################"
        echo -e "${green}Username: ${existing_username}${plain}"
        echo -e "${green}Password: ${existing_password}${plain}"
        echo -e "${green}Port: ${existing_port}${plain}"
        echo -e "${green}WebBasePath: ${webBasePathClean}${plain}"
        if [[ -n "$panel_domain" ]]; then
            echo -e "${green}Panel URL: https://${panel_domain}:${existing_port}/${webBasePathClean}${plain}"
        else
            echo -e "${green}Panel URL: http://${server_ip}:${existing_port}/${webBasePathClean}${plain}"
        fi
        echo "###############################################"
    } > /tmp/xui_install_info

    /usr/local/x-ui/x-ui migrate >/dev/null 2>&1 || true
}

install_x-ui() {
    cd /usr/local/ || exit 1

    local tag_version=""
    if [[ $# -eq 0 || -z "${1:-}" ]]; then
        tag_version="$(curl -fsSL --connect-timeout 8 --max-time 20 "https://api.github.com/repos/codemkt/3x-ui/releases/latest" \
          | grep -m1 '"tag_name":' \
          | sed -E 's/.*"tag_name":[ ]*"([^"]+)".*/\1/' \
          | tr -d '\r' \
          | xargs || true)"
        if [[ -z "${tag_version}" ]]; then
          tag_version="$(curl -fsSL --connect-timeout 8 --max-time 20 "https://api.github.com/repos/codemkt/3x-ui/releases?per_page=1" \
            | grep -m1 '"tag_name":' \
            | sed -E 's/.*"tag_name":[ ]*"([^"]+)".*/\1/' \
            | tr -d '\r' \
            | xargs || true)"
        fi
        if [[ -z "${tag_version}" ]]; then
          tag_version="v2.6.0"
          echo -e "${yellow}[WARN] GitHub API 未取到版本号，已回退到 ${tag_version}。${plain}"
        else
          echo -e "Got 3x-ui latest version: ${tag_version}, beginning installation..."
        fi
    else
        tag_version="$1"
        tag_version="$(echo "$tag_version" | tr -d '\r' | xargs)"
        echo -e "Beginning to install 3x-ui ${tag_version}"
    fi

    local url="https://github.com/codemkt/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"

    if command -v wget >/dev/null 2>&1; then
        wget -N --no-check-certificate -O "/usr/local/x-ui-linux-$(arch).tar.gz" "${url}"
    elif command -v curl >/dev/null 2>&1; then
        curl -Lso "/usr/local/x-ui-linux-$(arch).tar.gz" "${url}"
    else
        echo -e "${red}Neither wget nor curl available.${plain}"
        exit 1
    fi

    if [[ -e /usr/local/x-ui/ ]]; then
        systemctl stop x-ui 2>/dev/null || true
        rm -rf /usr/local/x-ui/
    fi

    tar zxvf "x-ui-linux-$(arch).tar.gz"
    rm -f "x-ui-linux-$(arch).tar.gz"
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

    systemctl daemon-reload
    systemctl enable x-ui
    systemctl start x-ui

    # post config (port/basepath/creds)
    config_after_install

    echo -e "${green}3x-ui ${tag_version}${plain} installed and started."
}

install_acme() {
    if ! command -v crontab >/dev/null 2>&1; then
        case "${release}" in
        ubuntu | debian | armbian) apt-get update -y && apt-get install -y cron ;;
        centos | almalinux | rocky | ol) yum install -y cronie ;;
        fedora | amzn) dnf install -y cronie ;;
        arch | manjaro | parch) pacman -Sy --noconfirm cronie ;;
        opensuse-tumbleweed) zypper -n install cron ;;
        *) ;;
        esac
        systemctl enable cron 2>/dev/null || systemctl enable crond 2>/dev/null || true
        systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null || true
    fi

    if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        echo -e "${green}acme.sh is already installed.${plain}"
        return 0
    fi

    echo -e "${yellow}Installing acme.sh...${plain}"
    curl -fsSL https://get.acme.sh | sh || true
    [[ -f "$HOME/.acme.sh/acme.sh" ]] || return 1
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

install_nginx_only_80() {
    local domain="$1"
    if ! command -v nginx &>/dev/null; then
        case "${release}" in
        ubuntu | debian | armbian) apt-get update -y && apt-get install -y nginx ;;
        centos | almalinux | rocky | ol) yum install -y nginx ;;
        fedora | amzn) dnf install -y nginx ;;
        arch | manjaro | parch) pacman -Sy --noconfirm nginx ;;
        opensuse-tumbleweed) zypper -n install nginx ;;
        *) echo -e "${red}Unsupported system for nginx auto-install.${plain}"; return 1 ;;
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
EOF

    mkdir -p /var/www/default_site
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl restart nginx || true
}

auto_ssl_and_nginx() {
    echo -e "${yellow}=== 申请证书 + 配置 Nginx(仅 80) ===${plain}"

    [[ -f /tmp/xui_panel_domain && -f /tmp/xui_panel_email ]] || { echo -e "${red}错误: 未找到域名或邮箱配置${plain}"; return 1; }

    local domain email
    domain="$(cat /tmp/xui_panel_domain)"
    email="$(cat /tmp/xui_panel_email)"

    install_acme || { echo -e "${red}acme.sh 安装失败${plain}"; return 1; }

    # stop services occupying 80 (for standalone)
    if lsof -i ":80" >/dev/null 2>&1; then
        echo -e "${yellow}检测到 80 端口被占用，尝试停止相关服务...${plain}"
        systemctl stop nginx 2>/dev/null || true
        systemctl stop apache2 2>/dev/null || true
        systemctl stop httpd 2>/dev/null || true
        sleep 1
    fi

    echo -e "${yellow}开始申请证书(standalone, 使用 80 端口)...${plain}"
    "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
    "$HOME/.acme.sh/acme.sh" --register-account -m "$email" >/dev/null 2>&1 || true
    "$HOME/.acme.sh/acme.sh" --issue -d "$domain" --standalone --force
    if [[ $? -ne 0 ]]; then
        echo -e "${red}证书申请失败${plain}"
        return 1
    fi

    local cert_dir="/root/cert/${domain}"
    mkdir -p "$cert_dir"
    "$HOME/.acme.sh/acme.sh" --installcert -d "$domain" \
        --key-file "$cert_dir/privkey.pem" \
        --fullchain-file "$cert_dir/fullchain.pem"

    local cert_file="$cert_dir/fullchain.pem"
    local key_file="$cert_dir/privkey.pem"
    if [[ ! -f "$cert_file" || ! -f "$key_file" ]]; then
        echo -e "${red}证书文件不存在${plain}"
        return 1
    fi

    # set panel cert (best effort; some builds may vary)
    /usr/local/x-ui/x-ui setting -webCert "$cert_file" -webCertKey "$key_file" >/dev/null 2>&1 || true

    # Compatibility: skip -subCertFile if unsupported
    if /usr/local/x-ui/x-ui setting -h 2>&1 | grep -q -- "-subCertFile"; then
        /usr/local/x-ui/x-ui setting -subCertFile "$cert_file" -subKeyFile "$key_file" >/dev/null 2>&1 || true
    else
        echo -e "${yellow}[WARN] 当前 3x-ui 不支持 -subCertFile/-subKeyFile，已跳过（不影响面板 HTTPS）。${plain}"
    fi

    # cron renew
    if ! crontab -l 2>/dev/null | grep -q 'acme.sh --cron'; then
        (crontab -l 2>/dev/null; echo "0 2 1 */2 * $HOME/.acme.sh/acme.sh --cron --home $HOME/.acme.sh > /dev/null") | crontab -
    fi

    # IMPORTANT: nginx only listens 80 (does NOT occupy 443)
    install_nginx_only_80 "$domain" || true
}

# Always generate VLESS+REALITY URL+params if REALITY enabled
generate_reality_params_and_link() {
    local enable_reality="N"
    [[ -f /tmp/xui_enable_reality ]] && enable_reality="$(cat /tmp/xui_enable_reality || echo N)"
    if [[ "$enable_reality" != "y" && "$enable_reality" != "Y" ]]; then
        return 0
    fi

    echo -e "${yellow}=== 生成 VLESS + REALITY 客户端导入链接 (默认生成) ===${plain}"

    local domain=""
    [[ -f /tmp/xui_panel_domain ]] && domain="$(cat /tmp/xui_panel_domain || true)"
    if [[ -z "$domain" ]]; then
        echo -e "${red}Domain not found. Cannot build VLESS URL.${plain}"
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

    local kp private_key public_key
    kp="$(gen_reality_keypair)" || { echo -e "${red}无法生成 REALITY keypair。请进入面板手动生成/填写。${plain}"; return 1; }
    private_key="${kp%%|*}"
    public_key="${kp##*|}"

    echo "$uuid" > /tmp/xui_vless_uuid
    echo "$remark" > /tmp/xui_vless_remark
    echo "$listen_port" > /tmp/xui_vless_port
    echo "$sni" > /tmp/xui_reality_sni
    echo "$dest" > /tmp/xui_reality_dest
    echo "$fp" > /tmp/xui_reality_fp
    echo "$sid" > /tmp/xui_reality_sid
    echo "$private_key" > /tmp/xui_reality_private
    echo "$public_key" > /tmp/xui_reality_public

    local vless_url
    vless_url="vless://${uuid}@${domain}:${listen_port}?type=tcp&security=reality&encryption=none&fp=${fp}&sni=${sni}&pbk=${public_key}&sid=${sid}#${remark}"
    echo "$vless_url" > /tmp/xui_vless_url

    echo -e "${green}已生成 REALITY 参数（请保存）：${plain}"
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

    echo -e "${yellow}提示：本脚本默认【只生成导入链接】。你可先在客户端导入链接，再到面板里按以上参数手动新建入站。${plain}"
}

check_firewall_ports() {
    local panel_port ssh_port open_ports
    panel_port=$(xui_get_value "port"); [[ -z "$panel_port" ]] && panel_port="8443"
    ssh_port=$(ss -tnlp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' | head -n1 || true)
    [[ -z "$ssh_port" ]] && ssh_port=22

    # if reality enabled, open 443 too
    local enable_reality="N"
    [[ -f /tmp/xui_enable_reality ]] && enable_reality="$(cat /tmp/xui_enable_reality || echo N)"
    if [[ "$enable_reality" == "y" || "$enable_reality" == "Y" ]]; then
        open_ports="80 443 ${panel_port} ${ssh_port}"
    else
        open_ports="80 ${panel_port} ${ssh_port}"
    fi

    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        for port in $open_ports; do
            firewall-cmd --permanent --add-port=${port}/tcp >/dev/null 2>&1 || true
        done
        firewall-cmd --reload >/dev/null 2>&1 || true
    elif command -v ufw &>/dev/null; then
        for port in $open_ports; do
            ufw allow $port/tcp >/dev/null 2>&1 || true
        done
        ufw --force enable >/dev/null 2>&1 || true
    fi
}

pre_check_input() {
    echo -e "${yellow}=== 集中输入参数 ===${plain}"

    local domain="" email=""
    read -p "请输入用于申请证书的域名 (example.com): " domain </dev/tty
    read -p "请输入邮箱 (admin@example.com): " email </dev/tty

    if [[ -z "$domain" || ! $domain =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${red}域名格式不正确${plain}"
        exit 1
    fi
    if [[ -z "$email" || ! $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${red}邮箱格式不正确${plain}"
        exit 1
    fi

    echo "$domain" > /tmp/xui_panel_domain
    echo "$email" > /tmp/xui_panel_email

    dns_check "$domain"

    echo -e "${yellow}=== 是否开启 VLESS + REALITY (使用 443) ===${plain}"
    echo -e "${yellow}说明：开启后将占用 443 端口用于 REALITY；Nginx 只监听 80；面板建议用 8443 走 HTTPS。${plain}"
    local enable_reality="N"
    read -p "是否开启 REALITY? Enable REALITY? [y/N]: " enable_reality </dev/tty || true
    enable_reality="${enable_reality:-N}"
    echo "$enable_reality" > /tmp/xui_enable_reality
}

show_installation_info() {
    echo -e "\n${yellow}=== 安装完成 Installation Complete ===${plain}"

    local info username password port webBasePath server_ip panel_domain webBasePathClean
    info="$(xui_setting_show)"
    username="$(echo "$info" | grep -Eo 'username: .+' | awk '{print $2}' | head -n1 || true)"
    password="$(echo "$info" | grep -Eo 'password: .+' | awk '{print $2}' | head -n1 || true)"
    port="$(echo "$info" | grep -Eo 'port: .+' | awk '{print $2}' | head -n1 || true)"
    webBasePath="$(echo "$info" | grep -Eo 'webBasePath: .+' | awk '{print $2}' | head -n1 || true)"
    webBasePathClean="$(echo "$webBasePath" | sed 's#^/*##;s#/*$##')"
    server_ip="$(get_public_ip)"; [[ -z "$server_ip" ]] && server_ip="YOUR_SERVER_IP"
    panel_domain="$(cat /tmp/xui_panel_domain 2>/dev/null || true)"

    echo -e "\n${green}=== 面板登录信息 Panel Login Info ===${plain}"
    echo -e "${green}用户名 Username: ${username}${plain}"
    echo -e "${green}密码 Password: ${password}${plain}"
    echo -e "${green}Port: ${port}${plain}"
    echo -e "${green}WebBasePath: ${webBasePathClean}${plain}"

    if [[ -n "$panel_domain" ]]; then
        echo -e "${yellow}Panel URL:${plain}"
        echo -e "${green}https://${panel_domain}:${port}/${webBasePathClean}${plain}"
    else
        echo -e "${yellow}Panel URL:${plain}"
        echo -e "${green}http://${server_ip}:${port}/${webBasePathClean}${plain}"
    fi

    if [[ -f /tmp/xui_vless_url ]]; then
        echo -e "\n${green}=== VLESS + REALITY (Client Import) ===${plain}"
        echo -e "${yellow}VLESS 一键导入链接：${plain}"
        cat /tmp/xui_vless_url
    fi

    echo -e "\n${yellow}提示：若需再次查看面板设置：x-ui settings${plain}"
    echo -e "${yellow}快速检查端口占用：ss -lntp | egrep ':80|:443|:8443'${plain}"
}

main() {
    pre_check_input
    install_base
    sync_time_and_tz

    # Install 3x-ui (optional version arg)
    if [[ $# -ge 1 && -n "${1:-}" ]]; then
        install_x-ui "$1"
    else
        install_x-ui
    fi

    auto_ssl_and_nginx || true

    # If REALITY enabled: ALWAYS generate link+params (no auto-add inbound by default)
    generate_reality_params_and_link || true

    check_firewall_ports
    show_installation_info
}

main "$@"
