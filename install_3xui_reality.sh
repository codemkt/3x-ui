#!/bin/bash
# 3X-UI + SSL(acme.sh) + Nginx(HTTP-only camouflage) + (optional) VLESS/REALITY installer
#
# 目标：REALITY 使用 443；Nginx 不监听 443（只监听 80 做伪装站点）；面板走 HTTPS 直连到 3X-UI 的面板端口（建议 8443）。
#
# 特性：
# - 集中输入：域名 + 邮箱 -> DNS 解析校验（提示） -> 是否开启 REALITY -> 是否设置时区
# - 自动时间同步：开启 NTP / 安装 chrony（最佳努力）
# - 自动申请证书：acme.sh standalone（仅占用 80）
# - Nginx 只监听 80：提供默认伪装站点
# - 若开启 REALITY：生成 x25519 keypair + shortId + vless:// 导入链接，并尽力通过 CLI 创建入站（失败则提示你在面板手动创建）
#
set -euo pipefail

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "${red}Fatal error:${plain} Please run this script with root privilege" && exit 1

if [[ -f /etc/os-release ]]; then
  source /etc/os-release
  release=$ID
elif [[ -f /usr/lib/os-release ]]; then
  source /usr/lib/os-release
  release=$ID
else
  echo "Failed to check the system OS!" >&2
  exit 1
fi

arch() {
  case "$(uname -m)" in
    x86_64|x64|amd64) echo 'amd64' ;;
    i*86|x86) echo '386' ;;
    armv8*|armv8|arm64|aarch64) echo 'arm64' ;;
    armv7*|armv7|arm) echo 'armv7' ;;
    armv6*|armv6) echo 'armv6' ;;
    armv5*|armv5) echo 'armv5' ;;
    s390x) echo 's390x' ;;
    *) echo -e "${red}Unsupported CPU architecture!${plain}" && exit 1 ;;
  esac
}

echo "The OS release is: $release"
echo "arch: $(arch)"

os_version=""
os_version=$(grep "^VERSION_ID" /etc/os-release | cut -d '=' -f2 | tr -d '"' | tr -d '.')

if [[ "${release}" == "ubuntu" ]]; then
  [[ ${os_version} -lt 1804 ]] && echo -e "${red}Please use Ubuntu 18.04 or higher!${plain}" && exit 1
elif [[ "${release}" == "debian" ]]; then
  [[ ${os_version} -lt 9 ]] && echo -e "${red}Please use Debian 9 or higher!${plain}" && exit 1
elif [[ "${release}" == "centos" ]]; then
  [[ ${os_version} -lt 8 ]] && echo -e "${red}Please use CentOS 8 or higher!${plain}" && exit 1
elif [[ "${release}" == "almalinux" ]]; then
  [[ ${os_version} -lt 80 ]] && echo -e "${red}Please use AlmaLinux 8.0 or higher!${plain}" && exit 1
elif [[ "${release}" == "rocky" ]]; then
  [[ ${os_version} -lt 8 ]] && echo -e "${red}Please use Rocky Linux 8 or higher!${plain}" && exit 1
elif [[ "${release}" == "ol" ]]; then
  [[ ${os_version} -lt 8 ]] && echo -e "${red}Please use Oracle Linux 8 or higher!${plain}" && exit 1
elif [[ "${release}" == "fedora" ]]; then
  [[ ${os_version} -lt 36 ]] && echo -e "${red}Please use Fedora 36 or higher!${plain}" && exit 1
elif [[ "${release}" == "amzn" ]]; then
  [[ ${os_version} != "2023" ]] && echo -e "${red}Please use Amazon Linux 2023!${plain}" && exit 1
else
  : # allow others already in your original script family
fi

install_base() {
  case "${release}" in
    ubuntu|debian|armbian)
      DEBIAN_FRONTEND=noninteractive apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q wget curl tar tzdata socat lsof unzip iproute2 ca-certificates openssl
      ;;
    centos|almalinux|rocky|ol)
      yum install -y wget curl tar socat tzdata lsof unzip iproute ca-certificates openssl
      ;;
    fedora|amzn)
      dnf install -y -q wget curl tar tzdata socat lsof unzip iproute ca-certificates openssl
      ;;
    arch|manjaro|parch)
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
  openssl rand -hex "$bytes"
}

get_public_ip() {
  curl -s https://api.ipify.org 2>/dev/null || true
}

resolve_domain_ips() {
  local d="$1"
  getent ahosts "$d" 2>/dev/null | awk '{print $1}' | sort -u | head -n 10
}

dns_check_prompt() {
  local domain="$1"
  local pub_ip="$2"
  local resolved
  resolved="$(resolve_domain_ips "$domain" | tr '\n' ' ' | xargs || true)"

  echo -e "${yellow}=== DNS 解析检查 (DNS check) ===${plain}"
  echo -e "${yellow}域名: ${domain}${plain}"
  echo -e "${yellow}本机公网 IP: ${pub_ip:-UNKNOWN}${plain}"
  echo -e "${yellow}解析到的 IP: ${resolved:-NONE}${plain}"
  echo -e "${yellow}说明：申请证书(standalone)要求域名 A/AAAA 记录解析到当前服务器公网 IP，并且 80 端口可从公网访问。${plain}"

  if [[ -n "$pub_ip" && -n "$resolved" && "$resolved" == *"$pub_ip"* ]]; then
    echo -e "${green}DNS 看起来已正确解析到当前服务器。${plain}"
    return 0
  fi

  echo -e "${red}提示：DNS 解析可能还没指向当前服务器（或 IPv6/多 IP 情况未覆盖）。${plain}"
  local c=""
  read -p "仍然继续安装并尝试申请证书吗？Continue anyway? [y/N]: " c </dev/tty || true
  c="${c:-N}"
  [[ "$c" == "y" || "$c" == "Y" ]] && return 0
  echo -e "${red}已取消。请先把域名解析到本机公网 IP 后再运行。${plain}"
  exit 1
}

apply_timezone_and_ntp() {
  local tz_choice="${1:-keep}"

  echo -e "${yellow}=== 时间同步与时区 ===${plain}"
  echo -e "${yellow}说明：时区只影响显示/日志时间；NTP 同步保证系统时间准确。${plain}"

  if command -v timedatectl >/dev/null 2>&1; then
    if [[ "$tz_choice" == "shanghai" ]]; then
      timedatectl set-timezone Asia/Shanghai || true
    fi
    timedatectl set-ntp true || true
  else
    if [[ "$tz_choice" == "shanghai" ]]; then
      ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime || true
    fi
  fi

  if ! (systemctl is-active --quiet systemd-timesyncd 2>/dev/null || systemctl is-active --quiet chrony 2>/dev/null || systemctl is-active --quiet chronyd 2>/dev/null || systemctl is-active --quiet ntp 2>/dev/null); then
    echo -e "${yellow}未检测到正在运行的 NTP 服务，尝试安装 chrony...${plain}"
    case "${release}" in
      ubuntu|debian|armbian)
        apt-get update -y
        apt-get install -y -q chrony || true
        systemctl enable chrony 2>/dev/null || true
        systemctl restart chrony 2>/dev/null || true
        ;;
      centos|almalinux|rocky|ol|fedora|amzn)
        (yum install -y chrony || dnf install -y chrony) || true
        systemctl enable chronyd 2>/dev/null || true
        systemctl restart chronyd 2>/dev/null || true
        ;;
      arch|manjaro|parch)
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

  echo -e "${green}当前时间状态：${plain}"
  if command -v timedatectl >/dev/null 2>&1; then
    timedatectl status | sed -n '1,15p' || true
  else
    date || true
  fi
}

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

  [[ -z "$xray_bin" ]] && return 1

  local out priv pub
  out=$("$xray_bin" x25519 2>/dev/null || true)
  priv=$(echo "$out" | grep -i "Private key" | awk -F: '{print $2}' | xargs || true)
  pub=$(echo "$out"  | grep -i "Public key"  | awk -F: '{print $2}' | xargs || true)

  [[ -z "$priv" || -z "$pub" ]] && return 1
  echo "$priv|$pub"
}

config_after_install() {
  local existing_username existing_password existing_webBasePath existing_port server_ip
  existing_username=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'username: .+' | awk '{print $2}' || true)
  existing_password=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'password: .+' | awk '{print $2}' || true)
  existing_webBasePath=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'webBasePath: .+' | awk '{print $2}' || true)
  existing_port=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'port: .+' | awk '{print $2}' || true)
  server_ip=$(get_public_ip || echo "YOUR_SERVER_IP")

  if [[ -z "$existing_port" || "$existing_port" == "0" ]]; then
    existing_port="8443"
  fi

  local panel_domain=""
  panel_domain=$(cat /tmp/xui_panel_domain 2>/dev/null || true)

  if [[ ${#existing_webBasePath} -lt 4 ]]; then
    local config_webBasePath config_username config_password config_port
    config_webBasePath=$(gen_random_string 15)
    config_username=$(gen_random_string 10)
    config_password=$(gen_random_string 12)

    echo -e "${yellow}面板端口建议使用 8443（因为 REALITY 默认占用 443）。${plain}"
    read -p "请设置面板端口(默认 8443): " config_port </dev/tty || true
    config_port="${config_port:-8443}"

    /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}" -port "${config_port}" -webBasePath "${config_webBasePath}"
    existing_port="${config_port}"
  else
    if [[ "$existing_username" == "admin" && "$existing_password" == "admin" ]]; then
      local config_username config_password
      config_username=$(gen_random_string 10)
      config_password=$(gen_random_string 12)
      /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}"
    fi
  fi

  /usr/local/x-ui/x-ui migrate || true
}

install_x-ui() {
  cd /usr/local/ || exit 1

  local tag_version url
  if [[ $# -eq 0 || -z "${1:-}" ]]; then
    tag_version=$(curl -Ls "https://api.github.com/repos/codemkt/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -z "$tag_version" ]] && echo -e "${red}Failed to fetch 3x-ui version (GitHub API).${plain}" && exit 1
  else
    tag_version="$1"
  fi

  url="https://github.com/codemkt/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"
  echo -e "${yellow}Installing 3x-ui ${tag_version} ...${plain}"

  if command -v wget >/dev/null 2>&1; then
    wget -N --no-check-certificate -O /usr/local/x-ui-linux-$(arch).tar.gz "${url}"
  else
    curl -Lso /usr/local/x-ui-linux-$(arch).tar.gz "${url}"
  fi

  if [[ -e /usr/local/x-ui/ ]]; then
    systemctl stop x-ui 2>/dev/null || true
    rm -rf /usr/local/x-ui/
  fi

  tar zxvf /usr/local/x-ui-linux-$(arch).tar.gz -C /usr/local/
  rm -f /usr/local/x-ui-linux-$(arch).tar.gz

  cd /usr/local/x-ui || exit 1
  chmod +x x-ui || true
  chmod +x x-ui.service 2>/dev/null || true
  cp -f x-ui.service /etc/systemd/system/

  wget --no-check-certificate -O /usr/bin/x-ui https://raw.githubusercontent.com/codemkt/3x-ui/main/x-ui.sh
  chmod +x /usr/bin/x-ui

  config_after_install

  systemctl daemon-reload
  systemctl enable x-ui
  systemctl start x-ui

  echo -e "${green}3x-ui ${tag_version} installed and started.${plain}"
}

install_acme() {
  if ! command -v crontab >/dev/null 2>&1; then
    case "${release}" in
      ubuntu|debian|armbian) apt-get update && apt-get install -y cron ;;
      centos|almalinux|rocky|ol) yum install -y cronie ;;
      fedora|amzn) dnf install -y cronie ;;
      arch|manjaro|parch) pacman -Sy --noconfirm cronie ;;
      opensuse-tumbleweed) zypper -n install cron ;;
      *) apt-get install -y cron || yum install -y cronie ;;
    esac
    systemctl enable cron 2>/dev/null || systemctl enable crond 2>/dev/null || true
    systemctl start  cron 2>/dev/null || systemctl start  crond 2>/dev/null || true
  fi

  [[ -f "$HOME/.acme.sh/acme.sh" ]] && return 0
  curl -s https://get.acme.sh | sh || true
  [[ -f "$HOME/.acme.sh/acme.sh" ]] && return 0
  return 1
}

generate_default_site() {
  local domain="$1"
  local site_dir="/var/www/default_site"
  mkdir -p "$site_dir"
  cat >"$site_dir/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Welcome to ${domain}</title>
</head>
<body>
  <h1>Welcome to ${domain}</h1>
  <p>This is a default camouflage site (HTTP only).</p>
</body>
</html>
EOF
}

install_nginx_http_only() {
  local domain="$1"

  if ! command -v nginx &>/dev/null; then
    case "${release}" in
      ubuntu|debian|armbian) apt-get update && apt-get install -y nginx ;;
      centos|almalinux|rocky|ol) yum install -y nginx ;;
      fedora|amzn) dnf install -y nginx ;;
      arch|manjaro|parch) pacman -Sy --noconfirm nginx ;;
      *) echo -e "${red}Unsupported system for nginx auto-install.${plain}" && return 1 ;;
    esac
  fi

  generate_default_site "$domain"

  cat >/etc/nginx/conf.d/default_site.conf <<EOF
server {
  listen 80;
  server_name ${domain};
  location / {
    root /var/www/default_site;
    index index.html;
  }
}
EOF

  systemctl enable nginx || true
  systemctl restart nginx || true
}

auto_ssl_and_nginx() {
  echo -e "${yellow}=== 申请证书 + 配置 Nginx(仅 80) ===${plain}"

  local domain email
  domain=$(cat /tmp/xui_panel_domain)
  email=$(cat /tmp/xui_panel_email)

  install_acme || { echo -e "${red}acme.sh 安装失败，请手动安装后重试。${plain}"; return 1; }

  if lsof -i ":80" >/dev/null 2>&1; then
    echo -e "${yellow}检测到 80 端口被占用，尝试停止相关服务...${plain}"
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    systemctl stop httpd 2>/dev/null || true
    sleep 1
  fi

  echo -e "${yellow}开始申请证书(standalone, 使用 80 端口)...${plain}"
  "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt || true
  "$HOME/.acme.sh/acme.sh" --register-account -m "$email" || true
  "$HOME/.acme.sh/acme.sh" --issue -d "$domain" --standalone --force

  local cert_dir="/root/cert/${domain}"
  mkdir -p "$cert_dir"
  "$HOME/.acme.sh/acme.sh" --installcert -d "$domain" \
    --key-file "$cert_dir/privkey.pem" \
    --fullchain-file "$cert_dir/fullchain.pem"

  local cert_file="${cert_dir}/fullchain.pem"
  local key_file="${cert_dir}/privkey.pem"
  if [[ ! -f "$cert_file" || ! -f "$key_file" ]]; then
    echo -e "${red}证书文件不存在，申请可能失败。${plain}"
    return 1
  fi

  /usr/local/x-ui/x-ui cert -webCert "$cert_file" -webCertKey "$key_file" || true
  /usr/local/x-ui/x-ui setting -subCertFile "$cert_file" -subKeyFile "$key_file" || true

  if ! crontab -l 2>/dev/null | grep -q 'acme.sh --cron'; then
    (crontab -l 2>/dev/null; echo "0 2 1 */2 * $HOME/.acme.sh/acme.sh --cron --home $HOME/.acme.sh > /dev/null") | crontab -
  fi

  install_nginx_http_only "$domain" || true
}

auto_add_reality_inbound() {
  local enable
  enable="$(cat /tmp/xui_enable_reality 2>/dev/null || echo "0")"
  [[ "$enable" != "1" ]] && return 0

  echo -e "${yellow}=== 创建 VLESS + REALITY 入站 (443) ===${plain}"
  echo -e "${yellow}提示：本脚本不让 Nginx 占用 443，确保 REALITY 可以监听 443。${plain}"

  local domain uuid remark listen_port sni dest fp sid kp private_key public_key vless_url
  domain="$(cat /tmp/xui_panel_domain)"
  uuid="$(cat /proc/sys/kernel/random/uuid)"
  remark="VR_$(date +%y%m%d%H%M%S)$(gen_random_string 2)"
  listen_port="443"
  sni="www.cloudflare.com"
  dest="${sni}:443"
  fp="chrome"
  sid="$(gen_hex 8)"

  kp="$(gen_reality_keypair || true)"
  if [[ -z "$kp" ]]; then
    echo -e "${red}未找到 xray 或无法生成 REALITY keypair。你可以在 3x-ui 面板里手动创建 REALITY 入站。${plain}"
    return 0
  fi
  private_key="${kp%%|*}"
  public_key="${kp##*|}"

  vless_url="vless://${uuid}@${domain}:${listen_port}?type=tcp&security=reality&encryption=none&fp=${fp}&sni=${sni}&pbk=${public_key}&sid=${sid}#${remark}"

  echo "$vless_url" > /tmp/xui_vless_url

  echo -e "${green}已生成客户端导入链接：${plain}"
  echo "---------------------------------------------"
  echo "$vless_url"
  echo "---------------------------------------------"

  echo -e "${yellow}尝试通过 CLI 自动添加入站（失败可忽略，改为面板手动添加）...${plain}"
  set +e
  add_output=$(/usr/local/x-ui/x-ui setting -AddInbound "$vless_url" 2>&1)
  add_status=$?
  set -e
  if [[ $add_status -eq 0 ]]; then
    echo -e "${green}已通过 CLI 添加 VLESS+REALITY 入站。${plain}"
    systemctl restart x-ui || true
  else
    echo -e "${yellow}CLI 添加未成功（可忽略）。请到面板手动新增 VLESS+REALITY 入站，参数参考导入链接即可。${plain}"
    echo -e "${yellow}CLI 输出：${plain}\n$add_output"
  fi
}

check_firewall_ports() {
  local panel_port ssh_port open_ports
  panel_port=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null | grep -Eo 'port: .+' | awk '{print $2}' || true)
  [[ -z "$panel_port" ]] && panel_port="8443"

  ssh_port=$(ss -tnlp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' | head -n1 || true)
  [[ -z "$ssh_port" ]] && ssh_port=22

  open_ports="80 ${panel_port} ${ssh_port}"
  if [[ "$(cat /tmp/xui_enable_reality 2>/dev/null || echo "0")" == "1" ]]; then
    open_ports="80 443 ${panel_port} ${ssh_port}"
  fi

  if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
    for port in $open_ports; do firewall-cmd --permanent --add-port=${port}/tcp || true; done
    firewall-cmd --reload || true
  elif command -v ufw &>/dev/null; then
    for port in $open_ports; do ufw allow $port/tcp || true; done
    ufw --force enable || true
  fi
}

pre_check_input() {
  echo -e "${yellow}=== 集中输入参数 ===${plain}"

  local domain="" email="" retry=0 max_retries=3
  while [[ $retry -lt $max_retries ]]; do
    read -p "请输入用于申请证书的域名 (example.com): " domain </dev/tty || true
    [[ -z "$domain" ]] && echo -e "${red}域名不能为空${plain}" && ((retry++)) && continue
    [[ ! $domain =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && echo -e "${red}域名格式不正确${plain}" && ((retry++)) && continue
    break
  done
  [[ $retry -eq $max_retries ]] && echo -e "${red}重试次数已达上限，退出。${plain}" && exit 1

  retry=0
  while [[ $retry -lt $max_retries ]]; do
    read -p "请输入邮箱 (admin@example.com): " email </dev/tty || true
    [[ -z "$email" ]] && echo -e "${red}邮箱不能为空${plain}" && ((retry++)) && continue
    [[ ! $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && echo -e "${red}邮箱格式不正确${plain}" && ((retry++)) && continue
    break
  done
  [[ $retry -eq $max_retries ]] && echo -e "${red}重试次数已达上限，退出。${plain}" && exit 1

  echo "$domain" > /tmp/xui_panel_domain
  echo "$email"  > /tmp/xui_panel_email

  local pub_ip
  pub_ip="$(get_public_ip || true)"
  dns_check_prompt "$domain" "$pub_ip"

  echo -e "${yellow}=== 是否开启 VLESS + REALITY (使用 443) ===${plain}"
  echo -e "${yellow}说明：开启后将占用 443 端口用于 REALITY；Nginx 只监听 80；面板建议用 8443 走 HTTPS。${plain}"
  local r=""
  read -p "是否开启 REALITY? Enable REALITY? [y/N]: " r </dev/tty || true
  r="${r:-N}"
  if [[ "$r" == "y" || "$r" == "Y" ]]; then
    echo "1" > /tmp/xui_enable_reality
  else
    echo "0" > /tmp/xui_enable_reality
  fi

  echo -e "${yellow}=== 时区设置 (最后一步输入) ===${plain}"
  echo -e "${yellow}[1] 保持当前时区${plain}"
  echo -e "${yellow}[2] 设置为 Asia/Shanghai${plain}"
  local tz=""
  read -p "选择 [1/2] (默认 2): " tz </dev/tty || true
  tz="${tz:-2}"
  if [[ "$tz" == "2" ]]; then
    echo "shanghai" > /tmp/xui_tz_choice
  else
    echo "keep" > /tmp/xui_tz_choice
  fi
}

show_installation_info() {
  echo -e "\n${yellow}=== 安装完成 ===${plain}"

  local info username password port webBasePath webBasePathClean server_ip panel_domain
  info=$(/usr/local/x-ui/x-ui setting -show true 2>/dev/null || true)
  username=$(echo "$info" | grep -Eo 'username: .+' | awk '{print $2}' || true)
  password=$(echo "$info" | grep -Eo 'password: .+' | awk '{print $2}' || true)
  port=$(echo "$info" | grep -Eo 'port: .+' | awk '{print $2}' || true)
  webBasePath=$(echo "$info" | grep -Eo 'webBasePath: .+' | awk '{print $2}' || true)
  webBasePathClean=$(echo "$webBasePath" | sed 's#^/*##;s#/*$##')
  server_ip=$(get_public_ip || echo "YOUR_SERVER_IP")
  panel_domain=$(cat /tmp/xui_panel_domain 2>/dev/null || true)

  echo -e "${green}=== 面板信息 (HTTPS 直连 3X-UI) ===${plain}"
  echo -e "${green}用户名: ${username}${plain}"
  echo -e "${green}密码: ${password}${plain}"
  echo -e "${green}面板端口: ${port}${plain}"
  echo -e "${green}WebBasePath: ${webBasePathClean}${plain}"
  if [[ -n "$panel_domain" ]]; then
    echo -e "${yellow}面板访问(HTTPS):${plain} ${green}https://${panel_domain}:${port}/${webBasePathClean}${plain}"
  else
    echo -e "${yellow}面板访问(HTTPS):${plain} ${green}https://${server_ip}:${port}/${webBasePathClean}${plain}"
  fi

  echo -e "\n${green}=== Nginx 伪装站点 (HTTP only) ===${plain}"
  if [[ -n "$panel_domain" ]]; then
    echo -e "${yellow}伪装站点:${plain} ${green}http://${panel_domain}/${plain}"
  else
    echo -e "${yellow}伪装站点:${plain} ${green}http://${server_ip}/${plain}"
  fi

  if [[ -f /tmp/xui_vless_url ]]; then
    echo -e "\n${green}=== VLESS + REALITY 客户端导入链接 ===${plain}"
    echo -e "${green}$(cat /tmp/xui_vless_url)${plain}"
  fi

  echo -e "\n${yellow}提示：查看面板设置：x-ui settings${plain}"
  echo -e "${yellow}提示：检查 443 是否被占用：ss -lntp | grep :443${plain}"
}

main() {
  pre_check_input
  install_base

  local tz_choice
  tz_choice="$(cat /tmp/xui_tz_choice 2>/dev/null || echo "shanghai")"
  apply_timezone_and_ntp "$tz_choice"

  install_x-ui "${1:-}"

  auto_ssl_and_nginx
  auto_add_reality_inbound

  check_firewall_ports
  show_installation_info
}

main "$@"
