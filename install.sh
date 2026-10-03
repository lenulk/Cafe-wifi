#!/usr/bin/env bash
#
# ============================================================================
#  Cafe Wi-Fi Gateway & Management System  --  Universal Linux Installer
#  Project-01 / สาขาวิศวกรรมคอมพิวเตอร์และการสื่อสาร
# ----------------------------------------------------------------------------
#  รองรับ: Debian / Ubuntu / Raspberry Pi OS, Fedora / RHEL / Rocky / Alma,
#          Arch / Manjaro, openSUSE, Alpine
#
#  โหมดเครือข่าย: สาย LAN เส้นเดียว (one-armed router) -- RPi ต่อเราเตอร์บ้านด้วย
#  RJ45 เส้นเดียว, ตัวเราเตอร์ปล่อย Wi-Fi ให้ลูกค้าและปิด DHCP ของตัวเอง (ดู PROJECT_PLAN.md §3.1)
#
#  ใช้งาน:
#     sudo ./install.sh                                     # โหมดถาม-ตอบ
#     sudo ./install.sh -y --nic eth0 --uplink-gw 192.168.1.1
#     sudo ./install.sh --skip-network                      # โหมดพัฒนาบน VM/แล็ปท็อป
#     ./install.sh --dry-run                                # ดูว่าจะทำอะไรบ้าง
#     sudo ./install.sh --uninstall
# ============================================================================

set -Eeuo pipefail

readonly APP_NAME="cafe-wifi"
readonly APP_VERSION="1.0.0"
readonly APP_USER="cafewifi"
readonly ETC_DIR="/etc/${APP_NAME}"
readonly OPT_DIR="/opt/${APP_NAME}"
readonly LOG_DIR="/var/log/${APP_NAME}"
readonly BACKUP_USB_LABEL="CAFEBACKUP"            # ตั้งชื่อ USB นี้แล้วเสียบ = สำรองออกนอก SD อัตโนมัติ
readonly BACKUP_USB_MNT="/mnt/cafebackup"
readonly BACKUP_DIR="/var/backups/${APP_NAME}"  # แก้บั๊ก H4 (เดิมไม่มี backup DB เลยในระบบ)
# macvlan ฝั่งลูกค้า ซ้อนบน $NIC -- ดูเหตุผลเต็มๆ ที่ configure_network() (R11/§3.1.6 Plan B
# ที่พิสูจน์แล้วจาก VM lab ว่าเป็นทางเดียวที่ openNDS ยอมทำงานบนโหมดสายเดียว)
readonly CLI_IFACE="${APP_NAME}-cli0"
readonly VENV_DIR="${OPT_DIR}/venv"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly STATE_FILE="${ETC_DIR}/install.state"

# ---- ค่าเริ่มต้น (override ได้ด้วย flag) -----------------------------------
# ---- โหมดสาย LAN เส้นเดียว (D17) -- ต่อ Pi เข้ากับเราเตอร์บ้านด้วยสายเดียว แล้วให้ Pi
#      ถือ 2 IP บนอินเทอร์เฟซเดียวกัน: หนึ่งไว้คุยกับเราเตอร์/ออกเน็ต อีกหนึ่งเป็น gateway
#      ของลูกค้า (ดู PROJECT_PLAN.md §3.1 สำหรับเหตุผลและข้อจำกัด) -----------------------
NIC=""                          # อินเทอร์เฟซเดียว (เช่น eth0) -- ไม่มี WAN/LAN แยกกันอีกแล้ว
UPLINK_CIDR="192.168.1.2/24"    # IP ของ Pi ฝั่งเราเตอร์ (ใช้ออกเน็ต + SSH เข้ามาดูแล)
UPLINK_GW="192.168.1.1"         # IP ของเราเตอร์บ้าน (default route ของ Pi)
HOST_DNS="1.1.1.1 8.8.8.8"      # DNS ที่ตัว Pi เองใช้ (chrony/apt/ทดสอบความเร็ว) -- ชุดเดียวกับ server= ของ dnsmasq
TRUSTED_MACS=""                 # N36: MAC ของอุปกรณ์โครงสร้างพื้นฐาน (เช่น AP) คั่นด้วย comma
CLIENT_CIDR="10.10.0.1/24"      # IP ของ Pi ฝั่งลูกค้า (เป็น gateway/DHCP/DNS ให้ลูกค้า)
DHCP_START="10.10.0.100"
DHCP_END="10.10.0.250"
DHCP_LEASE="4h"
DB_NAME="cafewifi"
DB_USER="cafewifi"
DB_PASS=""
ADMIN_PORT="8443"          # nginx https  (หน้าพนักงาน)
FAS_PORT="8080"            # nginx http   (หน้าลูกค้า) -- openNDS ชี้มาที่นี่
NDS_PORT="2050"            # openNDS gateway port
ADMIN_BACKEND="18443"      # gunicorn ภายใน
FAS_BACKEND="18080"        # gunicorn ภายใน
GATEWAY_NAME="Cafe-Guest"
# แก้บั๊ก M4: ปักเวอร์ชัน openNDS ที่ build แทนการดึง default branch ล่าสุดทุกครั้ง
# *** ตรวจว่า tag นี้ยังมีอยู่จริงที่ https://github.com/openNDS/openNDS/tags ก่อนใช้งานจริง
# เสมอ (ยังไม่เคย build/ทดสอบ tag นี้บนฮาร์ดแวร์จริง) เปลี่ยนได้ด้วย --opennds-ref ***
OPENNDS_REF="v10.1.3"
NTP_SERVERS="time1.nimt.or.th time2.nimt.or.th th.pool.ntp.org"
LOG_RETENTION_DAYS="180"
BACKUP_RETENTION_DAYS="14"  # แก้บั๊ก H4 -- เก็บ backup DB ในเครื่องกี่วัน (ไม่ใช่ log ตาม ม.26
                            # จึงไม่มีขั้นต่ำตามกฎหมายเหมือน LOG_RETENTION_DAYS)

INTERACTIVE=1
DRY_RUN=0
DO_UNINSTALL=0
SKIP_OPENNDS=0
SKIP_NETWORK=0
ASSUME_YES=0
ENABLE_PARTITIONS=0        # แก้บั๊ก (พบตอนตรวจทานรอบ 2) -- opt-in สำหรับ sql/003_partitions.sql

# ---- สี / logging ----------------------------------------------------------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
  C_RED=$(tput setaf 1); C_GRN=$(tput setaf 2); C_YEL=$(tput setaf 3)
  C_BLU=$(tput setaf 6); C_DIM=$(tput dim);     C_RST=$(tput sgr0)
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_RST=""
fi

info() { printf '%s[ %s ]%s %s\n'     "$C_BLU" "INFO" "$C_RST" "$*"; }
ok()   { printf '%s[ %s ]%s %s\n'     "$C_GRN" " OK " "$C_RST" "$*"; }
warn() { printf '%s[ %s ]%s %s\n' >&2 "$C_YEL" "WARN" "$C_RST" "$*"; }
err()  { printf '%s[ %s ]%s %s\n' >&2 "$C_RED" "FAIL" "$C_RST" "$*"; }
die()  { err "$*"; exit 1; }
step() { printf '\n%s==>%s %s%s%s\n' "$C_BLU" "$C_RST" "$C_GRN" "$*" "$C_RST"; }

run() {
  if (( DRY_RUN )); then printf '%s      $ %s%s\n' "$C_DIM" "$*" "$C_RST"; return 0; fi
  "$@"
}

run_sh() {  # สำหรับคำสั่งที่ต้องใช้ pipe / redirect
  if (( DRY_RUN )); then printf '%s      $ %s%s\n' "$C_DIM" "$1" "$C_RST"; return 0; fi
  bash -c "$1"
}

# write_file <path> [mode] [owner:group]   -- เนื้อหามาจาก stdin (heredoc)
write_file() {
  local path="$1" mode="${2:-0644}" own="${3:-}"
  if (( DRY_RUN )); then
    printf '%s      $ เขียนไฟล์ %s (mode %s)%s\n' "$C_DIM" "$path" "$mode" "$C_RST"
    cat >/dev/null
    return 0
  fi
  install -d -m 0755 "$(dirname "$path")"
  cat > "$path"
  chmod "$mode" "$path"
  [[ -n "$own" ]] && chown "$own" "$path"
  return 0
}

# ---------- DNS ของตัว Pi เอง (พบตอนทดสอบสายเส้นเดียวจริง 2026-10-02) ----------
# ${NIC} ถูกตั้ง IP เองแบบ static + ปลดจาก NetworkManager (N34) จึง**ไม่มีใครบอก Pi ว่า DNS คืออะไร**
# ในแลปไม่เคยเห็นเพราะ wlan0 ได้ DNS จาก DHCP ของ Wi-Fi -- ปิด wlan0 (= สภาพร้านจริง สายเดียว)
# แล้ว resolv.conf ว่างทันที: chrony หา time1.nimt.or.th/pool ไม่เจอหลังรีบูต (เวลาเพี้ยน = ผิด ม.26),
# apt/หน้าสถานะ/ทดสอบความเร็วพังหมด ส่วนลูกค้าไม่กระทบเพราะ dnsmasq ส่งต่อไป server= ตรง ๆ
configure_host_dns() {
  [[ -z "$HOST_DNS" ]] && return 0
  local ns body=""
  for ns in $HOST_DNS; do body+="nameserver ${ns}"$'\n'; done
  if [[ -L /etc/resolv.conf ]] && readlink /etc/resolv.conf | grep -q systemd; then
    write_file "/etc/systemd/resolved.conf.d/99-${APP_NAME}.conf" 0644 <<RESOLVED
# managed by ${APP_NAME} installer -- DNS ของตัว Pi (ไม่ใช่ของลูกค้า)
[Resolve]
DNS=${HOST_DNS}
RESOLVED
    run_sh "systemctl restart systemd-resolved 2>/dev/null || true"
    ok "ตั้ง DNS ของ Pi ผ่าน systemd-resolved: ${HOST_DNS}"
    return 0
  fi
  if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; then
    # ห้าม NetworkManager เขียนทับ resolv.conf (ไม่งั้นพอ Wi-Fi/อินเทอร์เฟซอื่นเปลี่ยนสถานะ ไฟล์จะว่างอีก)
    write_file "/etc/NetworkManager/conf.d/99-${APP_NAME}-dns.conf" 0644 <<NMDNS
# managed by ${APP_NAME} installer -- DNS ของ Pi ตั้งตายตัวใน /etc/resolv.conf
[main]
dns=none
rc-manager=unmanaged
NMDNS
    run_sh "nmcli general reload 2>/dev/null || systemctl reload NetworkManager 2>/dev/null || true"
  fi
  (( DRY_RUN )) || rm -f /etc/resolv.conf  # อาจเป็น symlink ของระบบอื่น -- เขียนเป็นไฟล์จริงแทน
  printf '# managed by %s installer -- DNS ของตัว Pi (ลูกค้าใช้ dnsmasq ที่ %s)\n%s' \
    "$APP_NAME" "${CLIENT_CIDR%%/*}" "$body" | write_file /etc/resolv.conf 0644
  ok "ตั้ง DNS ของ Pi: ${HOST_DNS} (ไม่พึ่ง DHCP/Wi-Fi)"
}

# ---------- สำรองข้อมูลลง USB (2026-10-03) ----------
# backup รายวันเดิมอยู่บน SD card ใบเดียวกับฐานข้อมูล -- การ์ดเสีย (เรื่องปกติของ Pi) = ข้อมูลและ backup
# หายพร้อมกัน log ย้อนหลังตาม ม.26 หายหมด · ให้ USB ที่ตั้งชื่อ (label) ${BACKUP_USB_LABEL} mount เองที่
# ${BACKUP_USB_MNT}: nofail = ไม่เสียบก็บูตได้, x-systemd.automount = เสียบทีหลังก็ใช้ได้ไม่ต้องรีบูต
configure_backup_usb() {
  step "สำรองข้อมูลลง USB (label ${BACKUP_USB_LABEL})"
  run install -d -m 0700 "$BACKUP_USB_MNT"
  local line="LABEL=${BACKUP_USB_LABEL} ${BACKUP_USB_MNT} auto nofail,noatime,x-systemd.automount,x-systemd.idle-timeout=120,x-systemd.device-timeout=3s 0 2"
  if grep -q "^LABEL=${BACKUP_USB_LABEL}[[:space:]]" /etc/fstab 2>/dev/null; then
    run_sh "sed -i 's|^LABEL=${BACKUP_USB_LABEL}[[:space:]].*|${line}|' /etc/fstab"
  else
    run_sh "printf '%s\\n' '# ${APP_NAME}: USB สำรองข้อมูล (ไม่เสียบก็บูตได้)' '${line}' >> /etc/fstab"
  fi
  if [[ "$INIT_SYS" == systemd ]]; then
    run_sh "systemctl daemon-reload && systemctl restart '$(systemd-escape -p --suffix=automount "$BACKUP_USB_MNT")' 2>/dev/null || true"
  fi
  if [[ -e "/dev/disk/by-label/${BACKUP_USB_LABEL}" ]]; then
    ok "พบ USB ${BACKUP_USB_LABEL} — backup รายวันจะคัดลอกไปที่ ${BACKUP_USB_MNT}/${APP_NAME}"
  else
    warn "ยังไม่ได้เสียบ USB สำรองข้อมูล — ตั้งชื่อ USB เป็น ${BACKUP_USB_LABEL} แล้วเสียบได้ทุกเมื่อ"
    warn "  (ดูวิธีเตรียม USB ใน docs/backup-usb.md) ระหว่างนี้ backup อยู่บน SD card ใบเดียวกันเท่านั้น"
  fi
}

on_error() {
  local rc=$? line=${1:-?}
  err "ติดตั้งล้มเหลวที่บรรทัด ${line} (exit=${rc})"
  err "ดู log ได้ที่ ${LOG_DIR}/install.log"
  err "ถอนการติดตั้งบางส่วนออกด้วย: sudo $0 --uninstall"
  exit "$rc"
}
trap 'on_error $LINENO' ERR

# ============================================================================
#  1. Argument parsing
# ============================================================================
usage() {
  cat <<'USAGE'
Cafe Wi-Fi Gateway Installer

  --nic <iface>            อินเทอร์เฟซเดียวที่ต่อไปเราเตอร์บ้าน (เช่น eth0) -- โหมดสาย LAN เส้นเดียว
  --uplink-cidr <cidr>     IP/prefix ของ Pi ฝั่งเราเตอร์ (default 192.168.1.2/24)
  --uplink-gw <ip>         IP ของเราเตอร์บ้าน / default route (default 192.168.1.1)
  --host-dns <a,b>         DNS ที่ตัว Pi เองใช้ (default 1.1.1.1,8.8.8.8) -- ไม่ใช่ DNS ของลูกค้า
  --client-cidr <cidr>     IP/prefix ของ Pi ฝั่งลูกค้า (default 10.10.0.1/24)
  --dhcp-range <a>,<b>    ช่วง DHCP ฝั่งลูกค้า (default 10.10.0.100,10.10.0.250)
  --ssid <name>           ชื่อที่แสดงบน captive portal (default Cafe-Guest)
  --admin-port <p>        พอร์ต Admin Panel HTTPS (default 8443)
  --fas-port <p>          พอร์ต Captive Portal HTTP (default 8080)
  --db-pass <pw>          รหัสผ่าน DB (ไม่ใส่ = สุ่มให้)
  --retention-days <n>    เก็บ log กี่วันก่อนลบ (default 180, ขั้นต่ำตามกฎหมาย 90)
  --backup-retention-days <n>  เก็บ backup DB ในเครื่องกี่วัน (default 14)
  --opennds-ref <tag>     git tag ของ openNDS ที่จะ build (default: ดูค่าใน install.sh
                          -- ตรวจ tag ล่าสุดที่ github.com/openNDS/openNDS/tags ก่อนใช้จริง)

  -y, --non-interactive   ไม่ถาม ใช้ค่า default/flag ทั้งหมด
  --skip-network          ไม่แตะ dnsmasq/nftables/routing (โหมดพัฒนาบน VM)
  --skip-opennds          ไม่ build openNDS
  --enable-partitions     เปิด sql/003_partitions.sql (partition รายสัปดาห์ + event scheduler
                          -- optional, ตาราง conn_log/dns_log ที่มีข้อมูลอยู่แล้วอาจ ALTER ช้า)
  --dry-run               แสดงคำสั่งที่จะรัน แต่ไม่รันจริง
  --trusted-mac LIST      MAC ของอุปกรณ์โครงสร้างพื้นฐานที่ไม่ต้อง login เช่น AP (คั่นด้วย ,)
  --uninstall             ถอนการติดตั้ง
  --version | -h/--help
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --nic)             NIC="$2"; shift 2 ;;
      --uplink-cidr)     UPLINK_CIDR="$2"; shift 2 ;;
      --uplink-gw)       UPLINK_GW="$2"; shift 2 ;;
      --host-dns)        HOST_DNS="${2//,/ }"; shift 2 ;;
      --trusted-mac)     TRUSTED_MACS="$2"; shift 2 ;;
      --client-cidr)     CLIENT_CIDR="$2"; shift 2 ;;
      --wan-if|--lan-if|--lan-cidr)
        die "ตัวเลือก $1 ถูกยกเลิกแล้ว (D17 เปลี่ยนเป็นโหมดสาย LAN เส้นเดียว) ใช้ --nic / --uplink-gw / --client-cidr แทน" ;;
      --dhcp-range)      DHCP_START="${2%%,*}"; DHCP_END="${2##*,}"; shift 2 ;;
      --ssid)            GATEWAY_NAME="$2"; shift 2 ;;
      --admin-port)      ADMIN_PORT="$2"; ADMIN_BACKEND=$((ADMIN_PORT+10000)); shift 2 ;;
      --fas-port)        FAS_PORT="$2";   FAS_BACKEND=$((FAS_PORT+10000));     shift 2 ;;
      --db-pass)         DB_PASS="$2"; shift 2 ;;
      --retention-days)  LOG_RETENTION_DAYS="$2"; shift 2 ;;
      --backup-retention-days) BACKUP_RETENTION_DAYS="$2"; shift 2 ;;
      --opennds-ref)     OPENNDS_REF="$2"; shift 2 ;;
      -y|--non-interactive) INTERACTIVE=0; ASSUME_YES=1; shift ;;
      --skip-network)    SKIP_NETWORK=1; shift ;;
      --skip-opennds)    SKIP_OPENNDS=1; shift ;;
      --enable-partitions) ENABLE_PARTITIONS=1; shift ;;
      --dry-run)         DRY_RUN=1; shift ;;
      --uninstall)       DO_UNINSTALL=1; shift ;;
      --version)         echo "${APP_NAME} installer ${APP_VERSION}"; exit 0 ;;
      -h|--help)         usage; exit 0 ;;
      *) die "ไม่รู้จักตัวเลือก: $1  (ดู --help)" ;;
    esac
  done
}

confirm() {
  if (( ASSUME_YES )); then return 0; fi
  local ans
  read -r -p "$(printf '%s?%s %s [y/N] ' "$C_YEL" "$C_RST" "${1:-ดำเนินการต่อ?}")" ans || true
  [[ "${ans,,}" == y* ]]
}

ask() {  # ask VAR "คำถาม" "ค่า default"
  local __var="$1" __q="$2" __def="$3" __ans
  if (( ! INTERACTIVE )); then printf -v "$__var" '%s' "$__def"; return 0; fi
  read -r -p "$(printf '%s>%s %s [%s]: ' "$C_BLU" "$C_RST" "$__q" "$__def")" __ans || true
  printf -v "$__var" '%s' "${__ans:-$__def}"
}

# ============================================================================
#  2. Distro detection + package abstraction
# ============================================================================
DISTRO_ID=""; DISTRO_NAME=""; PKG=""

detect_distro() {
  [[ -r /etc/os-release ]] || die "ไม่พบ /etc/os-release — ไม่รองรับระบบนี้"
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"

  if   command -v apt-get >/dev/null 2>&1; then PKG=apt
  elif command -v dnf     >/dev/null 2>&1; then PKG=dnf
  elif command -v yum     >/dev/null 2>&1; then PKG=yum
  elif command -v pacman  >/dev/null 2>&1; then PKG=pacman
  elif command -v zypper  >/dev/null 2>&1; then PKG=zypper
  elif command -v apk     >/dev/null 2>&1; then PKG=apk
  else die "ไม่พบ package manager ที่รองรับ (apt/dnf/yum/pacman/zypper/apk)"
  fi
  info "ระบบปฏิบัติการ: ${DISTRO_NAME}   package manager: ${PKG}"
}

pkg_map() {
  case "$1:$PKG" in
    mariadb:apt)             echo "mariadb-server mariadb-client" ;;
    mariadb:dnf|mariadb:yum) echo "mariadb-server" ;;
    mariadb:pacman)          echo "mariadb" ;;
    mariadb:zypper)          echo "mariadb" ;;
    mariadb:apk)             echo "mariadb mariadb-client" ;;

    python:apt)              echo "python3 python3-venv python3-dev python3-pip" ;;
    python:dnf|python:yum)   echo "python3 python3-devel python3-pip" ;;
    python:pacman)           echo "python python-pip" ;;
    python:zypper)           echo "python3 python3-devel python3-pip" ;;
    python:apk)              echo "python3 python3-dev py3-pip" ;;

    buildtools:apt)                echo "build-essential pkg-config libffi-dev libssl-dev" ;;
    buildtools:dnf|buildtools:yum) echo "gcc gcc-c++ make pkgconf-pkg-config libffi-devel openssl-devel" ;;
    buildtools:pacman)             echo "base-devel libffi openssl" ;;
    buildtools:zypper)             echo "gcc gcc-c++ make pkg-config libffi-devel libopenssl-devel" ;;
    buildtools:apk)                echo "build-base pkgconf libffi-dev openssl-dev" ;;

    microhttpd:apt)                echo "libmicrohttpd-dev" ;;
    microhttpd:dnf|microhttpd:yum) echo "libmicrohttpd-devel" ;;
    microhttpd:pacman)             echo "libmicrohttpd" ;;
    microhttpd:zypper)             echo "libmicrohttpd-devel" ;;
    microhttpd:apk)                echo "libmicrohttpd-dev" ;;

    # ทดสอบบน VM lab (2026-08-27) พบว่า openNDS exit ทันทีตอนสตาร์ทถ้า fas_secure_enabled
    # ตั้งแต่ระดับ 2 ขึ้นไปแล้วไม่มี php-cli + module openssl ของ php (มันเข้ารหัส query
    # string เองฝั่ง openNDS ก่อนส่งไป FAS แม้ FAS จะเป็น Flask ของเราเองก็ตาม ไม่ใช่แค่
    # ตัวอย่างสคริปต์ FAS ที่แถมมาเฉยๆ) -- php-cli บน Debian มี ext-openssl ติดมาให้แล้วในตัว
    php:apt)                echo "php-cli" ;;
    php:dnf|php:yum)        echo "php-cli php-openssl" ;;
    php:pacman)             echo "php" ;;
    php:zypper)             echo "php-cli" ;;
    php:apk)                echo "php-cli php-openssl" ;;

    conntrack:apt)                echo "conntrack" ;;
    conntrack:dnf|conntrack:yum)  echo "conntrack-tools" ;;
    conntrack:pacman)             echo "conntrack-tools" ;;
    conntrack:zypper)             echo "conntrack-tools" ;;
    conntrack:apk)                echo "conntrack-tools" ;;

    iproute:apt) echo "iproute2" ;;
    iproute:apk) echo "iproute2" ;;
    iproute:*)   echo "iproute2" ;;

    nginx:*)    echo "nginx" ;;
    dnsmasq:*)  echo "dnsmasq" ;;
    nftables:*) echo "nftables" ;;
    chrony:*)   echo "chrony" ;;
    git:*)      echo "git" ;;
    curl:*)     echo "curl" ;;
    openssl:*)  echo "openssl" ;;
    tcpdump:*)  echo "tcpdump" ;;
    *)          echo "$1" ;;
  esac
}

pkg_refresh() {
  case "$PKG" in
    apt)
      # หมายเหตุ (พบจริงตอนติดตั้งบน Pi 2026-08-26):
      #   1) apt/DNS resolver บางระบบลอง IPv6 ก่อนแล้วพัง "Network is unreachable" ทันที
      #      โดยไม่ fallback ไป IPv4 เอง ทั้งที่เครือข่ายโหมดสายเดียวของเราเป็น IPv4-only
      #      ล้วน -- บังคับ apt ให้ใช้ IPv4 เท่านั้นกันไว้ก่อนเสมอ (idempotent)
      #   2) Debian trixie เปลี่ยนสถานะจาก testing เป็น stable ทำให้ repo metadata
      #      เปลี่ยนชื่อ/โครงสร้าง apt จะปฏิเสธ cache เก่าด้วย error "Release file...
      #      no longer has a Release file" ถ้าไม่อนุญาตให้เปลี่ยนสถานะ suite
      write_file /etc/apt/apt.conf.d/99force-ipv4 0644 <<'APTCONF'
Acquire::ForceIPv4 "true";
APTCONF
      run_sh "DEBIAN_FRONTEND=noninteractive apt-get update -qq --allow-releaseinfo-change"
      ;;
    dnf)    run dnf -q makecache ;;
    yum)    run yum -q makecache ;;
    pacman) run pacman -Sy --noconfirm ;;
    zypper) run zypper --non-interactive refresh ;;
    apk)    run apk update ;;
  esac
}

pkg_install() {
  local list=() p
  for p in "$@"; do
    # shellcheck disable=SC2206
    list+=( $(pkg_map "$p") )
  done
  info "ติดตั้งแพ็กเกจ: ${list[*]}"
  case "$PKG" in
    apt)    run_sh "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${list[*]}" ;;
    dnf)    run dnf install -y "${list[@]}" ;;
    yum)    run yum install -y "${list[@]}" ;;
    pacman) run pacman -S --needed --noconfirm "${list[@]}" ;;
    zypper) run zypper --non-interactive install "${list[@]}" ;;
    apk)    run apk add --no-cache "${list[@]}" ;;
  esac
}

INIT_SYS=""
detect_init() {
  if   [[ -d /run/systemd/system ]];          then INIT_SYS=systemd
  elif command -v rc-service >/dev/null 2>&1; then INIT_SYS=openrc
  else INIT_SYS=none; fi
  info "ระบบ init: ${INIT_SYS}"
  [[ "$INIT_SYS" == none ]] && warn "ไม่พบ systemd/OpenRC — จะไม่ตั้งค่า service อัตโนมัติ"
  return 0
}

svc() {  # svc <enable|disable|start|stop|restart|reload> <name>
  local action="$1" name="$2"
  case "$INIT_SYS" in
    systemd)
      case "$action" in
        enable)  run systemctl enable --now "$name" ;;
        disable) run systemctl disable --now "$name" 2>/dev/null || true ;;
        *)       run systemctl "$action" "$name" ;;
      esac ;;
    openrc)
      case "$action" in
        enable)  run rc-update add "$name" default; run rc-service "$name" start ;;
        disable) run rc-service "$name" stop 2>/dev/null || true
                 run rc-update del "$name" default 2>/dev/null || true ;;
        *)       run rc-service "$name" "$action" ;;
      esac ;;
    none) warn "ข้ามการจัดการ service '${name}'" ;;
  esac
}

# ============================================================================
#  3. Preflight
# ============================================================================
require_root() {
  if (( DRY_RUN )); then return 0; fi
  [[ $EUID -eq 0 ]] || die "ต้องรันด้วย root  ->  sudo $0 ..."
}

preflight() {
  step "ตรวจสอบความพร้อมของระบบ (preflight)"
  local fail=0 arch mem_mb free_mb p

  arch="$(uname -m)"
  case "$arch" in
    x86_64|aarch64|armv7l|armv6l) info "สถาปัตยกรรม: ${arch}" ;;
    *) warn "สถาปัตยกรรม ${arch} ยังไม่เคยทดสอบ — อาจต้อง build บางส่วนเอง" ;;
  esac
  info "เคอร์เนล: $(uname -r)"

  mem_mb=$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
  if (( mem_mb < 900 )); then
    warn "RAM ${mem_mb} MB (ต่ำกว่า 1 GB) — MariaDB อาจทำงานไม่ราบรื่น"
  else
    ok "RAM ${mem_mb} MB"
  fi

  free_mb=$(df -Pm / | awk 'NR==2{print $4}')
  if (( free_mb < 2048 )); then
    err "พื้นที่ว่างบน / เหลือ ${free_mb} MB (ต้องการอย่างน้อย 2048 MB)"; fail=1
  else
    ok "พื้นที่ว่าง ${free_mb} MB"
  fi

  # แก้บั๊ก (พบจากรัน dry-run เต็มรูปแบบบน Debian netinst จริง): เครื่องขั้นต่ำที่เพิ่ง
  # bootstrap ยังไม่มี curl ติดตั้งมาแต่แรก (จะเพิ่งถูกติดตั้งทีหลังใน install_packages())
  # เหมือนกรณี ip/ss (M4) -- ถ้าไม่มี curl ให้ข้ามการเช็คแทนที่จะรายงาน false-negative ว่า
  # "อินเทอร์เน็ตไม่ผ่าน" ทั้งที่จริงแล้วแค่ยังไม่มีเครื่องมือเช็คต่างหาก
  if ! command -v curl >/dev/null 2>&1; then
    info "ยังไม่มี curl ให้ตรวจอินเทอร์เน็ต — ข้ามไปก่อน (จะติดตั้งแพ็กเกจแล้วค่อยเจอปัญหาเน็ตตรงนั้นแทนถ้ามี)"
  elif curl -fsS --max-time 8 -o /dev/null https://pypi.org 2>/dev/null; then
    ok "เชื่อมต่ออินเทอร์เน็ตได้"
  else
    warn "ตรวจอินเทอร์เน็ตไม่ผ่าน — การติดตั้งแพ็กเกจอาจล้มเหลว"
  fi

  # เตือนถ้ารันบน SD card (write endurance ต่ำกว่า SSD)
  local rootdev
  rootdev="$(findmnt -no SOURCE / 2>/dev/null || echo '')"
  if [[ "$rootdev" == *mmcblk* ]]; then
    warn "root filesystem อยู่บน SD card (${rootdev})"
    warn "ใช้ได้สำหรับเฟสทดสอบในแล็บ แต่ก่อนใช้งานจริงควรย้าย ${LOG_DIR} และ MariaDB ไป SSD"
    warn "ความเสี่ยงหลักคือไฟดับแล้ว filesystem พัง ไม่ใช่การเขียนจนหมดอายุ"
  fi

  if (( ! SKIP_NETWORK )); then
    if ! command -v ip >/dev/null 2>&1; then
      # iproute2 ปกติมากับทุก distro หลักอยู่แล้ว (Debian/RPi OS/Ubuntu/Fedora ฯลฯ) แต่ระบบ
      # ขั้นต่ำสุดบางแบบอาจยังไม่มีตอนนี้ -- ข้ามการตรวจอินเทอร์เฟซแทนที่จะทำให้สคริปต์ล้ม
      # ทั้งดุ้น (install_packages ขั้นตอนถัดไปจะติดตั้ง iproute2 ให้อยู่ดี)
      warn "ไม่พบคำสั่ง 'ip' (iproute2) — ข้ามการตรวจสอบอินเทอร์เฟซตอนนี้ จะติดตั้ง iproute2 ให้ในขั้นตอนถัดไป แล้วตรวจใหม่ตอนตั้งค่าเครือข่ายจริง"
    else
      local ifaces
      ifaces=$(ip -o link show 2>/dev/null | awk -F': ' '$2!="lo"{print $2}' | paste -sd' ' -)
      info "อินเทอร์เฟซที่พบ: ${ifaces:-<ไม่พบ>}"
      if [[ -n "$NIC" ]]; then
        ip link show "$NIC" >/dev/null 2>&1 || { err "ไม่พบอินเทอร์เฟซ '${NIC}'"; fail=1; }
      fi
    fi
    # โหมดสาย LAN เส้นเดียว (D17) -- ไม่มีการตรวจ WAN!=LAN อีกแล้ว เพราะตั้งใจใช้อินเทอร์เฟซเดียว
  fi

  if ! command -v ss >/dev/null 2>&1; then
    warn "ไม่พบคำสั่ง 'ss' (iproute2) — ข้ามการตรวจพอร์ตชนกันตอนนี้"
  fi
  # N24 (พบตอนรันซ้ำบน Pi จริง 2026-09-19): เดิมเจอใครใช้พอร์ตก็ FAIL ทันที รวมถึงบริการของเรา
  # เองจากการติดตั้งครั้งก่อน -> รันทับเพื่ออัปเดตเครื่องที่ติดตั้งแล้วไม่ได้เลย (ที่ยืนยันว่าผ่านใน
  # N15 คือการติดตั้งจากเครื่องเปล่า ไม่เคยทดสอบการรันทับ) ตอนนี้ถ้าเจ้าของพอร์ตเป็นบริการของเรา
  # (nginx/opennds/gunicorn) และมี secrets.env จากการติดตั้งเดิมอยู่ ถือเป็นการอัปเดต ขั้นตอน
  # ถัดไปจะรีสตาร์ทให้เอง -- ถ้าเป็นโปรแกรมอื่นแย่งพอร์ตยังต้อง FAIL เหมือนเดิม
  local owner
  for p in "$ADMIN_PORT" "$FAS_PORT" "$NDS_PORT" "$ADMIN_BACKEND" "$FAS_BACKEND"; do
    command -v ss >/dev/null 2>&1 || continue
    if ss -Hltn "sport = :${p}" 2>/dev/null | grep -q .; then
      owner="$(ss -Hltnp "sport = :${p}" 2>/dev/null | grep -oE 'users:\(\("[^"]+"' | head -1 | cut -d'"' -f2)"
      if [[ -f "${ETC_DIR}/secrets.env" && "$owner" =~ ^(nginx|opennds|gunicorn)$ ]]; then
        info "พอร์ต ${p} ใช้โดย ${owner} ของการติดตั้งเดิม — รันทับเพื่ออัปเดต จะรีสตาร์ทให้เอง"
      else
        err "พอร์ต ${p} ถูกใช้งานอยู่แล้ว${owner:+ (โดย ${owner})}"; fail=1
      fi
    fi
  done

  if command -v firewalld >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    warn "firewalld ทำงานอยู่ — อาจขัดกับ nftables rules ของระบบนี้"
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    warn "ufw ทำงานอยู่ — อาจขัดกับ nftables rules ของระบบนี้"
  fi

  (( fail )) && die "preflight ไม่ผ่าน — แก้ตามข้อความข้างบนแล้วรันใหม่"
  ok "preflight ผ่าน"
}

# ============================================================================
#  4. Wizard
# ============================================================================
guess_nic() {
  # เดาอินเทอร์เฟซที่มีอยู่จริงตัวแรก (ไม่นับ loopback/virtual) -- โหมดสายเดียวใช้อินเทอร์เฟซนี้
  # ทั้งคุยกับเราเตอร์และเป็น gateway ให้ลูกค้า
  local def_route
  def_route="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
  if [[ -n "$def_route" ]]; then echo "$def_route"; return 0; fi
  local i
  for i in $(ip -o link show 2>/dev/null | awk -F': ' '$2!="lo"{print $2}'); do
    case "$i" in docker*|br-*|veth*|virbr*|tailscale*) continue ;; esac
    echo "$i"; return 0
  done
}

wizard() {
  step "ตั้งค่าการติดตั้ง"
  local def_nic
  def_nic="${NIC:-$(guess_nic)}"

  if (( ! SKIP_NETWORK )); then
    ask NIC          "อินเทอร์เฟซเดียวที่ต่อไปเราเตอร์บ้าน (โหมดสาย LAN เส้นเดียว)" "${def_nic:-eth0}"
    ask UPLINK_CIDR  "IP ของ Pi ฝั่งเราเตอร์ (ใช้ออกเน็ต + SSH)"                    "$UPLINK_CIDR"
    ask UPLINK_GW    "IP ของเราเตอร์บ้าน (default route)"                          "$UPLINK_GW"
    ask CLIENT_CIDR  "IP ของ Pi ฝั่งลูกค้า (gateway/DHCP/DNS)"                     "$CLIENT_CIDR"
  fi
  ask GATEWAY_NAME       "ชื่อที่แสดงบนหน้า captive portal"        "$GATEWAY_NAME"
  ask ADMIN_PORT         "พอร์ต Admin Panel (HTTPS)"               "$ADMIN_PORT"
  ask FAS_PORT           "พอร์ต Captive Portal (HTTP)"             "$FAS_PORT"
  ask LOG_RETENTION_DAYS "เก็บ log กี่วันก่อนลบ (ขั้นต่ำ 90)"       "$LOG_RETENTION_DAYS"
  ADMIN_BACKEND=$((ADMIN_PORT+10000))
  FAS_BACKEND=$((FAS_PORT+10000))

  printf '\n  %sสรุปการติดตั้ง%s\n' "$C_BLU" "$C_RST"
  printf '  --------------------------------------------------\n'
  printf '    ระบบปฏิบัติการ  : %s\n' "$DISTRO_NAME"
  printf '    อินเทอร์เฟซ      : %s\n' "${NIC:-<ข้าม>}"
  printf '    Uplink (เราเตอร์) : %s  ผ่าน gw %s\n' "${UPLINK_CIDR:-<ข้าม>}" "${UPLINK_GW:-<ข้าม>}"
  printf '    Client gateway   : %s\n' "$CLIENT_CIDR"
  printf '    DHCP pool       : %s - %s\n' "$DHCP_START" "$DHCP_END"
  printf '    ชื่อ portal      : %s\n' "$GATEWAY_NAME"
  printf '    Admin Panel     : https  port %s\n' "$ADMIN_PORT"
  printf '    Captive Portal  : http   port %s\n' "$FAS_PORT"
  printf '    เก็บ log        : %s วัน\n' "$LOG_RETENTION_DAYS"
  printf '    ติดตั้งไปที่     : %s , %s , %s\n' "$OPT_DIR" "$ETC_DIR" "$LOG_DIR"
  printf '  --------------------------------------------------\n\n'
  confirm "เริ่มติดตั้ง" || die "ยกเลิกโดยผู้ใช้"
}

# ============================================================================
#  5. ขั้นตอนติดตั้ง
# ============================================================================
create_user_and_dirs() {
  step "สร้างผู้ใช้ระบบและไดเรกทอรี"
  if ! id -u "$APP_USER" >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
      run useradd --system --home-dir "$OPT_DIR" --shell /usr/sbin/nologin "$APP_USER"
    else
      run adduser -S -H -h "$OPT_DIR" -s /sbin/nologin "$APP_USER"
    fi
    ok "สร้างผู้ใช้ ${APP_USER}"
  else
    info "ผู้ใช้ ${APP_USER} มีอยู่แล้ว"
  fi
  run install -d -m 0755 -o root        -g root        "$OPT_DIR"
  run install -d -m 0750 -o root        -g "$APP_USER" "$ETC_DIR"
  run install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$LOG_DIR"
  run install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "${LOG_DIR}/archive"
  run install -d -m 0750 -o root        -g "$APP_USER" "$BACKUP_DIR"  # แก้บั๊ก H4
  ok "ไดเรกทอรีพร้อม"
}

gen_secrets() {
  step "สร้างกุญแจเข้ารหัส (secrets)"
  local secrets="${ETC_DIR}/secrets.env"
  if [[ -f "$secrets" ]] && (( ! DRY_RUN )); then
    warn "พบ ${secrets} อยู่แล้ว — ใช้ของเดิม (สร้างใหม่จะทำให้ข้อมูลเดิมถอดรหัสไม่ได้)"
    # N27: กุญแจเข้ารหัสต้องคงเดิม แต่ค่าเครือข่ายต้องตามพารามิเตอร์ของรอบนี้เสมอ --
    # เดิมไฟล์นี้ถูกเขียนครั้งเดียวตอนติดตั้งครั้งแรก พอย้าย Pi ไปเครือข่ายใหม่ (แล็บ <-> บ้าน) แล้ว
    # รันซ้ำด้วย --uplink-cidr/--uplink-gw ใหม่ ไฟร์วอลล์กับ IP ถูกอัปเดตแต่ค่าในนี้ไม่ถูก
    # bypass_detector.py (ตัวเดียวที่อ่านค่าเหล่านี้) จึงไปเฝ้าวงเก่าต่อแล้วเงียบไปโดยไม่มีใครรู้
    local kv key
    for kv in "UPLINK_IP=${UPLINK_CIDR%%/*}" "UPLINK_GW=${UPLINK_GW}" \
              "UPLINK_NETWORK=$(cidr_to_network "$UPLINK_CIDR")" \
              "GATEWAY_IP=${CLIENT_CIDR%%/*}" "CLIENT_CIDR=${CLIENT_CIDR}" \
              "ADMIN_URL=https://cafe.wifi:${ADMIN_PORT}/login" \
              "OFFSITE_BACKUP_DIR=${BACKUP_USB_MNT}/${APP_NAME}" "OFFSITE_REQUIRE_SEPARATE_DEVICE=1"; do
      key="${kv%%=*}"
      if grep -q "^${key}=" "$secrets"; then
        sed -i "s|^${key}=.*|${kv}|" "$secrets"
      else
        printf '%s\n' "$kv" >> "$secrets"
      fi
    done
    ok "อัปเดตค่าเครือข่ายใน ${secrets} ให้ตรงกับรอบนี้แล้ว (uplink ${UPLINK_CIDR}, client ${CLIENT_CIDR})"
    return 0
  fi
  [[ -z "$DB_PASS" ]] && DB_PASS="$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 28)"
  local pepper dek flask faskey setup_token
  pepper="$(openssl rand -hex 32)"
  dek="$(openssl rand -hex 32)"
  flask="$(openssl rand -hex 32)"
  faskey="$(openssl rand -hex 16)"
  setup_token="$(openssl rand -hex 24)"

  write_file "$secrets" 0640 "root:${APP_USER}" <<SECRETS
# ============================================================
#  ${APP_NAME} secrets  --  ห้าม commit ไฟล์นี้เข้า Git เด็ดขาด
#  สร้างเมื่อ: $(date -Iseconds)
# ------------------------------------------------------------
#  ถ้าไฟล์นี้หาย: เลขบัตรประชาชนที่เข้ารหัสไว้จะถอดกลับไม่ได้อีก
#  -> สำรองไฟล์นี้ไว้นอกเครื่อง ในที่ที่ปลอดภัย
# ============================================================
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}

# HMAC pepper สำหรับ hash เลขบัตรประชาชน (ใช้ค้นหา/กันซ้ำ)
NATID_PEPPER=${pepper}
# Data Encryption Key สำหรับ AES-256-GCM (เก็บเลขบัตรแบบถอดกลับได้ตามหมายศาล)
NATID_DEK=${dek}
# Flask session secret
SECRET_KEY=${flask}
# openNDS FAS shared key (fas_secure_enabled = 2)
FAS_KEY=${faskey}

FAS_PORT=${FAS_BACKEND}
ADMIN_PORT=${ADMIN_BACKEND}
NDS_PORT=${NDS_PORT}
GATEWAY_NAME=${GATEWAY_NAME}
GATEWAY_IP=${CLIENT_CIDR%%/*}
CLIENT_CIDR=${CLIENT_CIDR}
GATEWAY_AUTHDIR=opennds_auth
# ปุ่ม "สำหรับแอดมิน/พนักงาน" บนหน้า portal -- ชื่อ cafe.wifi ชี้มาที่ Pi ผ่าน dnsmasq และอยู่ใน SAN ของใบรับรอง
ADMIN_URL=https://cafe.wifi:${ADMIN_PORT}/login

# N10 (CODING_BRIEF.md) -- bypass_detector.py (T17) ใช้ 3 ค่านี้เฝ้าวง uplink หา IP/MAC
# แปลกปลอมที่ไม่ใช่ Pi เองหรือเราเตอร์ (ดู D19/§3.1.4) -- ก่อนหน้านี้ UPLINK_CIDR/UPLINK_GW
# เป็นตัวแปรฝั่ง shell ของ install.sh ล้วน ๆ ไม่เคยถูกส่งต่อให้ฝั่ง Python เลย
UPLINK_IP=${UPLINK_CIDR%%/*}
UPLINK_GW=${UPLINK_GW}
UPLINK_NETWORK=$(cidr_to_network "$UPLINK_CIDR")
ETC_DIR=${ETC_DIR}
LOG_DIR=${LOG_DIR}
LOG_RETENTION_DAYS=${LOG_RETENTION_DAYS}
BACKUP_DIR=${BACKUP_DIR}
BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS}
# สำรองออกนอก SD card: USB ที่ label = ${BACKUP_USB_LABEL} (ดู configure_backup_usb) -- ไม่เสียบก็ไม่พัง
# แค่หน้าสถานะเตือน · REQUIRE_SEPARATE_DEVICE กันกรณีไม่ได้เสียบแล้วไฟล์ไปลง SD ใบเดิมเงียบ ๆ
OFFSITE_BACKUP_DIR=${BACKUP_USB_MNT}/${APP_NAME}
OFFSITE_REQUIRE_SEPARATE_DEVICE=1
SECRETS

  write_file "${ETC_DIR}/setup.token" 0640 "root:${APP_USER}" <<TOKEN
${setup_token}
TOKEN

  ok "สร้าง secrets แล้ว: ${secrets} (mode 0640)"
  warn "สำรอง ${secrets} ไว้ที่อื่นด้วย — ถ้าหาย ข้อมูลที่เข้ารหัสไว้จะกู้ไม่ได้"
}

install_packages() {
  step "ติดตั้งแพ็กเกจของระบบ"
  pkg_refresh
  local pkgs=(python buildtools git curl openssl mariadb nginx chrony iproute)
  (( SKIP_NETWORK )) || pkgs+=(dnsmasq nftables conntrack tcpdump)
  (( SKIP_OPENNDS )) || pkgs+=(microhttpd php)
  # Pi ไม่มี RTC: ถ้าไม่มีตัวนี้ systemd เริ่มนาฬิกาทุกบูตจาก mtime ของ
  # /var/lib/systemd/timesync/clock ซึ่ง chrony ไม่เคยแตะ (บน Pi จริงค้างที่ 2026-09-16 14:20 ทุกบูต
  # จนถึง 2 ต.ค. -- ผิดไป 16 วัน) fake-hwclock บันทึกเวลาทุกชั่วโมง + ตอนปิดเครื่อง แล้วคืนตอนบูต
  # ถ้า NTP ไม่มาภายในเพดาน 180 วิ ของ chrony-wait (N23) log จะผิดแค่เท่ากับเวลาที่ไฟดับ ไม่ใช่หลายวัน
  [[ "$PKG" == apt ]] && pkgs+=(fake-hwclock)
  pkg_install "${pkgs[@]}"
  ok "ติดตั้งแพ็กเกจเสร็จ"
}

setup_python() {
  step "สร้าง Python virtualenv"
  run_sh "python3 -m venv '${VENV_DIR}'"
  run_sh "'${VENV_DIR}/bin/pip' install --quiet --upgrade pip wheel setuptools"
  local req="${SCRIPT_DIR}/app/requirements.txt"
  if [[ -f "$req" ]]; then
    run_sh "'${VENV_DIR}/bin/pip' install --quiet -r '${req}'"
  else
    # แก้บั๊ก (N8, CODING_BRIEF.md): รายชื่อ fallback นี้เคยหลุดไม่ตรงกับ requirements.txt จริง
    # มาก่อนแล้ว (ไม่มี qrcode ที่ N7 เพิ่งเพิ่ม) -- ถือโอกาสซิงค์ให้ตรงพร้อมกันตอนถอด pyotp
    # ออก (2FA ตัดสินใจไม่ทำ ดู sql/006_drop_totp.sql) ไม่งั้นเครื่องที่ไม่มี requirements.txt
    # (กรณีสำรองเท่านั้น ปกติมีเสมอ) จะติดตั้งแพ็กเกจไม่ครบ/เกินความจำเป็นแบบเงียบ ๆ
    run_sh "'${VENV_DIR}/bin/pip' install --quiet Flask gunicorn PyMySQL cryptography argon2-cffi"
  fi
  ok "Python environment พร้อม (${VENV_DIR})"
}

install_app_files() {
  step "คัดลอกไฟล์แอปพลิเคชัน"
  if [[ -d "${SCRIPT_DIR}/app" ]]; then
    run_sh "cp -a '${SCRIPT_DIR}/app/.' '${OPT_DIR}/'"
    ok "คัดลอก app/ -> ${OPT_DIR}"
  else
    warn "ไม่พบโฟลเดอร์ app/ ข้าง install.sh — ข้ามขั้นตอนนี้"
  fi
  [[ -d "${SCRIPT_DIR}/sql" ]]   && run_sh "cp -a '${SCRIPT_DIR}/sql'   '${OPT_DIR}/'"
  [[ -d "${SCRIPT_DIR}/tools" ]] && run_sh "cp -a '${SCRIPT_DIR}/tools' '${OPT_DIR}/'"
  [[ -d "${SCRIPT_DIR}/docs" ]]  && run_sh "cp -a '${SCRIPT_DIR}/docs'  '${OPT_DIR}/'"
  run_sh "chown -R root:'${APP_USER}' '${OPT_DIR}'"
  run_sh "find '${OPT_DIR}' -type d -exec chmod 0755 {} + 2>/dev/null || true"
  return 0
}

setup_database() {
  step "ตั้งค่าฐานข้อมูล MariaDB"
  local dbsvc="mariadb"
  if [[ "$INIT_SYS" == systemd ]] && systemctl list-unit-files 2>/dev/null | grep -q '^mysqld\.service'; then
    dbsvc="mysqld"
  fi

  # Alpine / distro ที่ต้อง init data dir ก่อน
  if [[ ! -d /var/lib/mysql/mysql ]] && command -v mariadb-install-db >/dev/null 2>&1; then
    run_sh "mariadb-install-db --user=mysql --datadir=/var/lib/mysql >/dev/null 2>&1 || true"
  fi
  svc enable "$dbsvc"

  if (( ! DRY_RUN )); then
    local i
    for i in $(seq 1 30); do mysqladmin ping >/dev/null 2>&1 && break; sleep 1; done
    mysqladmin ping >/dev/null 2>&1 || die "MariaDB ไม่ตอบสนองภายใน 30 วินาที"
    DB_PASS="$(grep -E '^DB_PASS=' "${ETC_DIR}/secrets.env" | cut -d= -f2-)"
  fi

  # แก้บั๊ก (พบตอนตรวจทานรอบ 2): เดิม GRANT ALL PRIVILEGES ให้ user ของแอป ทำให้ทั้ง
  # Flask apps และ tools/*.py มีสิทธิ์ DROP/ALTER ตารางหลักฐานได้โดยไม่จำเป็น -- ไม่มีจุดไหน
  # ในโค้ดรัน DDL ผ่าน user นี้เลย (schema โหลดครั้งเดียวตอนติดตั้งผ่าน root/socket auth
  # ด้านล่าง ไม่ใช่ DB_USER) จำกัดให้เหลือแค่สิทธิ์ที่ใช้จริง (SELECT/INSERT/UPDATE/DELETE)
  if (( DRY_RUN )); then
    printf '%s      $ สร้าง database %s + user %s%s\n' "$C_DIM" "$DB_NAME" "$DB_USER" "$C_RST"
  else
    mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${DB_NAME}\`.* TO '${DB_USER}'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL
  fi
  ok "database '${DB_NAME}' + user '${DB_USER}' พร้อม"

  local schema="${SCRIPT_DIR}/sql/001_schema.sql"
  if [[ -f "$schema" ]]; then
    run_sh "mysql '${DB_NAME}' < '${schema}'"
    ok "โหลด schema แล้ว"
  else
    warn "ไม่พบ sql/001_schema.sql — ต้องโหลด schema เอง"
  fi

  # N10 (CODING_BRIEF.md): ตาราง bypass_alert สำหรับ logger/bypass_detector.py (T17) --
  # 001_schema.sql apply ไปแล้วแก้ตรง ๆ ไม่ได้ (§5) จึงเพิ่มตารางใหม่ผ่าน migration แทน
  # ใช้ CREATE TABLE IF NOT EXISTS รันซ้ำได้เสมอ ไม่ใช่ opt-in เหมือน partitions เพราะเป็นแค่
  # ตารางใหม่เปล่า ๆ ไม่กระทบ/ล็อกตารางเดิมที่มีข้อมูลอยู่แล้ว
  local bypasssql="${SCRIPT_DIR}/sql/005_bypass_alert.sql"
  if [[ -f "$bypasssql" ]]; then
    run_sh "mysql '${DB_NAME}' < '${bypasssql}'"
    ok "สร้างตาราง bypass_alert แล้ว (N10 -- T17)"
  else
    warn "ไม่พบ sql/005_bypass_alert.sql — ข้าม (logger/bypass_detector.py จะบันทึกผลไม่ได้จนกว่าจะมีตารางนี้)"
  fi

  # N8 (CODING_BRIEF.md): ตัดสินใจถอด 2FA (TOTP) ออก เพราะ pyotp ค้างใน requirements.txt
  # มาตั้งแต่แรกโดยไม่มีไฟล์ไหน import เลยสักบรรทัด (ดู R8 ใน §13 ที่บอกไว้แล้วว่าตัด Phase 5
  # ได้) -- 001_schema.sql apply ไปแล้วแก้ตรง ๆ ไม่ได้ (§5 กติกา) ต้องลบคอลัมน์ totp_secret
  # ผ่าน migration ใหม่แทน -- ใช้ได้ไม่ว่าเครื่องใหม่หรือเครื่องที่เคย apply schema เก่าไปแล้ว
  local droptotp="${SCRIPT_DIR}/sql/006_drop_totp.sql"
  if [[ -f "$droptotp" ]]; then
    run_sh "mysql '${DB_NAME}' < '${droptotp}'"
    ok "ถอดคอลัมน์ staff.totp_secret แล้ว (N8 -- 2FA ตัดสินใจไม่ทำ)"
  else
    warn "ไม่พบ sql/006_drop_totp.sql — ข้าม (staff.totp_secret จะยังค้างอยู่ในสคีมาเฉย ๆ ไม่กระทบการทำงาน)"
  fi

  # R2-02: conn_log.started_at -- เวลาเริ่ม connection (ts เดิมคือเวลาจบ) ใช้จับคู่ว่าใครเปิด
  # connection นั้น ต้องมีก่อน cafe-logger เริ่ม เพราะ conn_collector.py INSERT คอลัมน์นี้เสมอ
  local connstart="${SCRIPT_DIR}/sql/007_conn_log_started_at.sql"
  if [[ -f "$connstart" ]]; then
    run_sh "mysql '${DB_NAME}' < '${connstart}'"
    ok "เพิ่มคอลัมน์ conn_log.started_at แล้ว (R2-02)"
  else
    die "ไม่พบ sql/007_conn_log_started_at.sql — cafe-logger จะเขียน conn_log ไม่ได้ถ้าไม่มีคอลัมน์นี้"
  fi

  # คอลัมน์/ตารางของรีวิวรอบ 2 (pending session, FAS nonce, dns answer, การลบ archive) -- เคยแก้ไว้ใน
  # 001_schema.sql อย่างเดียว ซึ่งเป็น CREATE TABLE IF NOT EXISTS เครื่องที่ติดตั้งไว้แล้วจึงไม่ได้
  # คอลัมน์ใหม่ แล้ว FAS พังตอน login + dns_log เขียนไม่ได้ (หลักฐานหาย) -- ไฟล์นี้รันซ้ำได้เสมอ
  local r2cols="${SCRIPT_DIR}/sql/008_pending_sessions_and_log_columns.sql"
  if [[ -f "$r2cols" ]]; then
    run_sh "mysql '${DB_NAME}' < '${r2cols}'"
    ok "อัปเดตสคีมา pending session / dns_log / log_manifest แล้ว (R2)"
  else
    die "ไม่พบ sql/008_pending_sessions_and_log_columns.sql — FAS และ cafe-logger ต้องใช้คอลัมน์ในไฟล์นี้"
  fi

  # หน้า /staff (บัญชีพนักงานรายคน): บังคับเปลี่ยนรหัสชั่วคราว + เปลี่ยนรหัสแล้ว session เดิมหลุด
  local staffpw="${SCRIPT_DIR}/sql/009_staff_password_lifecycle.sql"
  if [[ -f "$staffpw" ]]; then
    run_sh "mysql '${DB_NAME}' < '${staffpw}'"
    ok "อัปเดตสคีมาบัญชีพนักงานแล้ว"
  else
    die "ไม่พบ sql/009_staff_password_lifecycle.sql — Admin Panel ต้องใช้คอลัมน์ในไฟล์นี้"
  fi

  # ลูกค้าขอใช้งานบน portal แล้วพนักงานอนุมัติ (แทนสลิปรหัสผ่าน)
  local accessreq="${SCRIPT_DIR}/sql/010_access_request.sql"
  if [[ -f "$accessreq" ]]; then
    run_sh "mysql '${DB_NAME}' < '${accessreq}'"
    ok "สร้างตารางคำขอใช้งานแล้ว"
  else
    die "ไม่พบ sql/010_access_request.sql — portal และหน้าอนุมัติต้องใช้ตารางนี้"
  fi

  # ปุ่มต่อเวลา: ธงให้ cafe-reconcile ต่อเวลาที่ openNDS
  local extend="${SCRIPT_DIR}/sql/012_voucher_extend.sql"
  if [[ -f "$extend" ]]; then
    run_sh "mysql '${DB_NAME}' < '${extend}'"
    ok "เพิ่มคอลัมน์สำหรับต่อเวลาแล้ว"
  else
    die "ไม่พบ sql/012_voucher_extend.sql — ปุ่มต่อเวลาต้องใช้คอลัมน์ในไฟล์นี้"
  fi

  # ชื่อเครื่อง + ระบบปฏิบัติการของลูกค้า
  local devinfo="${SCRIPT_DIR}/sql/011_device_info.sql"
  if [[ -f "$devinfo" ]]; then
    run_sh "mysql '${DB_NAME}' < '${devinfo}'"
    ok "เพิ่มคอลัมน์ชื่อเครื่อง/ระบบปฏิบัติการแล้ว"
  else
    die "ไม่พบ sql/011_device_info.sql — portal และหน้าอนุมัติต้องใช้คอลัมน์ในไฟล์นี้"
  fi


  # แก้บั๊ก (พบตอนตรวจทานรอบ 2): sql/003_partitions.sql มีอยู่ในโปรเจกต์และ Task Board
  # ติ๊กว่าเขียนแล้ว แต่ install.sh ไม่เคยเรียกใช้ไฟล์นี้เลยสักบรรทัด -- เป็น optional
  # ตามที่ comment ในไฟล์บอกไว้ (ไม่มีก็ทำงานถูกต้อง แค่ purge ช้ากว่าเมื่อข้อมูลเยอะมาก)
  # จึงทำเป็น opt-in ผ่าน --enable-partitions แทนที่จะบังคับ ALTER TABLE บนทุกเครื่อง
  # (partition ตารางที่มีข้อมูลอยู่แล้วอาจช้า/ล็อกตารางได้ ไม่ควรทำเงียบ ๆ โดยไม่ให้เลือก)
  if (( ENABLE_PARTITIONS )); then
    local partsql="${SCRIPT_DIR}/sql/003_partitions.sql"
    if [[ -f "$partsql" ]]; then
      run_sh "mysql '${DB_NAME}' < '${partsql}'"
      # ไฟล์ .sql เขียน retention_days=180 ตายตัวไว้ในนิยาม event -- ผูกกับ
      # LOG_RETENTION_DAYS จริงที่ผู้ติดตั้งตั้งไว้แทน (แก้บั๊ก M4 เดิม เลข 180 ไม่ตรงกับ
      # ค่าที่ตั้งจริงถ้าไม่ใช่ default)
      run_sh "mysql '${DB_NAME}' -e \"ALTER EVENT cafewifi_daily_partition_maintenance ON SCHEDULE EVERY 1 DAY STARTS (CURRENT_DATE + INTERVAL 1 DAY + INTERVAL 3 HOUR) DO CALL cafewifi_partition_maintenance(${LOG_RETENTION_DAYS});\""
      run_sh "mysql -e 'SET GLOBAL event_scheduler = ON;'"
      ok "เปิด partition รายสัปดาห์ + event scheduler แล้ว (retention ${LOG_RETENTION_DAYS} วัน)"
      warn "หมายเหตุ: tools/backup_db.py ไม่ได้ backup event/procedure พวกนี้ (ตั้งใจ ดู"
      warn "  docstring ในไฟล์นั้น) ถ้า restore DB ใหม่ ต้องรัน sql/003_partitions.sql ซ้ำเองด้วย"
    else
      warn "ระบุ --enable-partitions แต่ไม่พบ sql/003_partitions.sql"
    fi
  else
    info "ข้าม sql/003_partitions.sql (optional — เปิดด้วย --enable-partitions ถ้าต้องการ)"
  fi

  local cnf_dir=""
  for d in /etc/mysql/mariadb.conf.d /etc/my.cnf.d /etc/mysql/conf.d; do
    [[ -d "$d" ]] && { cnf_dir="$d"; break; }
  done
  if [[ -n "$cnf_dir" ]]; then
    {
      echo "[mysqld]"
      echo "bind-address                   = 127.0.0.1"
      echo "innodb_buffer_pool_size        = 256M"
      echo "innodb_log_file_size           = 64M"
      echo "# ทนไฟดับ -- สำคัญมากเมื่อรันบน SD card"
      echo "innodb_flush_log_at_trx_commit = 1"
      echo "innodb_flush_method            = O_DIRECT"
      echo "max_connections                = 64"
      # แก้บั๊ก (พบตอนตรวจทานรอบ 2): SET GLOBAL event_scheduler ที่ตั้งตอน --enable-partitions
      # มีผลแค่ session ปัจจุบัน หายไปเมื่อ MariaDB restart -- ต้องตั้งถาวรในไฟล์ config ด้วย
      if (( ENABLE_PARTITIONS )); then
        echo "event_scheduler                = ON"
      fi
    } | write_file "${cnf_dir}/99-${APP_NAME}.cnf" 0644
    svc restart "$dbsvc"
    ok "ปรับแต่ง MariaDB (${cnf_dir}/99-${APP_NAME}.cnf)"
  fi
}

configure_time() {
  step "ตั้งค่านาฬิกา (chrony) — กฎหมายกำหนดคลาดเคลื่อนไม่เกิน 10 ms"
  local conf=/etc/chrony/chrony.conf s marker="# --- ${APP_NAME} installer (ต่อท้าย, ไม่ลบของเดิม) ---"
  [[ -f /etc/chrony.conf ]] && conf=/etc/chrony.conf

  # แก้บั๊ก (พบตอนตรวจทานรอบ 2 — และแก้ผิดไปรอบหนึ่งแล้วด้วยระหว่างพยายามแก้บั๊กนี้):
  #   เดิมเขียนทับ chrony.conf ทั้งไฟล์ ลบค่า default ของ distro ทิ้งหมด (เช่น Raspberry
  #   Pi OS ใส่ `confdir /etc/chrony/conf.d`, `sourcedir /run/chrony-dhcp` ไว้ให้แล้ว)
  #   รอบแรกที่ลองแก้ ใช้วิธีเขียนไฟล์ลง conf.d/ ถ้าเจอโฟลเดอร์นั้น -- แต่พบว่าไม่ปลอดภัย
  #   พอ ๆ กัน: เจอโฟลเดอร์ conf.d อยู่จริง ไม่ได้แปลว่า chrony.conf มีบรรทัด `confdir`/
  #   `include` ชี้มาที่มันจริง (เดายืนยันไม่ได้ในสคริปต์ติดตั้งที่ไม่รู้จักทุก distro
  #   ล่วงหน้า) ถ้าเดาผิด ไฟล์ที่เขียนไปจะไม่ถูกอ่านเลย แล้ว NTP server ที่ตั้งใจเพิ่มก็จะ
  #   ไม่มีผลอะไรทั้งที่ควรมี -- แก้ให้ถูกจริง ๆ ด้วยการ "ต่อท้าย" ไฟล์ที่ยืนยันแล้วว่า
  #   chrony อ่านแน่ ๆ (คือ $conf เอง) แทน โดยเช็ค marker กันการต่อท้ายซ้ำเวลารัน
  #   install.sh ซ้ำ ไม่แตะบรรทัดเดิมที่มีอยู่ก่อนเลยสักบรรทัด
  if [[ -f "$conf" ]] && grep -qF "$marker" "$conf" 2>/dev/null; then
    info "ตั้งค่า chrony ไว้แล้ว (เจอ marker ใน ${conf}) — ข้าม"
  else
    # ห้ามทำ `cat "$conf" | write_file "$conf"` (source กับ destination เป็นไฟล์เดียวกัน)
    # เพราะ pipeline รันทุก stage พร้อมกัน -- ฝั่งเขียนจะ truncate ไฟล์ก่อนฝั่งอ่านอ่านจบ
    # ได้ (เจอจริงจากการทดสอบ: เนื้อหาเดิมหายเกือบทุกรอบ เหลือแต่ที่ต่อท้ายอย่างเดียว)
    # ต้องอ่านให้จบเป็นตัวแปรก่อน (command substitution บล็อกจนอ่านเสร็จ) แล้วค่อยเขียนทับ
    local old_content=""
    [[ -f "$conf" ]] && old_content="$(cat "$conf")"
    {
      [[ -n "$old_content" ]] && printf '%s\n' "$old_content"
      echo ""
      echo "$marker"
      for s in $NTP_SERVERS; do echo "server ${s} iburst"; done
      echo "makestep 1.0 3"
    } | write_file "$conf" 0644
    ok "เพิ่ม NTP server ต่อท้าย ${conf} แล้ว (ไม่ลบค่า default เดิมของ distro)"
  fi

  svc enable chronyd 2>/dev/null || svc enable chrony 2>/dev/null || warn "เปิด chrony อัตโนมัติไม่สำเร็จ"

  # *** N23 (พบจากการทดสอบไฟดับบน Pi จริง 2026-09-19) *** Pi 4 ไม่มีนาฬิกา RTC ตอนบูตนาฬิกา
  # เริ่มจากเวลาเก่าที่บันทึกไว้ (รอบนั้นผิดไป 2.98 วัน) แล้วค่อยกระโดดเมื่อ chrony sync ได้
  # ซึ่งเกิดช้ากว่า openNDS พร้อมรับลูกค้าถึง ~106 วินาที -- ระหว่างนั้นลูกค้า login และใช้เน็ต
  # ได้แล้ว แต่ log ทุกแถวติดวันที่ผิด ปนกับข้อมูลจริงของวันนั้นจนแยกไม่ออก (ขัด ม.26 ตรง ๆ)
  # chrony-wait.service (มากับแพ็กเกจ chrony อยู่แล้ว แต่ปิดไว้โดย default) จะกั้น
  # time-sync.target ไว้จนกว่านาฬิกาจะ sync -- openNDS/cafe-logger ผูก After=time-sync.target
  # ไว้ (ดู drop-in ข้างล่างและ unit ของ cafe-logger) จึงไม่มีลูกค้าออกเน็ตได้ตอนนาฬิกายังผิด
  # มีเพดาน TimeoutStartSec=180 ของตัว unit เอง: ถ้า NTP ไม่มาภายใน 3 นาที unit จะ fail แต่
  # time-sync.target ยังถูกนับว่าถึงแล้ว (เป็นแค่ Wants) ร้านจึงไม่ล่มยาวเพราะเน็ตมีปัญหา
  if systemctl cat chrony-wait.service >/dev/null 2>&1; then
    svc enable chrony-wait 2>/dev/null || warn "เปิด chrony-wait ไม่สำเร็จ -- หลังไฟดับลูกค้าอาจใช้เน็ตได้ก่อนนาฬิกาถูก"
  else
    warn "ไม่พบ chrony-wait.service -- หลังไฟดับลูกค้าอาจใช้เน็ตได้ก่อนนาฬิกา sync (log จะติดเวลาผิด)"
  fi

  # แก้บั๊ก (พบตอนตรวจทานรอบ 2) 2 จุดพร้อมกันเพราะเป็นสาเหตุ-ผลกันตรง ๆ:
  #   (1) เดิมมี `set -e` ครอบทั้งสคริปต์ แต่ chronyc ล้มได้ (เช่น chronyd ยังไม่พร้อม) และ
  #       pipefail ทำให้ทั้ง pipeline คืน exit code ที่ไม่ใช่ 0 -- ตัวแปร `off="$(...)"`
  #       assignment ที่ fail จะทำให้ `set -e` ฆ่าสคริปต์ทันที "ก่อน" ถึงบรรทัด printf เลย
  #       แปลว่า fallback ${off:-unknown} เป็นโค้ดตาย ไม่มีทางถูกรันจริง -- ต้องเอา `-e` ออก
  #   (2) เดิมวัดค่าอย่างเดียว ไม่เคยแจ้งเตือนเลยแม้นาฬิกาจะเพี้ยนเกิน 10ms ตามที่กฎหมาย
  #       กำหนด (หรืออ่านค่าไม่ได้เลย) -- เพิ่ม log แจ้งเตือนแยกต่างหากเมื่อเกินเกณฑ์
  write_file "${OPT_DIR}/check_time.sh" 0755 <<'TIMECHK'
#!/usr/bin/env bash
# บันทึกความคลาดเคลื่อนของนาฬิกาเป็นหลักฐานตาม พ.ร.บ.คอมพิวเตอร์ ม.26 (ต้อง < 10 ms)
set -uo pipefail
LOG_DIR="${LOG_DIR:-/var/log/cafe-wifi}"
LOG="${LOG_DIR}/time-accuracy.log"
ALERT_LOG="${LOG_DIR}/time-accuracy-alerts.log"

# ไม่ใส่ -e ตรงนี้โดยตั้งใจ: chronyc ล้มได้ (เช่น chronyd ยังไม่พร้อมตอนบูต) ต้องให้สคริปต์
# รันต่อจนถึง printf เพื่อบันทึก "unknown" ไว้เป็นหลักฐานว่าตรวจไม่ได้ ไม่ใช่เงียบหายไปเฉย ๆ
off="$(chronyc tracking 2>/dev/null | awk -F': *' '/System time/{print $2}')"
off="${off:-unknown}"
printf '%s  %s\n' "$(date -Iseconds)" "$off" >> "$LOG"

if [[ "$off" == "unknown" ]]; then
  printf '%s  WARN: อ่านค่า chronyc ไม่ได้ -- ตรวจว่า chronyd ทำงานอยู่ (chronyc tracking)\n' \
    "$(date -Iseconds)" >> "$ALERT_LOG"
else
  # off มีรูปแบบ "0.000123456 seconds slow of NTP time" (chronyc ไม่ใส่เครื่องหมาย +/-
  # เอง ใช้คำว่า slow/fast แทน) เอาแค่ตัวเลขวินาทีไปคูณ 1000 หาหน่วย ms
  secs="${off%% *}"
  ms="$(awk -v s="$secs" 'BEGIN{printf "%.3f", (s+0)*1000}' 2>/dev/null || echo "")"
  if [[ -n "$ms" ]] && awk -v m="$ms" 'BEGIN{exit !(m>10)}'; then
    printf '%s  WARN: นาฬิกาคลาดเคลื่อน %s ms (เกิน 10ms ตามที่กฎหมายกำหนด)\n' \
      "$(date -Iseconds)" "$ms" >> "$ALERT_LOG"
  fi
fi
TIMECHK

  # แก้บั๊ก (พบตอนตรวจทานรอบ 4): cafe-maintenance.service ไม่มี User= (รันเป็น root) แต่
  # logrotate ตั้ง `create 0640 ${APP_USER} ${APP_USER}` ไว้สำหรับไฟล์ที่หมุนใหม่ -- ถ้าไม่
  # สร้างไฟล์นี้ไว้ล่วงหน้าด้วย owner ที่ถูกต้องตั้งแต่แรก ไฟล์แรกสุด (ก่อน logrotate รอบแรก)
  # จะเป็น root:root mode ตาม umask ปกติ ไม่ตรงกับไฟล์ที่หมุนแล้วซึ่งเป็น cafewifi:cafewifi
  # -- touch+chown ไว้ล่วงหน้าเหมือนที่ทำกับ dnsmasq.log ให้ owner สม่ำเสมอตั้งแต่ไฟล์แรก
  run_sh "touch '${LOG_DIR}/time-accuracy.log' '${LOG_DIR}/time-accuracy-alerts.log'"
  run_sh "chown '${APP_USER}:${APP_USER}' '${LOG_DIR}/time-accuracy.log' '${LOG_DIR}/time-accuracy-alerts.log'"
  run_sh "chmod 0640 '${LOG_DIR}/time-accuracy.log' '${LOG_DIR}/time-accuracy-alerts.log'"
  ok "chrony พร้อม — ตรวจด้วย: chronyc tracking"
}

# cidr_to_network <ip/prefix>  ->  พิมพ์ "network/prefix" เช่น 10.10.0.1/24 -> 10.10.0.0/24
# ใช้คำนวณ subnet ของ nftables โดยไม่ต้องพึ่ง ipcalc (ไม่มีติดมากับทุก distro)
cidr_to_network() {
  local cidr="$1" ip prefix a b c d mask ip_int net_int
  ip="${cidr%%/*}"; prefix="${cidr##*/}"
  IFS='.' read -r a b c d <<< "$ip"
  ip_int=$(( (a<<24) + (b<<16) + (c<<8) + d ))
  if (( prefix == 0 )); then mask=0; else mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF )); fi
  net_int=$(( ip_int & mask ))
  printf '%d.%d.%d.%d/%d' $(( (net_int>>24)&255 )) $(( (net_int>>16)&255 )) $(( (net_int>>8)&255 )) $(( net_int&255 )) "$prefix"
}

ensure_uplink_before_packages() {
  # N37 (พบตอนย้าย Pi จากเครือข่ายแล็บไปต่อเราเตอร์ TP-Link จริง 2026-09-20):
  # install.sh ตั้งค่าเครือข่าย *หลัง* ติดตั้งแพ็กเกจ ซึ่งใช้ได้กับการติดตั้งครั้งแรกบนเครื่องที่
  # ต่อเน็ตอยู่แล้ว แต่พอ **ย้ายเครื่องไปเครือข่ายใหม่** แล้วรันซ้ำด้วย --uplink-cidr ใหม่
  # เครื่องยังใช้ default route เก่าที่ใช้ไม่ได้แล้ว -> apt/pip ค้างลองใหม่ซ้ำ ๆ หลายนาที
  # (preflight เตือนว่า "ตรวจอินเทอร์เน็ตไม่ผ่าน" แต่ไม่ได้หยุดหรือแก้ให้)
  #
  # ตั้ง IP + default route ของ uplink ให้ก่อน **เฉพาะเมื่อเน็ตใช้ไม่ได้จริง ๆ เท่านั้น**
  # ถ้าเน็ตใช้ได้อยู่แล้วจะไม่แตะอะไรเลย เพื่อไม่ไปตัดการเชื่อมต่อที่กำลังทำงานอยู่
  (( SKIP_NETWORK )) && return 0
  [[ -z "$NIC" || -z "$UPLINK_CIDR" || -z "$UPLINK_GW" ]] && return 0
  command -v curl >/dev/null 2>&1 || return 0
  command -v ip   >/dev/null 2>&1 || return 0
  curl -fsS --max-time 8 -o /dev/null https://pypi.org 2>/dev/null && return 0

  step "กู้การเชื่อมต่ออินเทอร์เน็ตก่อนติดตั้งแพ็กเกจ"
  warn "เน็ตใช้ไม่ได้ตอนนี้ — ตั้ง ${UPLINK_CIDR} บน ${NIC} และเส้นทางออกผ่าน ${UPLINK_GW} ให้ก่อน"
  warn "ถ้ากำลัง SSH เข้ามาผ่าน IP เดิมของ ${NIC} การเชื่อมต่ออาจหลุด — ให้ SSH ผ่าน IP ใหม่แทน"
  run_sh "ip link set '${NIC}' up 2>/dev/null || true"
  run_sh "ip addr add '${UPLINK_CIDR}' dev '${NIC}' 2>/dev/null || true"
  run_sh "ip route replace default via '${UPLINK_GW}' dev '${NIC}' 2>/dev/null || true"
  # route ถูกแต่ resolve ชื่อไม่ได้ (สายเส้นเดียว ไม่มี Wi-Fi มาให้ DNS) ก็ยังโหลดแพ็กเกจไม่ได้เหมือนกัน
  getent hosts pypi.org >/dev/null 2>&1 || configure_host_dns
  sleep 2

  if curl -fsS --max-time 10 -o /dev/null https://pypi.org 2>/dev/null; then
    ok "เชื่อมต่ออินเทอร์เน็ตได้แล้ว — ติดตั้งแพ็กเกจต่อได้"
  else
    warn "ยังออกเน็ตไม่ได้หลังตั้งค่า — ตรวจสายและค่า --uplink-cidr/--uplink-gw"
    warn "การติดตั้งแพ็กเกจจะล้มเหลวหรือค้างนานถ้าเครื่องออกเน็ตไม่ได้จริง ๆ"
  fi
}

configure_network() {
  if (( SKIP_NETWORK )); then info "ข้ามการตั้งค่าเครือข่าย (--skip-network)"; return 0; fi
  step "ตั้งค่าเครือข่าย (โหมดสาย LAN เส้นเดียว -- routing / NAT / DHCP / DNS บนอินเทอร์เฟซเดียว)"
  local client_ip="${CLIENT_CIDR%%/*}"
  local client_net upl_ip upl_net
  client_net="$(cidr_to_network "$CLIENT_CIDR")"
  upl_ip="${UPLINK_CIDR%%/*}"
  upl_net="$(cidr_to_network "$UPLINK_CIDR")"

  # ---------- N34: ปลด NIC ฝั่งลูกค้าออกจาก NetworkManager ก่อนตั้ง IP เอง ----------
  # Raspberry Pi OS / Debian รุ่นใหม่ใช้ NetworkManager คุมทุกอินเทอร์เฟซโดยปริยาย ถ้าไม่ปลด
  # มันจะแย่งตั้งค่า ${NIC} กับเรา (ขอ DHCP ทับ static IP ที่เราตั้ง, ลบ IP ทิ้งตอน renew)
  # ทำให้ลูกค้าหลุดเป็นช่วง ๆ แบบหาสาเหตุยาก -- เจอจริงตอนติดตั้งบน Pi ครั้งแรก 2026-09-16
  # แล้วแก้ด้วยมือ ซึ่งแปลว่าติดตั้งเครื่องใหม่จะเจอซ้ำ จึงต้องอยู่ในตัวติดตั้ง
  #
  # แตะเฉพาะ ${NIC} เท่านั้น ห้ามแตะอินเทอร์เฟซอื่น (เช่น wlan0 ที่ใช้ SSH เข้ามาดูแลเครื่อง)
  # ถ้าเครื่องไม่ได้ใช้ NetworkManager ก็ข้ามไปเงียบ ๆ (ifupdown/systemd-networkd ไม่มีปัญหานี้)
  if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; then
    write_file "/etc/NetworkManager/conf.d/99-${APP_NAME}-unmanage-${NIC}.conf" 0644 <<NMCONF
# managed by ${APP_NAME} installer -- ห้ามแก้มือ
# ${NIC} ถูกตั้งค่าโดย ${APP_NAME}-netsetup.service (static IP + macvlan ฝั่งลูกค้า)
# ปล่อยให้ NetworkManager คุมด้วยจะแย่งกันจนลูกค้าหลุดเป็นช่วง ๆ
[keyfile]
unmanaged-devices=interface-name:${NIC}
NMCONF
    run_sh "nmcli general reload 2>/dev/null || systemctl reload NetworkManager 2>/dev/null || true"
    run_sh "nmcli device set '${NIC}' managed no 2>/dev/null || true"
    ok "ปลด ${NIC} ออกจาก NetworkManager แล้ว (อินเทอร์เฟซอื่นไม่ถูกแตะ)"
  else
    info "ไม่ได้ใช้ NetworkManager — ข้ามขั้นตอนปลด ${NIC}"
  fi

  write_file "/etc/sysctl.d/99-${APP_NAME}.conf" 0644 <<'SYSCTL'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.core.rmem_max = 33554432
SYSCTL
  # หมายเหตุ net.core.rmem_max (N39): ยกเพดานบัฟเฟอร์รับของ socket ให้ตรงกับที่ตัวเก็บ log
  # ขอไว้ (32 MB) -- **ไม่ใช่สาเหตุของการสูญหายที่พบ** วัดแล้วพบว่า conntrack ตั้งได้ 64 MB
  # อยู่แล้วเพราะมี CAP_NET_ADMIN (ใช้ SO_RCVBUFFORCE ข้ามเพดานได้) ตั้งไว้เป็นการกันเหนียว
  # เผื่อวันใดที่บริการถูกรันโดยไม่มีสิทธิ์นั้น ค่าที่ขอจะได้ไม่ถูกตัดเหลือ 4 MB เงียบ ๆ
  # หมายเหตุ rp_filter=0: โหมดสายเดียวมี 2 IP บนอินเทอร์เฟซเดียว ทำให้ reverse-path
  # ของแพ็กเก็ตขาเข้า/ขาออกไม่สมมาตรได้ตามธรรมชาติ (asymmetric routing) -- ตั้งเป็น strict
  # (ค่า 1 เดิม) จะทำให้ Linux drop แพ็กเก็ตที่ถูกต้องทิ้งอย่างงงงวย ความปลอดภัยส่วนนี้เรา
  # คุมด้วย nftables (ip saddr/daddr ตาม subnet) แทนอยู่แล้ว ไม่ได้พึ่ง rp_filter
  run sysctl -q --system

  # ---------- IP บนอินเทอร์เฟซเดียว: uplink (ต่อเราเตอร์) อยู่บน ${NIC} ตรงๆ
  # ***ห้ามใช้ `ip addr replace` กับ uplink เด็ดขาด — ถ้าผู้ติดตั้งกำลัง SSH ผ่าน IP นี้อยู่
  # จะทำให้หลุดการเชื่อมต่อทันที (ดู PROJECT_PLAN.md §3.1.7)*** ใช้ `ip addr add` แบบ
  # idempotent (เพิกเฉยถ้ามี IP นี้อยู่แล้ว) แทน
  run_sh "ip addr add '${UPLINK_CIDR}' dev '${NIC}' 2>/dev/null || true"
  run_sh "ip link set '${NIC}' up 2>/dev/null || true"
  run_sh "ip route replace default via '${UPLINK_GW}' dev '${NIC}' 2>/dev/null || true"
  configure_host_dns

  # *** Plan B ของ R11 (§3.1.6) — ตอนนี้ยืนยันแล้วว่าเป็น**ทางเดียวที่ใช้งานได้จริง** ***
  # ทดสอบบน VM lab (2026-08-27) พบว่า openNDS 10.1.3 ปฏิเสธ interface ที่มี IP มากกว่า 1
  # ตัวแบบ hard-code ไม่มี config เลี่ยงได้ (ดู check_gw_ip() ใน libopennds.sh -- error
  # "IP address aliasing forbidden. Configure a VLAN instead.") แปลว่าเอา CLIENT_CIDR
  # ไปแปะบน ${NIC} ตรงๆ (แบบที่แผนเดิมตั้งใจไว้) ใช้กับ openNDS ไม่ได้เลย -- ต้องสร้าง
  # macvlan ซ้อนแยกออกมาให้ openNDS เห็นเป็นอินเทอร์เฟซคนละตัวกับ uplink เสมอ ถึงจะใช้สาย
  # กายภาพเส้นเดียวได้จริงตามเจตนาของ D17
  run_sh "ip link add '${CLI_IFACE}' link '${NIC}' type macvlan mode bridge 2>/dev/null || true"
  run_sh "ip addr add '${CLIENT_CIDR}' dev '${CLI_IFACE}' 2>/dev/null || true"
  run_sh "ip link set '${CLI_IFACE}' up 2>/dev/null || true"

  # ---------- ทำให้ IP + macvlan อยู่ถาวรข้ามรีบูต ----------
  # *** แก้บั๊กร้ายแรง (พบจากไฟดับจริงทำให้ VM lab รีบูตกลางเซสชันทดสอบ 2026-08-28) ***
  # เดิมเช็คแค่ `[[ -d /etc/systemd/network ]]` ว่ามีโฟลเดอร์อยู่ไหม ซึ่ง**มีอยู่แล้วแทบทุก
  # distro ที่ใช้ systemd แม้จะไม่ได้เปิดใช้ systemd-networkd จริงเลยก็ตาม** (Debian netinst
  # ใช้ ifupdown เป็นค่าเริ่มต้น มีโฟลเดอร์นี้อยู่เฉยๆ ไม่มีอะไรอ่านมันเลย) ทำให้เขียนไฟล์
  # .network/.netdev ไปแล้วไม่มีผลอะไรจริง — รีบูตแล้ว macvlan หาย, CLIENT_CIDR ตกกลับไปอยู่
  # บน ${NIC} ตรงๆ เหมือนก่อนแก้ R11 เลย (openNDS ล่มซ้ำด้วย "IP address aliasing forbidden"
  # ตัวเดิม, restart loop ไม่จบ) **ไม่มีทางรู้แน่ชัดว่า networkd/NetworkManager "ใช้งานจริง"
  # อยู่หรือเปล่าแค่ดูว่าไฟล์/โฟลเดอร์มันมีอยู่** — แก้ให้ไม่ต้องเดา network manager เลย
  # สร้าง systemd oneshot service ของเราเองที่รันคำสั่ง `ip` ตรงๆ ทุกครั้งที่บูต (idempotent
  # ปลอดภัยรันซ้ำได้เสมอ) ใช้ได้แน่นอนไม่ว่าเครื่องจะตั้งค่าเครือข่ายพื้นฐานด้วยอะไรอยู่ก่อน
  # แล้วก็ตาม (NetworkManager/systemd-networkd/ifupdown/ไม่มีเลย)
  write_file "${OPT_DIR}/netsetup.sh" 0755 <<NETSETUP
#!/bin/sh
# managed by ${APP_NAME} installer -- รันทุกครั้งที่บูตผ่าน ${APP_NAME}-netsetup.service
# ให้ IP + macvlan ฝั่งลูกค้ากลับมาเหมือนเดิมเสมอ ไม่ว่าเครื่องใช้อะไรจัดการ ${NIC} อยู่ก่อน
set -e
tries=0
while ! ip link show '${NIC}' >/dev/null 2>&1; do
    tries=\$((tries + 1))
    if [ "\$tries" -ge 30 ]; then
        echo "netsetup: ไม่พบอินเทอร์เฟซ ${NIC} หลังรอ 30 วิ ยอมแพ้" >&2
        exit 1
    fi
    sleep 1
done
ip addr add '${UPLINK_CIDR}' dev '${NIC}' 2>/dev/null || true
ip link set '${NIC}' up 2>/dev/null || true
ip link add '${CLI_IFACE}' link '${NIC}' type macvlan mode bridge 2>/dev/null || true
ip addr add '${CLIENT_CIDR}' dev '${CLI_IFACE}' 2>/dev/null || true
ip link set '${CLI_IFACE}' up 2>/dev/null || true
ip route replace default via '${UPLINK_GW}' dev '${NIC}' 2>/dev/null || true
# กันเหนียว: ถ้า resolv.conf (ไฟล์จริง ไม่ใช่ symlink ของ systemd-resolved) ไม่มี nameserver เลย
# ตัว Pi จะ resolve ชื่อไม่ได้ -- chrony หาเซิร์ฟเวอร์เวลาไม่เจอ (ม.26) ดู configure_host_dns() ใน install.sh
if [ ! -L /etc/resolv.conf ] && ! grep -q '^nameserver' /etc/resolv.conf 2>/dev/null; then
    for ns in ${HOST_DNS}; do echo "nameserver \$ns"; done > /etc/resolv.conf
fi
exit 0
NETSETUP
  write_file "/etc/systemd/system/${APP_NAME}-netsetup.service" 0644 <<NETSVC
[Unit]
Description=${APP_NAME} network setup (uplink IP + client macvlan, idempotent, runs every boot)
DefaultDependencies=no
After=systemd-udevd.service local-fs.target
Before=network-online.target dnsmasq.service nftables.service opennds.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${OPT_DIR}/netsetup.sh

[Install]
WantedBy=multi-user.target
NETSVC
  run_sh "systemctl daemon-reload"
  svc enable "${APP_NAME}-netsetup"
  run_sh "systemctl start '${APP_NAME}-netsetup' 2>/dev/null || true"
  ok "ตั้ง ${APP_NAME}-netsetup.service ให้ IP/macvlan กลับมาเองทุกครั้งที่บูต (ไม่พึ่ง network manager ตัวไหนโดยเฉพาะ)"

  # ---------- dnsmasq (ให้บริการ DHCP/DNS เฉพาะฝั่งลูกค้าเท่านั้น ผ่าน listen-address) ----------
  write_file "/etc/dnsmasq.d/${APP_NAME}.conf" 0644 <<DNSMASQ
# managed by ${APP_NAME} installer -- DHCP + DNS + query logging
# โหมดสาย LAN เส้นเดียว: ผูกกับ ${CLI_IFACE} (macvlan ฝั่งลูกค้า) ไม่ใช่ ${NIC} เอง -- ต้อง
# ให้ตรงกับอินเทอร์เฟซจริงที่รับ broadcast (DHCP) ของลูกค้า ไม่งั้น DHCP จะไม่ทำงาน แม้ DNS
# จะยังพอผ่านได้เพราะ listen-address ผูก IP ตรงๆ (ทดสอบยืนยันบน VM lab แล้วว่าต้องเป็นแบบนี้)
interface=${CLI_IFACE}
bind-interfaces
except-interface=lo
listen-address=${client_ip}

dhcp-range=${DHCP_START},${DHCP_END},255.255.255.0,${DHCP_LEASE}
dhcp-option=option:router,${client_ip}
dhcp-option=option:dns-server,${client_ip}
dhcp-authoritative
# *** ห้ามเปลี่ยนชื่อไฟล์นี้เด็ดขาด *** (พบจาก VM lab 2026-08-28): openNDS เองมีเช็คความ
# ปลอดภัยที่ดี -- ปฏิเสธ client ที่ IP ไม่ปรากฏใน DHCP lease จริง (กัน static-IP self-assign
# บายพาส) แต่ libopennds.sh::dhcp_check() หา lease file จากรายชื่อ path ที่ hardcode ไว้แค่
# 3 ที่เท่านั้น (/tmp/dhcp.leases, /var/lib/misc/dnsmasq.leases, /var/db/dnsmasq.leases) ไม่รู้จัก
# ชื่อไฟล์กำหนดเองเลย -- ถ้าตั้งชื่ออื่น (เช่น ${APP_NAME}.leases เดิม) openNDS จะหา DHCP
# database ไม่เจอแล้วปฏิเสธ**ลูกค้าจริงทุกคน**ด้วย "IP not allocated by dhcp" ทันที ทั้งที่
# DHCP ทำงานถูกต้อง 100% ก็ตาม -- นี่คือบั๊กที่จะทำให้ระบบใช้งานไม่ได้เลยถ้าไม่จับได้ก่อน
dhcp-leasefile=/var/lib/misc/dnsmasq.leases

server=1.1.1.1
server=8.8.8.8
domain-needed
bogus-priv
no-resolv

# แหล่งข้อมูลของ dns_log -- logger/dns_collector.py อ่านไฟล์นี้
log-queries
log-facility=${LOG_DIR}/dnsmasq.log
log-async=25

# ให้ลูกค้าพิมพ์ cafe.wifi เข้าหน้า portal เองได้เมื่อ captive detection ไม่เด้ง
address=/cafe.wifi/${client_ip}
DNSMASQ

  run_sh "touch '${LOG_DIR}/dnsmasq.log'"
  run_sh "chown dnsmasq:'${APP_USER}' '${LOG_DIR}/dnsmasq.log' 2>/dev/null || chown root:'${APP_USER}' '${LOG_DIR}/dnsmasq.log'"
  run_sh "chmod 0640 '${LOG_DIR}/dnsmasq.log'"

  # แก้บั๊ก (พบจากรัน install.sh จริงบน Raspberry Pi, 2026-08-28): แพ็กเกจ dnsmasq ของ Debian
  # (/usr/share/dnsmasq/init-system-common) ใส่ `--local-service` ให้ทุกครั้งแบบไม่มีเงื่อนไข
  # ("DNSMASQ_OPTS=\"\${DNSMASQ_OPTS} --local-service\"") ทั้งที่เราตั้ง interface=/bind-interfaces/
  # listen-address= เจาะจงเองแล้วใน ${APP_NAME}.conf ด้านบน -- ผลคือ dnsmasq เงียบๆ ปฏิเสธ DHCP
  # request บางส่วนจากฝั่งลูกค้า (ทดสอบยืนยันจริงว่า DHCPDISCOVER ไปถึง dnsmasq แต่ไม่มี DHCPOFFER
  # ตอบกลับเลย) ไม่มี flag ให้ปิด --local-service ตรงๆ ใน dnsmasq เอง ต้อง patch ไฟล์ของแพ็กเกจ
  # -- ใช้ pattern match แทน hardcode เลขบรรทัด (กัน Debian เปลี่ยนไฟล์ระหว่างเวอร์ชัน) และเช็คก่อน
  # ว่ายัง patch ไม่ได้ทำ เพื่อให้รันซ้ำได้ปลอดภัย (idempotent)
  local dnsmasq_helper="/usr/share/dnsmasq/init-system-common"
  if [[ -f "$dnsmasq_helper" ]] && grep -q '^DNSMASQ_OPTS=.*--local-service' "$dnsmasq_helper" 2>/dev/null; then
    # ตัดแค่ส่วน " --local-service" ออกจากบรรทัดนั้น (ไม่ไปแตะส่วนอื่นของบรรทัด/ไฟล์เลย
    # -- ปลอดภัยกว่าการ reconstruct ทั้งบรรทัดใหม่ และรันซ้ำได้เรื่อยๆ เพราะ grep เช็คก่อนทุกครั้ง)
    run_sh "sed -i '/^DNSMASQ_OPTS=/ s/ --local-service//' '${dnsmasq_helper}'"
    ok "แก้บั๊ก dnsmasq --local-service แล้ว (เดิมบล็อก DHCP ฝั่งลูกค้าเงียบๆ)"
  fi

  svc enable dnsmasq
  svc restart dnsmasq
  ok "dnsmasq พร้อม (DHCP ${DHCP_START}-${DHCP_END}, ผูกเฉพาะ ${client_ip})"

  # ---------- nftables (อิง subnet แทนชื่ออินเทอร์เฟซ เพราะมีอินเทอร์เฟซเดียว) ----------
  write_file /etc/nftables.conf 0644 <<NFT
#!/usr/sbin/nft -f
# managed by ${APP_NAME} installer -- โหมดสาย LAN เส้นเดียว (D17): อินเทอร์เฟซเดียวกันทั้ง
# ขาเข้าและขาออก จึงแยกทิศทางด้วย ip saddr/daddr ตาม subnet แทน iifname/oifname แบบเดิม
# แก้ไขแล้วโหลดใหม่ด้วย:  nft -f /etc/nftables.conf
flush ruleset

define CLIENT_NET = ${client_net}
define CLIENT_GW  = ${client_ip}
define UPLINK_NET = ${upl_net}
define UPLINK_GW  = ${UPLINK_GW}

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop
    iif lo accept

    # R2-03: ระบบใช้ IPv4 อย่างเดียว กฎกัน SSH/Admin ด้านล่างเทียบด้วย ip saddr ซึ่งไม่ match
    # แพ็กเก็ต IPv6 เลย ถ้าไม่ drop ตรงนี้ ลูกค้าบน L2 เดียวกันจะเข้าถึงพอร์ตที่ฟังบน :: (เช่น
    # sshd) ผ่าน link-local fe80:: ได้ -- วางหลัง iif lo เพื่อให้ ::1 ภายในเครื่องยังใช้ได้
    meta nfproto ipv6 drop

    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept

    # N41: echo-reply จากวง uplink ถูกทำเป็น notrack (ดูหมายเหตุที่ table ip raw ด้านล่าง)
    # จึงไม่เข้าเงื่อนไข ct state established ต้องอนุญาตตรง ๆ ไม่งั้น ping สำรวจวงจะไม่เห็น
    # เครื่องที่ตอบกลับเลย ซึ่งจะทำให้ผลการตรวจจับ bypass (T17) เพี้ยน
    ip saddr \$UPLINK_NET icmp type echo-reply limit rate 300/second accept

    # *** บั๊กใหญ่ที่พบจากการทดสอบ DHCP จริงบน Pi จริงครั้งแรก (2026-09-16) ***
    # DHCP client ที่ยังไม่มี IP ต้องส่ง DHCPDISCOVER จาก source 0.0.0.0 -> 255.255.255.255
    # เสมอตามมาตรฐาน (RFC 2131) จึงไม่มีทางเข้าเงื่อนไข "ip saddr \$CLIENT_NET" ด้านล่างได้เลย
    # -- เดิมแพ็กเก็ตจึงตกไปโดน policy drop ทิ้งทุกครั้ง กลายเป็นไก่กับไข่: ลูกค้าต้องมี IP ในวง
    # ลูกค้าก่อนถึงจะขอ IP ได้ ผลคือ **ลูกค้าจริงไม่มีทางเชื่อมต่อได้เลยสักคน** ทั้งที่ dnsmasq
    # ทำงานถูกต้อง 100% (ยืนยันด้วย tcpdump: DHCPDISCOVER มาถึง NIC ทุกครั้ง แต่ไม่เคยถึง socket)
    # ที่ผ่านมาไม่เจอเพราะทดสอบด้วย static IP ในวง 10.10.0.0/24 มาตลอด ซึ่งข้ามขั้นตอนนี้ไป
    udp sport 68 udp dport 67 accept

    # จากฝั่งลูกค้า อนุญาตเฉพาะบริการที่จำเป็น
    ip saddr \$CLIENT_NET udp dport { 53, 67 } accept
    ip saddr \$CLIENT_NET tcp dport 53 accept
    ip saddr \$CLIENT_NET tcp dport ${NDS_PORT} accept
    ip saddr \$CLIENT_NET tcp dport ${FAS_PORT} accept
    ip saddr \$CLIENT_NET tcp dport 80 accept

    # Admin Panel เปิดให้วงลูกค้า (เปลี่ยนจาก T8 เดิม -- เจ้าของโครงงานเลือก 2026-10-02): ร้านจริงมีแค่
    # เราเตอร์ + Pi สายเดียว หลังปิด DHCP ของเราเตอร์ เครื่องพนักงานได้ IP วงลูกค้าเหมือนทุกคน ถ้าบล็อก
    # พนักงานจะเข้าหน้าแอดมินไม่ได้เลย -- ป้องกันด้วย HTTPS + รหัสผ่านรายคน + จำกัดการเดารหัสต่อ IP
    # และต่อชื่อผู้ใช้ (admin/app.py) + audit ทุกครั้งที่ login ไม่ผ่าน · ลูกค้าเปิด https://cafe.wifi:8443 เห็น
    # หน้า login ได้ (ความเสี่ยงที่ยอมรับ)
    ip saddr \$CLIENT_NET tcp dport ${ADMIN_PORT} accept
    # SSH ยังห้ามจากฝั่งลูกค้าเสมอ (ดูแลเครื่องผ่านหน้าแอดมิน หรือเสียบจอ/คีย์บอร์ดที่ Pi)
    ip saddr \$CLIENT_NET tcp dport 22 drop

    # จากฝั่งเราเตอร์/อัพลิงก์ (คนละ source กับ CLIENT_NET) อนุญาต SSH + Admin ตามปกติ
    tcp dport ${ADMIN_PORT} accept
    tcp dport 22 accept
  }

  chain forward {
    type filter hook forward priority filter; policy drop;

    # DoT จากวงลูกค้าไม่ผ่าน dnsmasq: ปิด TCP/UDP 853 ก่อน accept ของ connection ที่มีอยู่
    # กฎนี้ครอบคลุมเฉพาะทราฟฟิกที่ส่งผ่าน Pi (D17)
    ip saddr \$CLIENT_NET tcp dport 853 counter drop
    ip saddr \$CLIENT_NET udp dport 853 counter drop

    ct state established,related accept
    ct state invalid drop

    # D9: กันเฉพาะทราฟฟิกลูกค้า↔ลูกค้าที่ถูกส่งผ่าน Pi; การคุยกันตรงบน L2
    # (รวมถึง ARP spoof/sniffing ระหว่างลูกค้า) ต้องแยกที่ AP ด้วย client isolation
    ip saddr \$CLIENT_NET ip daddr \$CLIENT_NET drop

    # กันลูกค้าเข้าถึงเครือข่ายส่วนตัวฝั่งอัพลิงก์ของร้าน (ปลายทางอินเทอร์เน็ตสาธารณะไม่ติดกฎนี้)
    ip saddr \$CLIENT_NET ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop

    # ลูกค้าที่ผ่านการยืนยันแล้ว (openNDS อนุญาต MAC) ออกอินเทอร์เน็ตผ่าน uplink เส้นเดียวกันได้
    ip saddr \$CLIENT_NET accept
  }

  chain output { type filter hook output priority filter; policy accept; }
}

# N41: ห้ามให้ ping สำรวจวงของตัวตรวจจับ bypass สร้างรายการ conntrack
# ตัวตรวจจับยิง ping ทั้งวง (254 IP) ทุก 1 นาทีเพื่อบังคับให้เกิด ARP resolution (T17)
# ผลข้างเคียงที่วัดเจอจริง: เคอร์เนลสร้างรายการ conntrack 254 รายการ แล้วตัวเก็บกวาดของ
# เคอร์เนลลบทั้งหมดพร้อมกันในรอบเดียว -> เหตุการณ์ DESTROY ถล่มมา 250-290 รายการในวินาที
# เดียวทุกนาที -> ตัวเก็บ log หลุด (ENOBUFS) -> **หลักฐานการใช้งานของลูกค้าหายจริง ~5%**
# (วัดด้วยการเทียบพอร์ตต้นทางกับตัวฟังอ้างอิง -- N39/N40)
# การทยอยยิงไม่ช่วย เพราะเคอร์เนลเก็บกวาดรายการหมดอายุเป็นรอบ ไม่ได้ลบทีละรายการ
# จึงต้องไม่ให้สร้างรายการตั้งแต่แรก · ICMP ที่ Pi ยิงเองในวง uplink ไม่ใช่ข้อมูลจราจรของ
# ลูกค้า จึงไม่ต้องบันทึกตาม ม.26 อยู่แล้ว
table ip raw {
  # N43 (2026-10-03): ทราฟฟิกภายในเครื่อง (loopback) ไม่ใช่ข้อมูลจราจรของลูกค้า แต่เดิมถูกติดตามทุก
  # การเชื่อมต่อ -- ทุกบริการเปิด TCP ไป MariaDB 127.0.0.1:3306 ใหม่ทุก query (reconcile ทุก 5 วิ,
  # ตัวเก็บ log, หน้าแอดมิน) วัดบน Pi ได้ 122 จาก 281 รายการในตาราง conntrack แต่ละตัวส่งเหตุการณ์
  # NEW/DESTROY เข้าท่อเดียวกับที่ conn_collector อ่าน และหมดอายุพร้อมกันเป็นชุด (~250 รายการทุกนาที)
  # = รูปแบบเดียวกับ N41 ที่ทำให้เกิด ENOBUFS · แพ็กเก็ต notrack มีสถานะ "untracked" ไม่ใช่ invalid
  # จึงผ่าน ct state invalid drop ไปเข้า iif lo accept ใน chain input ได้ตามปกติ
  chain output {
    type filter hook output priority raw; policy accept;
    oif "lo" notrack
    ip daddr \$UPLINK_NET icmp type echo-request notrack
  }
  chain prerouting {
    type filter hook prerouting priority raw; policy accept;
    iif "lo" notrack
    ip saddr \$UPLINK_NET icmp type echo-reply notrack
  }
}

table ip nat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    # บังคับทุก DNS query จากฝั่งลูกค้าให้วิ่งเข้า dnsmasq (กัน DNS bypass)
    ip saddr \$CLIENT_NET udp dport 53 ip daddr != \$CLIENT_GW dnat to \$CLIENT_GW:53
    ip saddr \$CLIENT_NET tcp dport 53 ip daddr != \$CLIENT_GW dnat to \$CLIENT_GW:53
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    # single-NIC: masquerade ตาม source subnet แทน oifname (ไม่มีอินเทอร์เฟซแยกให้ระบุ)
    ip saddr \$CLIENT_NET masquerade
  }
}
NFT

  if ! run_sh "nft -c -f /etc/nftables.conf"; then
    warn "nft -c ไม่ผ่าน — ไม่ได้โหลด rules ตรวจสอบ /etc/nftables.conf เอง"
    return 0
  fi

  # ---------- dead-man switch (§3.1.6 ข้อ 10) ----------
  # เปลี่ยนกฎ firewall บนอินเทอร์เฟซเดียวกับที่ผู้ติดตั้งอาจกำลัง SSH เข้ามาอยู่ = เสี่ยงล็อก
  # ตัวเองออก (ดู PROJECT_PLAN.md §3.1.7) แม้ ct state established จะกันเซสชันปัจจุบันไว้ได้
  # แต่ถ้าเซสชันหลุดแล้วเชื่อมต่อใหม่ไม่ได้จะเข้าเครื่องไม่ได้อีกเลย -- ตั้งเวลาล้างกฎอัตโนมัติ
  # ไว้ก่อน ถ้าตรวจสอบแล้วว่ายัง SSH เข้าได้ปกติ ให้ยกเลิกด้วยคำสั่งที่พิมพ์ไว้ด้านล่าง
  local dead_man="${APP_NAME}-nft-failsafe"
  if [[ "$INIT_SYS" == systemd ]] && command -v systemd-run >/dev/null 2>&1; then
    run_sh "systemctl reset-failed '${dead_man}.service' >/dev/null 2>&1 || true"
    run_sh "systemd-run --unit='${dead_man}' --on-active=300 /usr/sbin/nft flush ruleset >/dev/null 2>&1 || true"
    warn "ตั้ง dead-man switch ไว้แล้ว: ถ้าไม่ยกเลิก nftables จะถูกล้างอัตโนมัติใน 5 นาที"
    warn "ตรวจสอบว่า SSH ยังเข้าได้ปกติก่อน แล้วยกเลิกด้วย: sudo systemctl stop ${dead_man}.timer 2>/dev/null; sudo systemctl reset-failed ${dead_man} 2>/dev/null"
  else
    warn "ไม่มี systemd-run ใช้ได้ — ข้ามการตั้ง dead-man switch อัตโนมัติ ตรวจ SSH เองให้ดีก่อนตัดการเชื่อมต่อ"
  fi

  run_sh "nft -f /etc/nftables.conf"
  svc enable nftables
  ok "nftables โหลดแล้ว (NAT + client isolation + DNS redirect, อิงตาม subnet)"

  # *** แก้บั๊ก (พบจาก VM lab 2026-08-28) *** conn_collector.py เขียน docstring ไว้เองว่า
  # ต้อง `sysctl -w net.netfilter.nf_conntrack_acct=1` ก่อนถึงจะได้ตัวเลข bytes จาก
  # conntrack แต่ install.sh ไม่เคยตั้งค่านี้ให้เลยจริงๆ สักจุด -- ผลคือ bytes_out/bytes_in
  # ใน conn_log เป็น 0 เสมอ (ยืนยันจาก conntrack -L จริงบน VM lab: ไม่มี packets=/bytes=
  # โผล่มาเลยสักแถว) ซึ่งทำให้ quota_mb (mark_used_up_vouchers() ที่รวมยอด bytes จาก
  # conn_log) ไม่มีทางตัดสิทธิ์ลูกค้าได้จริงเลยไม่ว่าลูกค้าจะโหลดไปเท่าไหร่ก็ตาม -- ต้อง
  # ทำหลัง nftables โหลดเสร็จเท่านั้น เพราะ net.netfilter.nf_conntrack_acct เป็น sysctl key
  # ที่ถูกสร้างแบบ dynamic ตอนโมดูล nf_conntrack ถูกโหลดเข้าเคอร์เนล (ปกติจะโหลดตอนกฎ
  # `ct state ...` ใน nftables.conf ถูก apply) ถ้าตั้งก่อนหน้านั้น (เช่นรวมไปกับ sysctl.d
  # ตัวอื่นตอนต้นฟังก์ชัน) จะไม่มี key นี้ให้ตั้งเลย เงียบๆ ไม่มี error ให้เห็นด้วย (--quiet)
  run_sh "modprobe nf_conntrack 2>/dev/null || true"
  run_sh "sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || warn \"ตั้ง nf_conntrack_acct ไม่สำเร็จ — bytes ใน conn_log จะเป็น 0 เสมอ, quota_mb จะไม่ตัดสิทธิ์ลูกค้าได้จริง\""
  # R2-02: (1) nf_conntrack_timestamp=1 ให้ DESTROY บอกเวลาเริ่ม connection ได้ (เป็นตัวสำรอง
  # ของ conn_log.started_at เวลาที่ collector ไม่เห็น NEW เช่นเพิ่งรีสตาร์ท)
  # (2) ลด timeout ของ TCP ESTABLISHED จากปริยาย 5 วัน -- ลูกค้าที่เดินออกจากร้านไปเฉย ๆ
  # ทำให้ connection ค้างในตารางจนกว่าจะหมดอายุ ยิ่งค้างนานยิ่งห่างจากการใช้งานจริง และ IP นั้น
  # ถูกแจกต่อให้คนอื่นไปแล้ว · 7440 วินาที (2 ชม. 4 นาที) คือค่าต่ำสุดที่ RFC 5382 แนะนำสำหรับ
  # NAT ไม่ให้ตัด connection ที่ idle แต่ยังใช้งานอยู่ (แอปทั่วไปส่ง keepalive ถี่กว่านี้มาก)
  run_sh "sysctl -w net.netfilter.nf_conntrack_timestamp=1 net.netfilter.nf_conntrack_tcp_timeout_established=7440 >/dev/null 2>&1 || warn \"ตั้ง nf_conntrack_timestamp/tcp_timeout_established ไม่สำเร็จ — conn_log.started_at อาจว่างสำหรับ connection ที่ collector ไม่เห็นตอนเปิด\""

  # ตั้งค่านี้ตอน install อย่างเดียวไม่พอ -- ต้องทำซ้ำทุกครั้งที่บูตด้วย เพราะ
  # net.netfilter.nf_conntrack_acct เป็น sysctl key แบบ dynamic ที่มีก็ต่อเมื่อโมดูล
  # nf_conntrack ถูกโหลดแล้วเท่านั้น (โหลดตอน nftables.service เริ่มทำงาน ซึ่งเกิดขึ้น
  # หลังจาก /etc/sysctl.d/*.conf ถูก apply โดย systemd-sysctl.service ไปแล้วเสมอทุกบูต
  # ทำให้ค่าที่ตั้งไว้ใน sysctl.d เฉยๆ ไม่มีทางมีผลจริงตั้งแต่บูตครั้งที่สองเป็นต้นไป)
  write_file "/etc/systemd/system/${APP_NAME}-conntrack-acct.service" 0644 <<CTACCT
[Unit]
Description=${APP_NAME} — enable nf_conntrack byte accounting (must run after nftables loads nf_conntrack)
After=nftables.service
Requires=nftables.service
Before=cafe-logger.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'modprobe nf_conntrack 2>/dev/null; sysctl -w net.netfilter.nf_conntrack_acct=1'
# R2-02: key แบบ dynamic เหมือนกัน ต้องตั้งหลังโหลดโมดูล -- ดูเหตุผลตอนตั้งครั้งแรกด้านบน
ExecStart=-/bin/sh -c 'sysctl -w net.netfilter.nf_conntrack_timestamp=1 net.netfilter.nf_conntrack_tcp_timeout_established=7440'

[Install]
WantedBy=multi-user.target
CTACCT
  run_sh "systemctl daemon-reload"
  svc enable "${APP_NAME}-conntrack-acct"
  ok "ตั้ง nf_conntrack_acct=1 ให้เอง (ทั้งตอนนี้และทุกครั้งที่บูต) — ไม่งั้น bytes ใน conn_log จะเป็น 0 เสมอ"
  return 0
}

build_opennds() {
  if (( SKIP_OPENNDS )) || (( SKIP_NETWORK )); then info "ข้าม openNDS"; return 0; fi
  step "ติดตั้ง openNDS (captive portal engine)"

  # แก้บั๊ก (พบจากรัน uninstall แล้ว reinstall ซ้ำบน VM lab 2026-08-27): เดิมเช็คแค่ว่ามี
  # binary opennds อยู่แล้วหรือยัง ถ้ามีก็ข้าม clone+build+`make install` ทั้งดุ้น -- แต่
  # `make install` เป็นตัวที่ copy resources/opennds.service ไปที่ /etc/systemd/system/ ด้วย
  # (ไม่ใช่แค่ binary) ถ้า unit ไฟล์นี้หายไป (เช่นจาก `--uninstall` รอบก่อน) ทั้งที่ binary
  # ยังอยู่ จะกลายเป็น "systemctl enable opennds" หา unit ไม่เจอเงียบๆ แล้ว service ไม่ขึ้น
  # เลยแม้ install.sh จะรายงานว่าเสร็จสมบูรณ์ก็ตาม -- ต้องเช็ค unit file ควบคู่ไปด้วยเสมอ
  #
  # แก้บั๊กเพิ่ม (พบจากรัน install.sh จริงครั้งแรกบน Raspberry Pi จริง, 2026-08-28): เช็คแค่
  # "มี binary + unit อยู่แล้ว" ยังไม่พอ -- ถ้า binary เดิมถูก build จาก tag คนละตัวกับที่ pin
  # ไว้ตอนนี้ (${OPENNDS_REF}) เช่น เครื่องนี้เคยมีคนรัน install.sh เก่าตอนที่ OPENNDS_REF ยังไม่
  # ได้ pin หรือ pin เป็นคนละ tag ได้ openNDS v11.0.0 มาแทน v10.1.3 ที่ทดสอบบน VM lab จริง --
  # พอ uninstall แล้ว reinstall ใหม่ branch นี้เจอ "มี binary อยู่" ก็ copy service file เดิม
  # กลับมาเฉยๆ โดยไม่ build ใหม่ ทำให้ config format ที่เขียนด้านล่าง (validate กับ 10.1.3)
  # ไปชนกับพฤติกรรมจริงของ libopennds.sh ใน v11.0.0 (เช็ครูปแบบ `config opennds 'setup'`
  # เข้มกว่า 10.1.3 -- ไม่มี 'setup' ต่อท้ายชื่อ section แล้ว exit 1 ทันทีตั้งแต่บรรทัดแรกที่
  # เรียก get_option_from_config เลย, error message ที่เห็นจริงคือ "Failed to get option
  # [11.0.0] Bad library or invalid config format" ซึ่งเป็นบั๊ก log ของ openNDS เองอีกที
  # (src/util.c ใส่ VERSION แทนชื่อ option จริงที่ fail ผิด) -- ต้องเช็ค version ให้ตรง pin
  # ด้วยเสมอ ไม่ใช่แค่เช็คว่ามี binary อยู่หรือไม่
  local nds_installed_ver="" nds_pinned_ver="${OPENNDS_REF#v}"
  if command -v opennds >/dev/null 2>&1; then
    # N24: `opennds -v` พิมพ์เวอร์ชันถูกต้องแต่คืน exit 1 เสมอ (ยืนยันกับ 10.1.3 บน Pi จริง) ภายใต้
    # set -e -o pipefail การกำหนดค่าบรรทัดนี้จึงล้มทั้งสคริปต์ทุกครั้งที่รันทับเครื่องที่ติดตั้ง
    # openNDS แล้ว -- `|| true` ยังได้ค่าเวอร์ชันที่พิมพ์ออกมาครบ แค่ไม่ปล่อยให้ exit code ฆ่าสคริปต์
    nds_installed_ver="$(opennds -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)" || true
  fi
  if [[ -n "$nds_installed_ver" && "$nds_installed_ver" != "$nds_pinned_ver" ]]; then
    warn "พบ openNDS ${nds_installed_ver} ติดตั้งอยู่ แต่ตอนนี้ pin ไว้ที่ ${OPENNDS_REF} (${nds_pinned_ver}) -- บิลด์ใหม่ให้ตรง pin เสมอ (ข้ามการ reuse binary เดิม)"
  fi
  if [[ -n "$nds_installed_ver" && "$nds_installed_ver" == "$nds_pinned_ver" ]] && [[ -f /etc/systemd/system/opennds.service ]]; then
    info "พบ openNDS ${nds_installed_ver} ติดตั้งอยู่แล้ว (พร้อม systemd unit, ตรงกับ pin ${OPENNDS_REF})"
  elif [[ -n "$nds_installed_ver" && "$nds_installed_ver" == "$nds_pinned_ver" ]] && [[ -f /usr/local/src/opennds/resources/opennds.service ]]; then
    info "พบ openNDS ${nds_installed_ver} ติดตั้งอยู่แล้วแต่ systemd unit หาย — คัดลอกกลับจาก source cache เดิม (ตรงกับ pin)"
    run_sh "install -d -m 0755 /etc/systemd/system"
    run_sh "cp /usr/local/src/opennds/resources/opennds.service /etc/systemd/system/opennds.service"
  else
    local src="/usr/local/src/opennds"
    run_sh "rm -rf '${src}'"
    # แก้บั๊ก M4: เดิม clone --depth 1 จาก default branch ตรง ๆ ทุกครั้ง ได้ commit ล่าสุด
    # ของ upstream เสมอ ไม่ reproducible และเสี่ยง build พังกลางคันถ้า upstream เปลี่ยนโค้ด
    # -- ปักเป็น tag ที่ระบุได้ผ่าน --opennds-ref (ตรวจ tag ล่าสุดจริงที่
    # github.com/openNDS/openNDS/tags ก่อนใช้งานจริงบนเครื่อง เพราะรายชื่อ tag เปลี่ยนได้
    # เรื่อย ๆ ตามการ release ของ upstream) ถ้า checkout tag ไม่สำเร็จ fallback ไป default
    # branch แล้วเตือนชัดเจนแทนที่จะ pretend ว่า pin สำเร็จ
    if run_sh "git clone --branch '${OPENNDS_REF}' --depth 1 https://github.com/openNDS/openNDS.git '${src}'"; then
      ok "clone openNDS (${OPENNDS_REF}) สำเร็จ"
    else
      warn "clone openNDS tag '${OPENNDS_REF}' ไม่สำเร็จ (อาจไม่มี tag นี้จริงแล้ว — ตรวจที่ https://github.com/openNDS/openNDS/tags แล้วระบุใหม่ด้วย --opennds-ref) ใช้ default branch (ล่าสุด, ไม่ pin) แทน"
      run_sh "rm -rf '${src}'"
      if ! run_sh "git clone --depth 1 https://github.com/openNDS/openNDS.git '${src}'"; then
        warn "clone openNDS ไม่สำเร็จ — ติดตั้งเองภายหลังแล้วรันซ้ำด้วย --skip-opennds"
        return 0
      fi
    fi
    if ! run_sh "make -C '${src}' -j\"\$(nproc)\" && make -C '${src}' install"; then
      warn "build openNDS ไม่สำเร็จ (มักขาด libmicrohttpd-dev)"
      warn "ติดตั้งเองแล้วรันซ้ำด้วย --skip-opennds"
      return 0
    fi
    ok "build + ติดตั้ง openNDS สำเร็จ"
    # แก้บั๊ก (พบจากรัน install.sh สดใหม่ทั้งหมดบน VM lab, 2026-08-28): `make install` ของ
    # openNDS เขียน /etc/systemd/system/opennds.service ตรงๆ ด้วย cp เอง (ไม่ผ่าน write_file()
    # ของเรา) install_services() ที่รันถัดไปมี `systemctl daemon-reload` ท้ายฟังก์ชันอยู่แล้ว
    # ตามลำดับควรจะพอ แต่จากการทดสอบจริงพบว่า start_services() ยัง enable opennds ไม่เจอ unit
    # อยู่ดีเป็นครั้งคราว (เจอ WARN "ยังไม่มี unit" ทั้งที่ unit file มีอยู่จริงและใช้งานได้ปกติ
    # ถ้า enable มือเอง) -- ไม่ยืนยันสาเหตุ race condition ที่แท้จริง แต่ daemon-reload ซ้ำ
    # ทันทีตรงนี้ (ก่อนจะรอ install_services() อีกที) ปลอดภัยเสมอและปิดช่องว่างนี้ได้ชัวร์กว่า
    run_sh "systemctl daemon-reload"
  fi

  # *** แก้บั๊กที่เจอซ้ำ 3 ครั้ง (VM lab 2026-08-28, Pi จริง 2026-09-16 x2) ***
  # openNDS เช็คตอนสตาร์ทด้วย check_heartbeat() (src/commandline.c) ซึ่งอ่านไฟล์
  # /tmp/ndscids/heartbeat -- ถ้าค่ายังไม่หมดอายุมันจะถือว่า "มีตัวเองรันอยู่แล้ว" แล้ว exit 1
  # ทันทีพร้อมข้อความ "openNDS is already running, status [ 1 ]. Retry later..."
  # ไฟล์นี้ค้างทุกครั้งที่ openNDS หยุดแบบไม่สะอาด (ไฟดับ, kill -9, หยุดกลางคัน) ทำให้ service
  # สตาร์ทกลับไม่ได้เองจนกว่า heartbeat จะหมดอายุ -- ร้ายแรงสำหรับระบบที่ต้องรอดไฟดับ
  # แก้ด้วย systemd drop-in (ไม่ใช่แก้ไฟล์ unit ตรง ๆ เพราะ `make install` ของ openNDS
  # เขียนทับ unit ทุกครั้งที่ build ใหม่ แต่ drop-in อยู่คนละไฟล์จึงรอด)
  # ลบ heartbeat เฉพาะตอนที่ไม่มี process opennds จริงเหลืออยู่เท่านั้น จึงไม่ไปฆ่า instance
  # ที่กำลังทำงานอยู่จริง
  write_file /etc/systemd/system/opennds.service.d/cafe-wifi-heartbeat.conf 0644 <<'NDSDROPIN'
# managed by cafe-wifi installer -- ห้ามแก้มือ
# ล้าง heartbeat ที่ค้างจากการหยุดแบบไม่สะอาด ก่อนสตาร์ททุกครั้ง (เฉพาะเมื่อไม่มี process จริง)
[Service]
ExecStartPre=-/bin/sh -c 'pgrep -x opennds >/dev/null || rm -f /tmp/ndscids/heartbeat'
NDSDROPIN

  # N23: openNDS คือประตูที่ปล่อยลูกค้าออกเน็ต ต้องไม่เปิดก่อนนาฬิกาถูก (ดูเหตุผลที่ configure_time)
  write_file /etc/systemd/system/opennds.service.d/cafe-wifi-time-sync.conf 0644 <<'NDSDROPIN'
# managed by cafe-wifi installer -- ห้ามแก้มือ
# ห้ามปล่อยลูกค้าออกเน็ตก่อนนาฬิกา sync ไม่งั้น log ตาม ม.26 จะติดเวลาผิด (Pi 4 ไม่มี RTC)
[Unit]
Wants=time-sync.target
After=time-sync.target
NDSDROPIN
  run_sh "systemctl daemon-reload"

  local faskey="CHANGEME"
  if [[ -f "${ETC_DIR}/secrets.env" ]] && (( ! DRY_RUN )); then
    faskey="$(grep -E '^FAS_KEY=' "${ETC_DIR}/secrets.env" | cut -d= -f2-)"
  fi

  # โหมดสาย LAN เส้นเดียว (D17): eth0 เดียวมี 2 IP -- GatewayAddress ไม่ต้องตั้งเอง openNDS
  # จะอ่าน IP จริงของ GatewayInterface ให้เองเสมอ (ดู get_iface_ip ใน src/conf.c)
  #
  # *** บั๊กใหญ่ที่พบจากการรัน install.sh จริงครั้งแรกบน VM lab (2026-08-27, ปิด R11/A1) ***
  # เดิมสคริปต์นี้เขียน config แบบ flat text (NoDogSplash-style) ไปที่ /etc/opennds/opennds.conf
  # แต่ openNDS รุ่นนี้ (10.1.3) **ไม่เคยอ่านไฟล์นั้นเลยแม้แต่บรรทัดเดียว** -- ทุก option
  # (รวม debuglevel) โหลดผ่าน get_option_from_config() ใน src/util.c ซึ่ง shell out ไปเรียก
  # /usr/lib/opennds/libopennds.sh เสมอ และสคริปต์นั้น "ไม่มี uci บน Debian" เลยอ่านจาก
  # /etc/config/opennds (รูปแบบ UCI ของ OpenWrt) แทน -- ผลคือค่าที่เราตั้งไว้ทั้งหมดถูกเมิน
  # เงียบๆ ทุกตัว แล้ว openNDS ใช้ค่า default ที่ compile ไว้แทนหมด (เช่น GatewayInterface
  # กลายเป็น "br-lan" ที่ hardcode ไว้ใน src/conf.h ทำให้ bind อินเทอร์เฟซผิดตัวแล้ว exit
  # ทันที -- เป็นสาเหตุที่แท้จริงของทั้งปัญหา "openNDS ทำงานบนอินเทอร์เฟซเดียวไม่ได้" ที่
  # กลัวกันไว้ใน R11 -- ทางแก้คือเขียนเป็น UCI format ไปที่ /etc/config/opennds ตรงๆ แทน
  # (parser ของ libopennds.sh อ่านแบบ plain grep/awk จากไฟล์นี้ได้โดยไม่ต้องมี uci บินารีจริง
  # ก็ได้ -- ดู get_option_from_config()/get_list_from_config() ใน libopennds.sh)
  # mode 0640 root:root (แก้บั๊ก H1: ป้องกันไม่ให้ทุกคนบนเครื่องอ่าน faskey ตรงๆ ได้)
  # N36 (พบตอนทดสอบกับ AP จริง 2026-09-20): อุปกรณ์โครงสร้างพื้นฐานอย่าง access point เองก็ถูก
  # openNDS นับเป็น "ลูกค้าที่ยังไม่ login" เหมือนกัน -- AP จึงออกไปหา NTP ไม่ได้ นาฬิกาในเครื่อง
  # AP เลยผิด (ผลคือ log/กราฟฝั่ง AP อ้างอิงเวลาไม่ได้) ใส่ MAC ของมันเป็น trustedmac เพื่อให้
  # ผ่านได้โดยไม่ต้อง login · ไม่กระทบการเก็บ log ของลูกค้า เพราะลูกค้าเชื่อมผ่าน AP แบบ bridge
  # Pi จึงยังเห็น MAC จริงของลูกค้าแต่ละเครื่องตามเดิม
  local nds_trusted_block=""
  if [[ -n "$TRUSTED_MACS" ]]; then
    local m
    nds_trusted_block=$'
	# อุปกรณ์โครงสร้างพื้นฐานที่ไม่ต้อง login (--trusted-mac)'
    for m in ${TRUSTED_MACS//,/ }; do
      if [[ ! "$m" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
        die "รูปแบบ MAC ไม่ถูกต้อง: '${m}' (ต้องเป็น aa:bb:cc:dd:ee:ff)"
      fi
      nds_trusted_block+=$'
	'"list trustedmac '${m,,}'"
    done
  fi

  write_file /etc/config/opennds 0640 <<NDS
config opennds
	option enabled '1'
	option debuglevel '1'
	# ต้องเป็น macvlan (${CLI_IFACE}) ไม่ใช่ ${NIC} ตรงๆ -- openNDS ปฏิเสธอินเทอร์เฟซที่มี
	# IP มากกว่า 1 ตัว ("IP address aliasing forbidden") ดู configure_network() สำหรับที่มา
	option gatewayinterface '${CLI_IFACE}'
	option gatewayname '${GATEWAY_NAME}'
	option gatewayport '${NDS_PORT}'
	# แก้บั๊กเทียบเวอร์ชันของ openNDS เอง (src/main.c): logic "else if (minor < MIN_MHD_MINOR)"
	# ไม่เช็คว่า major version สูงกว่าแล้วหรือยัง ทำให้ libmicrohttpd 1.x (Debian/Ubuntu ปัจจุบัน
	# แจกมาให้เป็นค่าเริ่มต้น) ถูกเข้าใจผิดว่า "เก่ากว่า 0.9.71" ทั้งที่จริงใหม่กว่ามาก -- ยืนยัน
	# จาก VM lab ว่าใช้ 1.0.1 ได้จริงไม่มีปัญหา ไม่ใช่การใช้เวอร์ชันเก่าจริงๆ ตามที่ option นี้เตือน
	option use_outdated_mhd '1'

	# Forwarding Authentication Service -> Flask app ของเรา
	option fasport '${FAS_PORT}'
	option faspath '/login'
	option fas_secure_enabled '2'
	option faskey '${faskey}'

	# แก้บั๊ก H3: เดิมตั้งตายตัวที่ 240 นาที (4 ชม.) แม้หน้า /issue ให้พนักงานเลือกอายุ
	# voucher ได้ 1-24 ชม. -- voucher 1 ชม. เคยใช้ได้จริงยาวกว่าที่จ่าย (4 ชม.) ส่วน voucher
	# 24 ชม. เคยถูกตัดสั้นกว่าที่จ่าย (แค่ 4 ชม.) ตั้งเป็น 1440 (=24 ชม., ค่าสูงสุดที่ /issue
	# อนุญาต) กัน "ตัดเร็วเกินไป" ไว้ก่อน แล้วให้ cafe-enforce.timer (tools/enforce_voucher_
	# expiry.py ทุก 5 นาที) เป็นตัวบังคับเวลาที่แท้จริงตาม valid_until ในฐานข้อมูลแทน
	option sessiontimeout '1440'
	option preauthidletimeout '10'
	option authidletimeout '30'
	option checkinterval '60'

	# พอร์ตบนตัว Pi ที่เครื่องลูกค้าเข้าถึงได้ (chain ndsRTR) -- กำหนดเองแล้ว**แทนที่ค่าปริยายทั้งชุด**
	# จึงต้องใส่ค่าปริยายของ openNDS (udp 53/67, tcp 22/443 -- อ่านจาก nft list บน Pi จริง) กลับไปครบ
	# + tcp 53 (DNS ขนาดใหญ่) + พอร์ตหน้าแอดมิน: พนักงานได้ IP วงลูกค้า (ร้านจริงมีแค่เราเตอร์ + Pi)
	# ถ้าไม่ใส่ openNDS จะ reject :${ADMIN_PORT} ทั้งที่ nftables ของเราอนุญาตแล้ว (พบบน Pi 2026-10-02)
	# gatewayport/fasport openNDS เติมให้เอง · SSH ถูก nftables ของเราบล็อกจากวงลูกค้าอีกชั้นอยู่แล้ว
	list users_to_router 'allow udp port 53'
	list users_to_router 'allow tcp port 53'
	list users_to_router 'allow udp port 67'
	list users_to_router 'allow tcp port 22'
	list users_to_router 'allow tcp port 443'
	# หมายเหตุ: ไม่ต้องใส่พอร์ต 80 -- openNDS มีกฎ nat ตายตัว "ip daddr <gateway> tcp dport 80 redirect to
	# :gatewayport" ส่งทุกคำขอพอร์ต 80 ไปหน้าของ openNDS เองเสมอ (พบบน Pi 2026-10-03) ลูกค้าดูเวลาที่เหลือ
	# จึงใช้ http://cafe.wifi:${FAS_PORT} แทน (พอร์ต FAS ซึ่ง openNDS อนุญาตให้ทุกเครื่องอยู่แล้ว)
	list users_to_router 'allow tcp port ${ADMIN_PORT}'

	# walled garden: ต้องเปิดให้ OS ตรวจเจอ captive portal
	list walledgarden_fqdn_list 'captive.apple.com'
	list walledgarden_fqdn_list 'connectivitycheck.gstatic.com'
	list walledgarden_fqdn_list 'www.msftconnecttest.com'
	list walledgarden_fqdn_list 'detectportal.firefox.com'
	list walledgarden_fqdn_list 'nmcheck.gnome.org'
${nds_trusted_block}
NDS
  ok "เขียน /etc/config/opennds (รูปแบบ UCI — ตัวที่ openNDS อ่านจริง)"
}

install_services() {
  step "ติดตั้ง service"
  if [[ "$INIT_SYS" != systemd ]]; then
    warn "ไม่ใช่ systemd — ข้ามการสร้าง unit (ต้องเขียน init script เอง)"
    return 0
  fi

  # แก้บั๊ก (พบตอนตรวจทานรอบ 2): เดิม --workers 2 แต่ rate-limit (_attempts dict) และ
  # SECRET_KEY fallback ใน admin/app.py กับ fas/app.py เป็น in-memory ต่อ "โปรเซส" -- gunicorn
  # worker คือคนละโปรเซสกัน ไม่ได้แชร์หน่วยความจำ ทำให้ limit จริงกลายเป็น 2 เท่าของที่ตั้งไว้
  # (เช่น 5 ครั้ง/10 นาที กลายเป็นได้ถึง 10 ครั้งถ้า request กระจายไปคนละ worker) และรีเซ็ต
  # ทุกครั้งที่ worker ถูก respawn -- ใช้ --workers 1 --threads 4 แทน (thread ใน process
  # เดียวกันแชร์หน่วยความจำได้ปกติ ยังรับ concurrent request ได้ปกติผ่าน thread ไม่ใช่ process)
  # ตรงกับที่ comment ในโค้ดเขียนไว้แต่แรกว่า "พอสำหรับ 1 เครื่อง; ถ้าขยายหลาย worker ให้ย้ายไป DB"
  #
  # ข้อแลกเปลี่ยนที่ตั้งใจ (ชัดเจนไว้ก่อน พบตอนตรวจทานรอบ 4): --workers 1 แปลว่าไม่มี worker
  # สำรอง -- ถ้า request หนึ่งค้าง (เช่น query ช้าผิดปกติ) worker เดียวนั้นจะไม่ตอบ request อื่น
  # จนกว่า gunicorn arbiter จะตรวจพบว่าเกิน --timeout 60 วินาทีแล้ว "ฆ่า+เกิดใหม่" worker ให้เอง
  # อัตโนมัติ (เป็นกลไกของ gunicorn เอง ไม่ต้องพึ่ง systemd Restart=on-failure) -- ผลคือระบบ
  # หยุดตอบสนองได้นานสุด ~60 วินาทีระหว่างนั้น ก่อนจะกลับมาใช้งานได้เองโดยไม่ต้องมีใครเข้าไปแตะ
  # ยอมรับข้อแลกเปลี่ยนนี้เพราะสเกลของระบบ (คาเฟ่ร้านเดียว) กับความถูกต้องของ rate-limit/
  # SECRET_KEY สำคัญกว่า -- ถ้าจะขยายเป็นหลาย worker ในอนาคตจริง ๆ ต้องย้าย rate-limit ไป DB
  # ก่อนเสมอ (ตามที่ comment เดิมบอกไว้)
  local name desc mod port
  for spec in "cafe-fas|Cafe WiFi Captive Portal (FAS)|fas.app|${FAS_BACKEND}" \
              "cafe-admin|Cafe WiFi Admin Panel|admin.app|${ADMIN_BACKEND}"; do
    IFS='|' read -r name desc mod port <<< "$spec"
    write_file "/etc/systemd/system/${name}.service" 0644 <<UNIT
[Unit]
Description=${desc}
After=network-online.target mariadb.service
Wants=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${OPT_DIR}
EnvironmentFile=${ETC_DIR}/secrets.env
Environment=PYTHONPATH=${OPT_DIR}
ExecStart=${VENV_DIR}/bin/gunicorn --workers 1 --threads 4 --timeout 60 --bind 127.0.0.1:${port} --access-logfile ${LOG_DIR}/${name}-access.log --error-logfile ${LOG_DIR}/${name}-error.log ${mod}:app
Restart=on-failure
RestartSec=5

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${LOG_DIR} ${ETC_DIR}
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes

[Install]
WantedBy=multi-user.target
UNIT
  done

  # แก้บั๊ก M3: เดิม User=root แบบไม่มี hardening directive เลยสักบรรทัด ทั้งที่ service
  # ที่สิทธิ์น้อยกว่า (cafe-admin/cafe-fas) กลับได้ hardening ครบชุด -- รันเป็นผู้ใช้ธรรมดา
  # แล้วให้เฉพาะ CAP_NET_ADMIN/CAP_NET_RAW ที่ conn_collector.py ต้องใช้เรียก `conntrack -E`
  # ผ่าน AmbientCapabilities+CapabilityBoundingSet (จำกัดไม่ให้ได้สิทธิ์อื่นเกินสองตัวนี้)
  # หมายเหตุ: RestrictAddressFamilies ต้องเปิด AF_NETLINK ด้วย (ไม่เหมือน cafe-admin/cafe-fas)
  # เพราะ conntrack ใช้ netlink socket คุยกับเคอร์เนล -- ถ้าลืมเปิดจะรันไม่ได้เงียบ ๆ
  write_file /etc/systemd/system/cafe-logger.service 0644 <<UNIT
[Unit]
Description=Cafe WiFi connection/DNS log collector
# N23: time-sync.target -- ห้ามเขียน log ก่อนนาฬิกา sync (Pi 4 ไม่มี RTC บูตมาเวลาผิดได้หลายวัน)
After=network-online.target mariadb.service dnsmasq.service cafe-wifi-conntrack-acct.service time-sync.target
Wants=cafe-wifi-conntrack-acct.service time-sync.target

[Service]
# N31 (รอบสอง 2026-09-20): ตัวอ่านเหตุการณ์ conntrack ต้องได้ CPU ก่อนงานอื่น ถ้าอ่านช้าบัฟเฟอร์
# netlink จะล้นแล้วเคอร์เนลทิ้งเหตุการณ์ทิ้ง = หลักฐานขาดโดยไม่มีใครรู้ (ENOBUFS)
Nice=-5
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${OPT_DIR}
EnvironmentFile=${ETC_DIR}/secrets.env
Environment=PYTHONPATH=${OPT_DIR}
ExecStart=${VENV_DIR}/bin/python -m logger.run_all
Restart=on-failure
RestartSec=10
# R2-06: SIGTERM ไปที่ python ตัวเดียว ให้มันปิด conntrack เองหลังดูดเหตุการณ์ที่ค้างในท่อ -- ค่าปริยาย
# (control-group) ส่งถึง conntrack พร้อมกัน ถ้ามันตายก่อน จะดูเหมือน crash และข้ามขั้นตอนดูดคิว
KillMode=mixed
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
# R2-06: ต้องเขียนได้ -- collector-*.json (สถานะที่หน้า Admin อ่าน) และตำแหน่งที่อ่าน dnsmasq.log
# ถึง (อ่านต่อหลัง restart) อยู่ใน LOG_DIR เดิมไม่มีบรรทัดนี้ ProtectSystem=strict ทำให้เขียนไม่ได้เงียบ ๆ
ReadWritePaths=${LOG_DIR}
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LockPersonality=yes

[Install]
WantedBy=multi-user.target
UNIT

  # แก้บั๊ก C2/M5 (ผลข้างเคียง): เติม `-` นำหน้าทุกบรรทัด ExecStart -- เดิมถ้าคำสั่งไหนคำสั่ง
  # หนึ่งพัง (exit code != 0) systemd oneshot จะหยุดทั้งหน่วยทันที ทำให้คำสั่งถัดไปในหน่วย
  # เดียวกันไม่ถูกรันตามไปด้วยแบบเงียบ ๆ (นี่คือกลไกที่ทำให้บั๊ก C2 ลามไปกระทบ integrity/
  # check_time ทั้งที่ไม่เกี่ยวกัน) `-` บอก systemd ให้ไม่สนใจ exit code ของบรรทัดนั้นแล้ว
  # ไปรันบรรทัดถัดไปต่อเสมอ -- ความล้มเหลวแต่ละงานยังคงถูกบันทึกลง journal ให้ตรวจสอบได้
  # แก้บั๊ก H4: เพิ่ม backup_db (สำรอง DB รายวัน หลัง purge เพื่อให้ backup มีขนาดเล็กลง)
  # N1 (CODING_BRIEF.md): เพิ่ม check_disk ต่อจาก backup_db -- แจ้งเตือนดิสก์ใกล้เต็มก่อนที่
  # การเขียน log ตามกฎหมายจะหยุดทำงานเงียบ ๆ (ดู Risk Register R5 ใน PROJECT_PLAN.md)
  write_file /etc/systemd/system/cafe-maintenance.service 0644 <<UNIT
[Unit]
Description=Cafe WiFi daily maintenance (retention purge + DB backup + disk check + log integrity + time check)

[Service]
Type=oneshot
EnvironmentFile=${ETC_DIR}/secrets.env
Environment=PYTHONPATH=${OPT_DIR}
WorkingDirectory=${OPT_DIR}
ExecStart=-${VENV_DIR}/bin/python -m tools.purge_old_data
ExecStart=-${VENV_DIR}/bin/python -m tools.backup_db
ExecStart=-${VENV_DIR}/bin/python -m tools.check_disk
ExecStart=-${VENV_DIR}/bin/python -m logger.integrity
ExecStart=-${OPT_DIR}/check_time.sh
UNIT

  write_file /etc/systemd/system/cafe-maintenance.timer 0644 <<'UNIT'
[Unit]
Description=Run cafe-wifi maintenance daily

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
UNIT

  # แก้บั๊ก H3/M1: บังคับอายุ voucher จริง + ปิด session ค้าง -- ต้องรันถี่กว่างาน
  # maintenance รายคืนมาก เพราะเป็นการบังคับสิทธิ์การเข้าถึงเครือข่าย ไม่ใช่แค่ housekeeping
  # (ทุก 5 นาที คือ ความคลาดเคลื่อนสูงสุดที่ลูกค้าจะใช้เน็ตเกินเวลาที่จ่ายไว้ได้)
  # ✅ ยืนยันบน Pi จริงแล้ว (2026-09-16) ว่าข้อกังวลที่เคยเขียนเตือนไว้ตรงนี้เป็นจริง และ
  # ร้ายแรงกว่าที่คิด: unit นี้เคยรันเป็น ${APP_USER} + NoNewPrivileges + PrivateTmp แล้ว
  # `ndsctl deauth` ล้มเหลวทุกครั้ง ด้วยสองสาเหตุพร้อมกัน
  #   1. อ่าน /etc/config/opennds ไม่ได้ (0640 root:root) -> "Permission denied"
  #   2. PrivateTmp=yes ทำให้ service มี /tmp ของตัวเอง มองไม่เห็น /tmp/ndsctl.sock ของ
  #      openNDS -> "opennds probably not yet started (No such file or directory)"
  # ผลจริงคือ **เพิกถอน/หมดอายุ voucher แล้วตัดลูกค้าไม่ออก** ฐานข้อมูลบันทึกว่าปิด session
  # แล้ว แต่ลูกค้ายังออกเน็ตได้ปกติ แถมทราฟฟิกหลังจากนั้นถูกนับเข้า session ที่ปิดไปแล้ว
  # (NoNewPrivileges=yes ยังปิดทางแก้ด้วย sudo ไปด้วยอีกชั้น) จึงต้องรันเป็น root +
  # PrivateTmp=no -- ยังคง ProtectSystem=strict/ProtectHome ไว้ตามเดิม งานนี้อ่าน /etc
  # อย่างเดียวและเขียนแค่ DB ผ่าน TCP
  write_file /etc/systemd/system/cafe-enforce.service 0644 <<UNIT
[Unit]
Description=Cafe WiFi voucher expiry enforcement (deauth + close stale sessions)
After=network-online.target mariadb.service

[Service]
Type=oneshot
EnvironmentFile=${ETC_DIR}/secrets.env
Environment=PYTHONPATH=${OPT_DIR}
WorkingDirectory=${OPT_DIR}
ExecStart=${VENV_DIR}/bin/python -m tools.enforce_voucher_expiry

NoNewPrivileges=yes
PrivateTmp=no
ProtectSystem=strict
# ต้องเปิด /tmp ให้เขียนได้ ไม่งั้นต่อ unix socket /tmp/ndsctl.sock ไม่ได้ (ProtectSystem=strict
# ทำให้ทั้งระบบไฟล์เป็น read-only ซึ่งรวม /tmp ด้วย และ connect() ต้องมีสิทธิ์เขียนที่ socket)
# ยืนยันบน Pi จริง: strict เปล่า ๆ -> ndsctl ตายพร้อม "Unable to open [/etc/localtime]" exit 5
ReadWritePaths=/tmp
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
UNIT

  write_file /etc/systemd/system/cafe-enforce.timer 0644 <<'UNIT'
[Unit]
Description=Run cafe-wifi voucher expiry enforcement every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
UNIT

  write_file /etc/systemd/system/cafe-reconcile.service 0644 <<UNIT
[Unit]
Description=Confirm pending Cafe WiFi sessions with openNDS
After=mariadb.service opennds.service

[Service]
Type=oneshot
User=root
EnvironmentFile=${ETC_DIR}/secrets.env
Environment=PYTHONPATH=${OPT_DIR}
WorkingDirectory=${OPT_DIR}
ExecStart=${VENV_DIR}/bin/python -m tools.reconcile_pending
NoNewPrivileges=yes
PrivateTmp=no
ProtectSystem=strict
ReadWritePaths=/tmp
ProtectHome=yes
UNIT

  write_file /etc/systemd/system/cafe-reconcile.timer 0644 <<'UNIT'
[Unit]
Description=Check pending Cafe WiFi sessions every 5 seconds

[Timer]
OnBootSec=5sec
OnUnitInactiveSec=5sec

[Install]
WantedBy=timers.target
UNIT

  # N10 (CODING_BRIEF.md): bypass_detector.py (T17) -- แค่อ่าน /proc/net/arp (world-readable
  # ปกติ ไม่ต้อง CAP_NET_ADMIN/RAW) แล้วต่อ DB ผ่าน TCP ธรรมดา จึงรันเป็น ${APP_USER} พร้อม
  # hardening ชุดเดียวกับ cafe-enforce ได้เลย -- รันถี่กว่า (ทุก 1 นาที) เพราะ ARP cache ของ
  # เคอร์เนลหมดอายุเร็ว (ดู docstring ของไฟล์นั้นเรื่อง polling ที่พลาดอุปกรณ์เชื่อมต่อสั้น ๆ ได้)
  write_file /etc/systemd/system/cafe-bypass-detect.service 0644 <<UNIT
[Unit]
Description=Cafe WiFi bypass detector (T17 -- เฝ้าวง uplink หา IP/MAC แปลกปลอม)
After=network-online.target mariadb.service

[Service]
Type=oneshot
User=${APP_USER}
Group=${APP_USER}
EnvironmentFile=${ETC_DIR}/secrets.env
Environment=PYTHONPATH=${OPT_DIR}
WorkingDirectory=${OPT_DIR}
ExecStart=${VENV_DIR}/bin/python -m logger.bypass_detector

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
UNIT

  write_file /etc/systemd/system/cafe-bypass-detect.timer 0644 <<'UNIT'
[Unit]
Description=Run cafe-wifi bypass detector every 1 minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
UNIT

  run systemctl daemon-reload
  ok "สร้าง systemd unit แล้ว"
}

configure_nginx() {
  step "ตั้งค่า Nginx (reverse proxy + TLS)"
  local lan_ip="${CLIENT_CIDR%%/*}" cert="${ETC_DIR}/tls"  # IP ฝั่งลูกค้า -- cert ครอบคลุม cafe.wifi ที่ลูกค้าเห็น
  run install -d -m 0750 -o root -g "$APP_USER" "$cert"

  if [[ ! -f "${cert}/server.crt" ]] && (( ! DRY_RUN )); then
    openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
      -keyout "${cert}/server.key" -out "${cert}/server.crt" \
      -subj "/C=TH/O=Cafe WiFi Gateway/CN=cafe.wifi" \
      -addext "subjectAltName=DNS:cafe.wifi,DNS:localhost,IP:${lan_ip}" >/dev/null 2>&1
    chmod 0640 "${cert}/server.key"; chown root:"$APP_USER" "${cert}/server.key"
    ok "สร้าง self-signed certificate (825 วัน)"
  fi

  local sites=/etc/nginx/conf.d
  [[ -d /etc/nginx/sites-available ]] && sites=/etc/nginx/sites-available

  write_file "${sites}/${APP_NAME}.conf" 0644 <<NGINX
# ---- Captive Portal (ต้องเป็น HTTP ลูกค้าถึงจะเด้งได้) ----
server {
    listen ${FAS_PORT};
    listen 80 default_server;
    server_name cafe.wifi _;
    access_log ${LOG_DIR}/portal-access.log;

    location / {
        proxy_pass http://127.0.0.1:${FAS_BACKEND};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        # แก้บั๊ก C3: proxy_add_x_forwarded_for "ต่อท้าย" ค่าที่ไคลเอนต์ส่งมาเอง ทำให้ตัวแรก
        # ใน header (ที่แอปเคยหยิบไปใช้) เป็นค่าที่ผู้โจมตีปลอมได้ตรง ๆ -- เขียนทับด้วย
        # \$remote_addr แทน (เชื่อถือได้เสมอเพราะ nginx เป็นคนกำหนดเอง ไม่รับต่อจากไคลเอนต์)
        proxy_set_header X-Forwarded-For \$remote_addr;
    }
}

# ---- Admin Panel (HTTPS เท่านั้น) ----
server {
    listen ${ADMIN_PORT} ssl;
    server_name cafe.wifi _;

    ssl_certificate     ${ETC_DIR}/tls/server.crt;
    ssl_certificate_key ${ETC_DIR}/tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    access_log ${LOG_DIR}/admin-access.log;
    client_max_body_size 4m;

    location / {
        proxy_pass http://127.0.0.1:${ADMIN_BACKEND};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;  # แก้บั๊ก C3 (ดูหมายเหตุด้านบน)
        proxy_set_header X-Forwarded-Proto https;
    }
}
NGINX

  if [[ -d /etc/nginx/sites-enabled ]]; then
    run_sh "rm -f /etc/nginx/sites-enabled/default"
    run_sh "ln -sf '${sites}/${APP_NAME}.conf' /etc/nginx/sites-enabled/${APP_NAME}.conf"
  fi

  if run_sh "nginx -t >/dev/null 2>&1"; then
    svc enable nginx
    svc restart nginx
    ok "Nginx พร้อม"
  else
    warn "nginx -t ไม่ผ่าน — ตรวจสอบ ${sites}/${APP_NAME}.conf"
  fi
  return 0
}

configure_logrotate() {
  step "ตั้งค่า log rotation (เก็บ ${LOG_RETENTION_DAYS} วัน)"
  # N3 (CODING_BRIEF.md): §6.1 กำหนดว่า log ต้อง "แก้ไขไม่ได้" ตาม ม.26 -- เดิมมีแค่ hash
  # chain (logger/integrity.py) ที่ "ตรวจจับ" การแก้ไขย้อนหลังได้ แต่ไม่มีอะไร "ป้องกัน" การ
  # แก้ไขไฟล์ที่หมุนแล้วโดยตรงเลย -- เพิ่ม chattr +a (append-only) ให้ไฟล์ที่หมุนแล้วใน
  # olddir เขียนทับ/ลบไม่ได้แม้แต่ root เอง (ต้อง chattr -a ก่อนเสมอ ซึ่งเป็นร่องรอยที่ตรวจสอบได้)
  #
  # หมายเหตุสำคัญ (ป้องกันปัญหาที่จะเกิดจริงถ้าไม่คิดล่วงหน้า): ไฟล์ที่เป็น append-only จะถูก
  # logrotate เอง "ลบไม่ได้" เมื่อเกิน `rotate ${LOG_RETENTION_DAYS}` รอบ (unlink บนไฟล์ +a ทำ
  # ไม่ได้แม้จะเป็น root ก็ตาม ต้อง chattr -a ก่อนเสมอ) -- แก้ด้วยการ chattr -a ทุกไฟล์ใน
  # olddir ใน prerotate (ก่อน logrotate ลบไฟล์เก่าที่เกิน retention) แล้วค่อย chattr +a กลับ
  # ทุกไฟล์อีกครั้งใน postrotate (หลังไฟล์ใหม่ถูกหมุนเข้ามาแล้ว) -- ช่วงระหว่าง prerotate ถึง
  # postrotate (เสี้ยววินาทีตอนรัน logrotate เอง) ไฟล์จะไม่มี +a ชั่วคราว เป็นข้อแลกเปลี่ยนที่
  # ยอมรับได้เพื่อให้ retention/disk-space ยังทำงานได้จริง ไม่ใช่ทำจนลบไฟล์เก่าไม่ได้เลยตลอดไป
  #
  # ต้องกันกรณี filesystem ไม่รองรับ extended attribute นี้ด้วย (เช่น FAT/overlay บางแบบ) --
  # `|| true` ทุกจุดให้เป็นแค่ warning ไม่ใช่ error ที่ทำให้ logrotate รอบนั้นล้มทั้งหมด
  write_file "/etc/logrotate.d/${APP_NAME}" 0644 <<ROT
# managed by ${APP_NAME} installer
${LOG_DIR}/*.log {
    daily
    # งาน logger.integrity ตรวจ hash และบันทึกการลบตามอายุเอง
    rotate -1
    missingok
    notifempty
    compress
    delaycompress
    dateext
    dateformat -%Y-%m-%d
    create 0640 ${APP_USER} ${APP_USER}
    olddir ${LOG_DIR}/archive
    sharedscripts
    prerotate
        chattr -a ${LOG_DIR}/archive/*.log-* 2>/dev/null || true
    endscript
    postrotate
        systemctl reload nginx    >/dev/null 2>&1 || true
        systemctl restart dnsmasq >/dev/null 2>&1 || true
        # N26: gunicorn เขียน log ลงไฟล์ตรง ๆ (--access-logfile/--error-logfile) ถ้าไม่สั่งให้
        # เปิดไฟล์ใหม่ มันจะเขียนต่อลงไฟล์เก่าที่ถูกย้ายไป archive และผนึกไปแล้ว (เจอจริงบน Pi:
        # hash_mismatch) และถ้าไฟล์นั้นถูกบีบอัด+ลบในรอบถัดไป log ที่เขียนต่อจะหายถาวร
        # USR1 = วิธีมาตรฐานของ gunicorn ในการเปิดไฟล์ log ใหม่ ไม่ตัดการเชื่อมต่อของลูกค้า
        systemctl kill -s USR1 --kill-whom=main cafe-fas.service cafe-admin.service >/dev/null 2>&1 || true
        chattr +a ${LOG_DIR}/archive/*.log-* 2>/dev/null || echo "warning: chattr +a ไม่สำเร็จ (filesystem อาจไม่รองรับ) — log ที่หมุนแล้วจะไม่ใช่ append-only" >&2
    endscript
    # หมายเหตุ (แก้บั๊ก M5): เดิมเรียก logger.integrity ตรงนี้ด้วย แต่ไม่มี PYTHONPATH/
    # EnvironmentFile ให้เลย (logrotate รันเอง ไม่ผ่าน systemd unit) ทำให้ import โมดูล
    # หรือต่อ DB ไม่ได้เสมอ แล้วก็ถูก \`|| true\` กลบ error ไว้เงียบ ๆ -- cafe-maintenance.timer
    # (03:30 ทุกคืน) เรียก logger.integrity พร้อม env ที่ครบอยู่แล้ว ไม่ต้องเรียกซ้ำที่นี่
}
ROT
  ok "logrotate พร้อม (archive ที่ ${LOG_DIR}/archive, ไฟล์ที่หมุนแล้วเป็น append-only)"
}

start_services() {
  step "เปิดใช้งาน service"
  if [[ "$INIT_SYS" != systemd ]]; then warn "ข้าม"; return 0; fi
  local s
  # แก้บั๊ก (พบตอนรันทับบน Pi จริง 2026-10-02): `enable --now` start เฉพาะ service ที่ยังไม่รัน --
  # รัน install.sh ซ้ำเพื่ออัปเดตโค้ด gunicorn/logger ตัวเดิมจึงรันโค้ดเก่าในหน่วยความจำต่อ ขณะที่
  # template บนดิสก์เป็นของใหม่แล้ว (หน้า Admin 500: 'csrf_token' is undefined) -- ต้อง restart
  # service ที่รันโค้ดของเราเสมอ (ไม่แตะ opennds: restart = ลูกค้าที่ออนไลน์หลุดทั้งร้าน)
  for s in cafe-fas cafe-admin; do
    run systemctl enable "$s" 2>/dev/null || true
    run systemctl restart "$s" 2>/dev/null || warn "เปิด ${s} ไม่สำเร็จ — ตรวจด้วย: systemctl status ${s}"
  done
  for s in cafe-maintenance.timer cafe-enforce.timer; do
    run systemctl enable --now "$s" 2>/dev/null || warn "เปิด ${s} ไม่สำเร็จ — ตรวจด้วย: systemctl status ${s}"
  done
  if (( ! SKIP_NETWORK )); then
    # restart ปลอดภัย: R2-06 ให้ collector flush ของที่ค้างก่อนออก และ dns_collector อ่านต่อจากตำแหน่งเดิม
    run systemctl enable cafe-logger 2>/dev/null || true
    run systemctl restart cafe-logger 2>/dev/null || warn "เปิด cafe-logger ไม่สำเร็จ"
    # ไม่ปิด stderr แล้ว (เดิม 2>/dev/null ซ่อนเหตุผลจริงไว้ ทำให้ debug ไม่ได้เวลา enable ล้ม)
    run systemctl enable --now opennds || {
      warn "เปิด opennds ไม่สำเร็จในรอบแรก — daemon-reload ซ้ำแล้วลองใหม่อีกครั้ง"
      run_sh "systemctl daemon-reload"
      run systemctl enable --now opennds || warn "เปิด opennds ไม่สำเร็จ — เริ่มเองด้วยคำสั่ง: systemctl start opennds"
    }
    # N10 (CODING_BRIEF.md): ต้องมี eth0/UPLINK_CIDR ตั้งค่าแล้วถึงจะมี ARP table ของวง uplink
    # ให้เฝ้าจริง -- ผูกไว้กับเงื่อนไขเดียวกับ cafe-logger/opennds
    run systemctl enable --now cafe-bypass-detect.timer 2>/dev/null || warn "เปิด cafe-bypass-detect.timer ไม่สำเร็จ"
    run systemctl enable --now cafe-reconcile.timer 2>/dev/null || warn "เปิด cafe-reconcile.timer ไม่สำเร็จ"
  fi
  ok "เปิด service เรียบร้อย"
}

write_state() {
  if (( DRY_RUN )); then return 0; fi
  write_file "$STATE_FILE" 0640 "root:${APP_USER}" <<STATE
INSTALLED_AT=$(date -Iseconds)
INSTALLER_VERSION=${APP_VERSION}
DISTRO=${DISTRO_NAME}
PKG=${PKG}
INIT=${INIT_SYS}
NIC=${NIC}
UPLINK_CIDR=${UPLINK_CIDR}
UPLINK_GW=${UPLINK_GW}
CLIENT_CIDR=${CLIENT_CIDR}
ADMIN_PORT=${ADMIN_PORT}
FAS_PORT=${FAS_PORT}
DB_NAME=${DB_NAME}
ENABLE_PARTITIONS=${ENABLE_PARTITIONS}
STATE
}

# ============================================================================
#  6. สรุปหลังติดตั้ง + first-run setup
# ============================================================================
final_summary() {
  # แก้บั๊ก (เดิมชี้ไป CLIENT_CIDR/IP ฝั่งลูกค้า): nftables ปิดไม่ให้วง CLIENT_NET เข้า
  # ADMIN_PORT ไว้เอง (T8) พนักงานต้องเข้าจากฝั่งอัพลิงก์/เราเตอร์เท่านั้น ดู PROJECT_PLAN.md §15
  local lan_ip="${UPLINK_CIDR%%/*}" token="<ดูที่ ${ETC_DIR}/setup.token>"  # หน้า /setup เข้าจาก IP ฝั่งอัพลิงก์เท่านั้น
  if [[ -f "${ETC_DIR}/setup.token" ]] && (( ! DRY_RUN )); then
    token="$(cat "${ETC_DIR}/setup.token")"
  fi

  printf '\n%s============================================================%s\n' "$C_GRN" "$C_RST"
  printf '%s  ติดตั้งเสร็จสมบูรณ์  --  %s v%s%s\n'  "$C_GRN" "$APP_NAME" "$APP_VERSION" "$C_RST"
  printf '%s============================================================%s\n\n' "$C_GRN" "$C_RST"

  printf '  %sขั้นตอนถัดไป: สร้างบัญชีผู้ดูแลระบบหลัก%s\n\n' "$C_YEL" "$C_RST"
  printf '    1) เปิดเบราว์เซอร์จากเครื่องพนักงาน ไปที่\n\n'
  printf '         %shttps://%s:%s/setup%s\n\n' "$C_BLU" "$lan_ip" "$ADMIN_PORT" "$C_RST"
  printf '       (เป็น self-signed cert เบราว์เซอร์จะเตือน — กด Advanced > Proceed)\n\n'
  printf '    2) กรอก Setup Token นี้\n\n'
  printf '         %s%s%s\n\n' "$C_BLU" "$token" "$C_RST"
  printf '    3) ตั้ง username / รหัสผ่านของผู้ดูแลระบบหลัก\n\n'
  printf '  %sหน้า /setup จะปิดตัวเองถาวรทันทีที่สร้างบัญชีแรกสำเร็จ%s\n' "$C_DIM" "$C_RST"
  printf '  %sและไฟล์ %s/setup.token จะถูกลบอัตโนมัติ%s\n\n' "$C_DIM" "$ETC_DIR" "$C_RST"

  printf '  ------------------------------------------------------------\n'
  printf '  ไฟล์สำคัญ\n'
  printf '    โปรแกรม         : %s\n' "$OPT_DIR"
  printf '    กุญแจเข้ารหัส    : %s/secrets.env  %s<-- สำรองไว้! ถ้าหายถอดรหัสข้อมูลเดิมไม่ได้%s\n' "$ETC_DIR" "$C_RED" "$C_RST"
  printf '    Log             : %s\n' "$LOG_DIR"
  printf '    ฐานข้อมูล        : %s (localhost)\n\n' "$DB_NAME"
  printf '  คำสั่งที่ใช้บ่อย\n'
  printf '    systemctl status cafe-admin cafe-fas cafe-logger cafe-enforce.timer cafe-bypass-detect.timer\n'
  printf '    journalctl -u cafe-admin -f\n'
  printf '    chronyc tracking            # ความคลาดเคลื่อนนาฬิกา ต้อง < 10 ms\n'
  printf '    nft list ruleset            # ดู firewall\n'
  printf '    sudo %s --uninstall\n' "$0"
  printf '  ------------------------------------------------------------\n\n'
}

# ============================================================================
#  7. Uninstall
# ============================================================================
uninstall() {
  step "ถอนการติดตั้ง ${APP_NAME}"
  warn "จะหยุด service และลบไฟล์โปรแกรม"
  warn "ฐานข้อมูล '${DB_NAME}' และ log จะไม่ถูกลบ (ต้องลบเองถ้าต้องการ)"
  confirm "ยืนยันถอนการติดตั้ง" || die "ยกเลิก"

  local s
  for s in cafe-fas cafe-admin cafe-logger cafe-maintenance.timer cafe-maintenance \
          cafe-enforce.timer cafe-enforce cafe-reconcile.timer cafe-reconcile \
          cafe-bypass-detect.timer cafe-bypass-detect opennds; do
    svc disable "$s"
    run_sh "rm -f /etc/systemd/system/${s}.service /etc/systemd/system/${s}.timer"
  done
  run_sh "systemctl daemon-reload 2>/dev/null || true"
  run_sh "rm -f /etc/dnsmasq.d/${APP_NAME}.conf"
  run_sh "rm -f /etc/nginx/conf.d/${APP_NAME}.conf /etc/nginx/sites-available/${APP_NAME}.conf /etc/nginx/sites-enabled/${APP_NAME}.conf"
  run_sh "rm -f /etc/logrotate.d/${APP_NAME} /etc/sysctl.d/99-${APP_NAME}.conf"
  run_sh "rm -rf '${OPT_DIR}'"
  run_sh "systemctl restart dnsmasq 2>/dev/null || true"
  run_sh "systemctl reload nginx 2>/dev/null || true"
  ok "ถอนการติดตั้งเสร็จ"

  printf '\n  สิ่งที่ %sยังเหลืออยู่%s (ลบเองถ้าต้องการ)\n' "$C_YEL" "$C_RST"
  printf '    %-24s กุญแจเข้ารหัส %sห้ามลบถ้ายังต้องถอดรหัสข้อมูลเดิม%s\n' "$ETC_DIR" "$C_RED" "$C_RST"
  printf '    %-24s log ตามกฎหมาย (ต้องเก็บ >= 90 วัน)\n' "$LOG_DIR"
  printf '    %-24s backup DB %sมี natid_enc เข้ารหัสอยู่ ต้องมี secrets.env คู่กันถึงถอดได้%s\n' "$BACKUP_DIR" "$C_RED" "$C_RST"
  printf '    %-24s ลบด้วย: mysql -e "DROP DATABASE %s;"\n' "database ${DB_NAME}" "$DB_NAME"
  printf '    %-24s ลบด้วย: userdel %s\n' "user ${APP_USER}" "$APP_USER"
  printf '    %-24s firewall rules\n\n' "/etc/nftables.conf"
}

# ============================================================================
#  main
# ============================================================================
main() {
  parse_args "$@"

  printf '\n%s  Cafe Wi-Fi Gateway & Management System%s\n'   "$C_GRN" "$C_RST"
  printf '%s  Universal Linux Installer v%s%s\n\n'            "$C_DIM" "$APP_VERSION" "$C_RST"
  if (( DRY_RUN )); then warn "โหมด DRY-RUN: แสดงคำสั่งอย่างเดียว ไม่แก้ไขระบบจริง"; fi

  require_root
  detect_distro
  detect_init

  if (( DO_UNINSTALL )); then uninstall; exit 0; fi

  if (( INTERACTIVE )); then wizard; fi

  # ตรวจหลัง wizard แต่ก่อนสร้าง log directory หรือแก้ค่าใด ๆ ทั้งโหมดปกติและ -y
  [[ "$LOG_RETENTION_DAYS" =~ ^[0-9]+$ ]] || die "retention-days ต้องเป็นจำนวนวันเต็ม"
  (( 10#$LOG_RETENTION_DAYS >= 90 )) || die "retention-days ต้องไม่น้อยกว่า 90 วัน"

  if (( ! DRY_RUN )); then
    install -d -m 0750 "$LOG_DIR"
    exec > >(tee -a "${LOG_DIR}/install.log") 2>&1
  fi

  preflight

  create_user_and_dirs
  ensure_uplink_before_packages   # N37: ย้ายเครื่องมาเครือข่ายใหม่แล้วรันซ้ำต้องไม่ค้างที่ apt/pip
  install_packages
  gen_secrets
  setup_python
  install_app_files
  setup_database
  configure_time
  configure_backup_usb
  configure_network
  build_opennds
  install_services
  configure_nginx
  configure_logrotate
  start_services
  write_state
  final_summary
}

main "$@"
