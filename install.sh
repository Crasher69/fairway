#!/usr/bin/env bash
#
# install.sh — установка fairway как systemd-сервиса.
#
# Работает на RHEL/Rocky/Alma/CentOS Stream/Fedora и Debian/Ubuntu: всё, что
# у них различается (firewalld или ufw, SELinux, путь к nologin), скрипт
# определяет сам.
#
# Скрипт можно запускать как рядом с бинарником, так и в одиночку:
# если бинарника рядом нет, он скачается с GitHub.
#
#     sudo ./install.sh
#
set -euo pipefail

REPO="Crasher69/fairway"
SERVICE_NAME="fairway"
SERVICE_USER="fairway"
BIN_DEST="/usr/local/bin/fairway"
DATA_DIR="/var/lib/fairway"
CONF_DIR="/etc/fairway"
CONF_FILE="${CONF_DIR}/config.json"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

DEFAULT_PROXY_ADDR=":8080"
DEFAULT_ADMIN_ADDR="127.0.0.1:8081"
PROXY_ADDR=""
ADMIN_ADDR=""
VERSION="latest"
BIN_SRC=""
FORCE_DOWNLOAD=0
NO_DOWNLOAD=0
OPEN_FIREWALL=0
ALLOW_FROM=""
UNINSTALL=0

ORIG_ARGS=("$@")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
TMP_DIR=""

# ─── вывод ────────────────────────────────────────────────────────────────────

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m  !\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
    [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
    return 0
}
trap cleanup EXIT

usage() {
    cat <<'USAGE'
install.sh — установка fairway как systemd-сервиса (RHEL-семейство, Debian, Ubuntu).

Использование:
    sudo ./install.sh [опции]

Бинарник берётся из папки со скриптом, а если его там нет — скачивается
с GitHub releases под архитектуру текущей машины.

Опции:
    --version TAG      версия для скачивания, напр. v0.3.0  (по умолчанию latest)
    --bin PATH         явный путь к готовому бинарнику
    --download         скачать свежий, даже если рядом лежит файл
    --no-download      только локальный файл, в сеть не ходить
    --proxy ADDR       адрес прокси-порта                   (по умолчанию :8080)
    --admin ADDR       адрес веб-панели             (по умолчанию 127.0.0.1:8081)
    --allow-from CIDR  открыть прокси-порт в firewalld/ufw только для этой
                       сети, напр. 203.0.113.0/24; можно повторять
    --open-firewall    открыть прокси-порт в firewalld/ufw для всех
                       (у прокси нет авторизации клиентов, см. README)
    --uninstall        удалить сервис (конфиг и данные остаются)
    -h, --help         эта справка

При обновлении адреса берутся из уже установленного юнита, если --proxy и
--admin не заданы явно.

Примеры:
    sudo ./install.sh                                  # последняя версия
    sudo ./install.sh --version v0.3.0                 # конкретный тег
    sudo ./install.sh --download                       # обновить до свежей
    sudo ./install.sh --proxy :3128 --allow-from 10.0.0.0/8
USAGE
}

# ─── разбор аргументов ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)       VERSION="${2:?--version требует значение}";  shift 2 ;;
        --bin)           BIN_SRC="${2:?--bin требует значение}";      shift 2 ;;
        --proxy)         PROXY_ADDR="${2:?--proxy требует значение}"; shift 2 ;;
        --admin)         ADMIN_ADDR="${2:?--admin требует значение}"; shift 2 ;;
        --allow-from)    ALLOW_FROM+="${ALLOW_FROM:+ }${2:?--allow-from требует значение}"; shift 2 ;;
        --download)      FORCE_DOWNLOAD=1; shift ;;
        --no-download)   NO_DOWNLOAD=1;    shift ;;
        --open-firewall) OPEN_FIREWALL=1;  shift ;;
        --uninstall)     UNINSTALL=1;      shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               die "неизвестная опция: $1 (см. --help)" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "нужны права root. Запустите: sudo $0 ${ORIG_ARGS[*]:-}"
command -v systemctl >/dev/null || die "systemd не найден, скрипт рассчитан на systemd-систему"
[[ -n "$ALLOW_FROM" && $OPEN_FIREWALL -eq 1 ]] \
    && die "--open-firewall и --allow-from вместе не имеют смысла: выберите одно"

# ─── удаление ─────────────────────────────────────────────────────────────────

if [[ $UNINSTALL -eq 1 ]]; then
    info "Удаляю ${SERVICE_NAME}"
    systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$UNIT_FILE" "$BIN_DEST"
    systemctl daemon-reload
    ok "Сервис и бинарник удалены."
    warn "Конфиг и данные остались — удалите вручную, если не нужны:"
    warn "    rm -rf ${DATA_DIR} ${CONF_DIR} && userdel ${SERVICE_USER}"
    warn "Правила firewall, если их открывал установщик, тоже остались."
    exit 0
fi

# ─── адреса ───────────────────────────────────────────────────────────────────

# При обновлении не меняем адреса молча: клиенты уже настроены на старый порт.
unit_flag() {  # unit_flag -proxy → значение из ExecStart установленного юнита
    [[ -f "$UNIT_FILE" ]] || return 0
    sed -n "s/^ExecStart=.*[[:space:]]$1[[:space:]]\+\([^[:space:]]\+\).*/\1/p" "$UNIT_FILE" | head -n 1
}
[[ -n "$PROXY_ADDR" ]] || PROXY_ADDR="$(unit_flag -proxy)"
[[ -n "$ADMIN_ADDR" ]] || ADMIN_ADDR="$(unit_flag -admin)"
PROXY_ADDR="${PROXY_ADDR:-$DEFAULT_PROXY_ADDR}"
ADMIN_ADDR="${ADMIN_ADDR:-$DEFAULT_ADMIN_ADDR}"

PROXY_PORT="${PROXY_ADDR##*:}"
ADMIN_PORT="${ADMIN_ADDR##*:}"
[[ "$PROXY_ADDR" == *:* && "$PROXY_PORT" =~ ^[0-9]+$ ]] || die "не разобрал порт в --proxy ${PROXY_ADDR}, нужен вид HOST:PORT или :PORT"
[[ "$ADMIN_ADDR" == *:* && "$ADMIN_PORT" =~ ^[0-9]+$ ]] || die "не разобрал порт в --admin ${ADMIN_ADDR}, нужен вид HOST:PORT"

case "${ADMIN_ADDR%:*}" in
    127.0.0.1|localhost|"[::1]") ADMIN_LOCAL=1 ;;
    *)                           ADMIN_LOCAL=0 ;;
esac

# ─── архитектура ──────────────────────────────────────────────────────────────

case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)             die "неизвестная архитектура $(uname -m), укажите файл через --bin" ;;
esac

ASSET="fairway-linux-${ARCH}"

# ─── скачивание ───────────────────────────────────────────────────────────────

fetch() {  # fetch URL DEST [quiet]
    local url="$1" dest="$2" quiet="${3:-}"
    if command -v curl >/dev/null; then
        if [[ -n "$quiet" ]]; then
            curl -fsSL -o "$dest" "$url" 2>/dev/null
        else
            curl -fL --progress-bar -o "$dest" "$url"
        fi
    elif command -v wget >/dev/null; then
        if [[ -n "$quiet" ]]; then
            wget -qO "$dest" "$url" 2>/dev/null
        else
            wget -O "$dest" "$url"
        fi
    else
        die "нужен curl или wget, ни того ни другого не нашлось"
    fi
}

download_binary() {
    local base
    if [[ "$VERSION" == "latest" ]]; then
        base="https://github.com/${REPO}/releases/latest/download"
    else
        base="https://github.com/${REPO}/releases/download/${VERSION}"
    fi

    TMP_DIR="$(mktemp -d)"
    local dest="${TMP_DIR}/${ASSET}"

    info "Скачиваю ${ASSET} (${VERSION}) с github.com/${REPO}"
    if ! fetch "${base}/${ASSET}" "$dest"; then
        die "не удалось скачать ${base}/${ASSET}
Проверьте доступ в сеть и что такая версия и архитектура есть в релизах:
    https://github.com/${REPO}/releases"
    fi

    # GitHub на несуществующий файл отдаёт HTML — проверяем магию ELF
    if [[ "$(head -c 4 "$dest" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]]; then
        die "скачался не ELF-бинарник. Возможно, релиза ${VERSION} не существует
или в нём нет файла ${ASSET}. Смотрите https://github.com/${REPO}/releases"
    fi

    local size
    size="$(du -h "$dest" | cut -f1)"
    ok "Скачано (${size})"

    # Контрольные суммы релиз публикует в SHA256SUMS (см. .github/workflows/release.yml).
    local line
    if fetch "${base}/SHA256SUMS" "${TMP_DIR}/SHA256SUMS" quiet \
       && line="$(awk -v f="$ASSET" '$2 == f || $2 == "*" f' "${TMP_DIR}/SHA256SUMS")" \
       && [[ -n "$line" ]]; then
        info "Проверяю контрольную сумму"
        if (cd "$TMP_DIR" && printf '%s\n' "$line" | sha256sum -c --quiet -); then
            ok "Сумма совпала"
        else
            die "контрольная сумма не совпала — файл повреждён или подменён"
        fi
    else
        warn "SHA256SUMS в релизе нет, проверку пропускаю"
    fi

    BIN_SRC="$dest"
}

# ─── откуда берём бинарник ────────────────────────────────────────────────────

if [[ -n "$BIN_SRC" ]]; then
    [[ -f "$BIN_SRC" ]] || die "файл не найден: $BIN_SRC"
    info "Использую указанный файл: $BIN_SRC"
elif [[ $FORCE_DOWNLOAD -eq 1 ]]; then
    download_binary
else
    for candidate in "$ASSET" "fairway"; do
        if [[ -f "${SCRIPT_DIR}/${candidate}" ]]; then
            BIN_SRC="${SCRIPT_DIR}/${candidate}"
            info "Нашёл бинарник рядом со скриптом: $candidate"
            break
        fi
    done

    if [[ -z "$BIN_SRC" ]]; then
        if [[ $NO_DOWNLOAD -eq 1 ]]; then
            die "бинарника нет в ${SCRIPT_DIR}, а --no-download запрещает скачивание"
        fi
        info "Рядом со скриптом бинарника нет — беру из релизов"
        download_binary
    fi
fi

chmod +x "$BIN_SRC" 2>/dev/null || true
if ! "$BIN_SRC" -h >/dev/null 2>&1; then
    die "бинарник $BIN_SRC не запускается. Проверьте, что он под linux-${ARCH}."
fi

# ─── установка ────────────────────────────────────────────────────────────────

if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "Сервис уже запущен — останавливаю на время обновления"
    systemctl stop "$SERVICE_NAME"
fi

if [[ "$BIN_SRC" -ef "$BIN_DEST" ]]; then
    # перенастройка без обновления: sudo ./install.sh --bin /usr/local/bin/fairway --proxy :3128
    info "Бинарник уже на месте: ${BIN_DEST}"
else
    info "Копирую бинарник в ${BIN_DEST}"
    install -m 755 -o root -g root "$BIN_SRC" "$BIN_DEST"
fi
# вернуть правильную метку SELinux (на RHEL/Rocky включён по умолчанию)
if command -v restorecon >/dev/null; then
    restorecon -F "$BIN_DEST" 2>/dev/null || true
fi
ok "Установлен"

if id "$SERVICE_USER" &>/dev/null; then
    ok "Пользователь ${SERVICE_USER} уже есть"
else
    info "Создаю системного пользователя ${SERVICE_USER}"
    # /sbin/nologin на RHEL, /usr/sbin/nologin на Debian/Ubuntu
    NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
    useradd --system --user-group --no-create-home --home-dir "$DATA_DIR" \
            --shell "$NOLOGIN" "$SERVICE_USER"
    ok "Пользователь создан"
fi

info "Готовлю каталоги ${CONF_DIR} и ${DATA_DIR}"
mkdir -p "$DATA_DIR" "$CONF_DIR"
# панель сохраняет правки конфига сама, поэтому каталог должен быть ей доступен
chown -R "${SERVICE_USER}:${SERVICE_USER}" "$DATA_DIR" "$CONF_DIR"
chmod 750 "$DATA_DIR" "$CONF_DIR"
if [[ -f "$CONF_FILE" ]]; then
    ok "Конфиг ${CONF_FILE} уже есть, не трогаю"
else
    # Сам fairway при первом запуске пишет конфиг с allow_direct: true —
    # удобно на своей машине, но на сервере это открытый прокси с IP сервера.
    # Здесь стартовый конфиг строже: без правила домен получает 503.
    info "Пишу стартовый конфиг ${CONF_FILE} (allow_direct: false)"
    install -m 600 -o "$SERVICE_USER" -g "$SERVICE_USER" /dev/null "$CONF_FILE"
    cat > "$CONF_FILE" <<'EOF'
{
  "language": "en",
  "defaults": {
    "allow_direct": false,
    "max_conns_per_proxy": 32,
    "ban_duration": "5m"
  },
  "proxies": [],
  "lists": [],
  "domains": []
}
EOF
fi
ok "Каталоги готовы"

info "Пишу юнит ${UNIT_FILE}"
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Fairway adaptive proxy load balancer
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DEST} -proxy ${PROXY_ADDR} -admin ${ADMIN_ADDR} -config ${CONF_FILE} -data ${DATA_DIR}
WorkingDirectory=${DATA_DIR}
User=${SERVICE_USER}
Group=${SERVICE_USER}
Restart=on-failure
RestartSec=5

# туннель — это пара сокетов, при сотнях клиентов лимит 1024 кончается быстро
LimitNOFILE=65536

# позволяет слушать порты ниже 1024 без root
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

# писать сервису нужно только в конфиг и данные
ProtectSystem=strict
ReadWritePaths=${CONF_DIR} ${DATA_DIR}
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF
ok "Юнит записан"

info "Запускаю сервис"
systemctl daemon-reload
systemctl enable --quiet "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "Сервис работает"
else
    printf '\n'
    systemctl status "$SERVICE_NAME" --no-pager -l || true
    die "сервис не поднялся, см. журнал выше и: journalctl -u ${SERVICE_NAME} -n 50"
fi

# ─── firewall ─────────────────────────────────────────────────────────────────

FIREWALL=""
if systemctl is-active --quiet firewalld 2>/dev/null; then
    FIREWALL="firewalld"
elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "^Status: active"; then
    FIREWALL="ufw"
fi

if [[ $OPEN_FIREWALL -eq 1 || -n "$ALLOW_FROM" ]]; then
    if [[ -z "$FIREWALL" ]]; then
        warn "ни firewalld, ни ufw не активны — открывать нечего."
        warn "Порт ${PROXY_PORT}/tcp и так доступен всем, кто достучится до сервера."
    elif [[ $OPEN_FIREWALL -eq 1 ]]; then
        info "Открываю порт ${PROXY_PORT}/tcp в ${FIREWALL} для всех"
        if [[ "$FIREWALL" == "firewalld" ]]; then
            firewall-cmd --permanent --add-port="${PROXY_PORT}/tcp" >/dev/null
            firewall-cmd --reload >/dev/null
        else
            ufw allow "${PROXY_PORT}/tcp" >/dev/null
        fi
        ok "Порт открыт"
        warn "У прокси нет авторизации: им сможет пользоваться любой, кто знает адрес."
    else
        for net in $ALLOW_FROM; do
            info "Открываю порт ${PROXY_PORT}/tcp в ${FIREWALL} для ${net}"
            if [[ "$FIREWALL" == "firewalld" ]]; then
                family="ipv4"; [[ "$net" == *:* ]] && family="ipv6"
                firewall-cmd --permanent --add-rich-rule="rule family=\"${family}\" source address=\"${net}\" port port=\"${PROXY_PORT}\" protocol=\"tcp\" accept" >/dev/null
            else
                ufw allow proto tcp from "$net" to any port "$PROXY_PORT" >/dev/null
            fi
        done
        [[ "$FIREWALL" == "firewalld" ]] && firewall-cmd --reload >/dev/null
        ok "Доступ открыт для: ${ALLOW_FROM}"
    fi
elif [[ -n "$FIREWALL" ]]; then
    warn "${FIREWALL} активен, порт ${PROXY_PORT}/tcp снаружи закрыт."
    warn "Открыть для своей сети: sudo $0 --allow-from 203.0.113.0/24"
else
    warn "Firewall не найден: порт ${PROXY_PORT}/tcp доступен всем, кто достучится до сервера,"
    warn "а авторизации у прокси нет. Закройте его снаружи или ограничьте по IP (см. README)."
fi

# ─── итог ─────────────────────────────────────────────────────────────────────

printf '\n\033[1;32mГотово.\033[0m Прокси слушает %s, панель — %s\n\n' "$PROXY_ADDR" "$ADMIN_ADDR"

# Токен новый на каждый запуск, поэтому смотрим только журнал текущего.
echo "Ссылка на панель с токеном (из журнала запуска):"
INVOCATION="$(systemctl show -p InvocationID --value "$SERVICE_NAME" 2>/dev/null || true)"
if [[ -z "$INVOCATION" ]] || ! journalctl _SYSTEMD_INVOCATION_ID="$INVOCATION" --no-pager -o cat 2>/dev/null \
     | grep -oE 'https?://[^[:space:]]+token=[^[:space:]]+' | tail -n 1 | sed 's/^/    /' | grep .; then
    echo "    не нашёл в журнале, посмотрите сами: journalctl -u ${SERVICE_NAME} -n 50"
fi

SSH_USER="${SUDO_USER:-$(id -un)}"
SSH_HOST="$(hostname -f 2>/dev/null || hostname)"

cat <<EOF

Полезное:
    systemctl status ${SERVICE_NAME}
    journalctl -u ${SERVICE_NAME} -f
    systemctl restart ${SERVICE_NAME}

Конфиг:  ${CONF_FILE}
Данные:  ${DATA_DIR}  (рейтинги, ключ CA)
EOF

if [[ $ADMIN_LOCAL -eq 1 ]]; then
    cat <<EOF
Панель доступна только с самого сервера. Пробросьте её со своей машины:
    ssh -L ${ADMIN_PORT}:127.0.0.1:${ADMIN_PORT} ${SSH_USER}@${SSH_HOST}
и откройте ссылку выше в браузере. Чтобы не искать токен, задайте пароль
на вкладке «Доступ».
EOF
else
    warn "Панель слушает ${ADMIN_ADDR}, не loopback: она доступна по сети."
    warn "Задайте пароль на вкладке «Доступ» и закройте порт ${ADMIN_PORT} firewall'ом."
fi

cat <<EOF

Обновление: sudo $0 --download
Удаление:   sudo $0 --uninstall
EOF
