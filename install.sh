#!/usr/bin/env bash
set -euo pipefail

info() { printf '\033[0;32m[+] \033[0m%s\n' "$*"; }
warn() { printf '\033[1;33m[!] \033[0m%s\n' "$*" >&2; }
fail() { printf '\033[0;31m[x] \033[0m%s\n' "$*" >&2; exit 1; }

SKIP_GO=0
case "${1:-}" in
    "") ;;
    --no-go) SKIP_GO=1 ;;
    -h|--help)
        echo "Usage: $0 [--no-go]"
        echo "  --no-go  Skip installing Go-based tools"
        exit 0
        ;;
    *) fail "Неизвестный аргумент: $1 (используйте --help)" ;;
esac

if command -v apt-get >/dev/null 2>&1; then
    PM=apt
elif command -v dnf >/dev/null 2>&1; then
    PM=dnf
elif command -v pacman >/dev/null 2>&1; then
    PM=pacman
else
    fail "Не найден поддерживаемый пакетный менеджер (apt, dnf, pacman)"
fi

if [[ $EUID -eq 0 ]]; then
    SUDO=()
elif command -v sudo >/dev/null 2>&1; then
    SUDO=(sudo)
else
    fail "Для установки системных пакетов требуется sudo или запуск от root"
fi

info "Установка системных пакетов через $PM..."
case "$PM" in
    apt)
        "${SUDO[@]}" apt-get update
        "${SUDO[@]}" apt-get install -y \
            python3 python3-pip python3-venv golang-go \
            nmap gobuster dirb tshark git curl wget libpcap-dev libcap2-bin
        ;;
    dnf)
        "${SUDO[@]}" dnf install -y \
            python3 python3-pip golang \
            nmap gobuster dirb wireshark-cli git curl wget libpcap-devel libcap
        ;;
    pacman)
        "${SUDO[@]}" pacman -Syu --needed --noconfirm \
            python python-pip go \
            nmap gobuster dirb wireshark-cli git curl wget libpcap libcap
        ;;
esac

if command -v tshark >/dev/null 2>&1; then
    if command -v setcap >/dev/null 2>&1; then
        "${SUDO[@]}" groupadd -f wireshark
        "${SUDO[@]}" usermod -aG wireshark "${SUDO_USER:-$USER}"
        "${SUDO[@]}" setcap cap_net_raw,cap_net_admin+eip "$(command -v tshark)" ||
            warn "Не удалось настроить capability tshark; для захвата пакетов может потребоваться root"
    else
        warn "Команда setcap не найдена; права tshark не настроены"
    fi
fi

if [[ $SKIP_GO -eq 0 ]]; then
    command -v go >/dev/null 2>&1 || fail "Go не установлен"
    export GOPATH="${GOPATH:-$HOME/go}"
    export PATH="$PATH:$GOPATH/bin"

    for spec in \
        "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
        "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
        "amass|github.com/owasp-amass/amass/v4/...@master"
    do
        name=${spec%%|*}
        pkg=${spec#*|}
        info "Установка $name..."
        go install "$pkg" || warn "Не удалось установить $name"
    done
    if command -v nuclei >/dev/null 2>&1; then
        nuclei -update-templates -silent || warn "Не удалось обновить шаблоны nuclei"
    fi
    info "Добавьте $GOPATH/bin в PATH, если Go-инструменты не находятся"
else
    warn "Установка Go-инструментов пропущена (--no-go)"
fi

info "Установка Python-зависимостей..."
[[ -d .venv ]] || python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

echo
info "Готово!"
echo "Запуск CLI: .venv/bin/python main.py --help"
echo "Меню:       .venv/bin/python menu.py"
if command -v tshark >/dev/null 2>&1; then
    warn "Чтобы применить членство в группе wireshark, выйдите из сеанса и войдите снова"
fi
