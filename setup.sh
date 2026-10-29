#!/usr/bin/env bash
#
# Chamlon one-shot installer.
#
# Installs everything the server, the command-line client and the PyQt5 GUI
# need, then builds both binaries. Safe to re-run: every step checks what is
# already there before touching anything.
#
# Written for Ubuntu 20.04 through 25.04 and Debian 11/12; verified end to
# end on Ubuntu 24.04.
#
#   ./setup.sh               install dependencies and build
#   ./setup.sh --build-only  skip apt/pip, just rebuild the binaries
#   ./setup.sh --no-gui      server and client only, no PyQt5 stack
#
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BUILD_ONLY=0
WANT_GUI=1
for arg in "$@"; do
    case "$arg" in
        --build-only) BUILD_ONLY=1 ;;
        --no-gui)     WANT_GUI=0 ;;
        -h|--help)    sed -n '3,14p' "$0" | cut -c3-; exit 0 ;;
        *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------- output ----

if [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'
    C_HEAD=$'\033[1m'; C_OFF=$'\033[0m'
else
    C_OK=''; C_WARN=''; C_ERR=''; C_HEAD=''; C_OFF=''
fi

step() { printf '\n%s==> %s%s\n' "$C_HEAD" "$*" "$C_OFF"; }
ok()   { printf '    %sok%s   %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '    %swarn%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
die()  { printf '\n%serror%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

WARNINGS=0
note_warn() { WARNINGS=$((WARNINGS + 1)); warn "$@"; }

trap 'die "setup failed on line $LINENO. Nothing is left half-installed that a re-run will not fix: run ./setup.sh again."' ERR

# ------------------------------------------------------- privilege helper ----

# Everything that needs root goes through $SUDO, so the script behaves the
# same whether it is run as a normal user (sudo asks once), or as root in a
# container where sudo is not installed at all.
SUDO=''
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO='sudo'
    else
        die "this script needs root to install packages. Install sudo, or run it as root: su -c ./setup.sh"
    fi
fi

keep_sudo_alive() {
    [ -n "$SUDO" ] || return 0
    # Ask for the password once, up front, rather than halfway through a build.
    sudo -v || die "sudo authentication failed"
    ( while true; do sudo -n true 2>/dev/null || exit 0; sleep 50; done ) &
    SUDO_KEEPALIVE_PID=$!
    trap 'kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true' EXIT
}

# -------------------------------------------------------------- platform ----

OS_ID=''
OS_PRETTY='unknown'
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}${ID_LIKE:+ $ID_LIKE}"
    OS_PRETTY="${PRETTY_NAME:-$OS_ID}"
fi

step "Checking the system"
printf '    %s\n' "$OS_PRETTY"
[ "$(uname -s)" = "Linux" ] || die "Chamlon needs Linux: it uses TUN devices and iptables. On Windows use WSL2, on macOS a Linux VM."
command -v apt-get >/dev/null 2>&1 || die "this installer only knows apt (Ubuntu/Debian). Elsewhere install the equivalents of build-essential, libsodium-dev, python3-pyqt5, python3-pyqt5.qtmultimedia, python3-opencv, python3-pyqtgraph and python3-requests, then run ./setup.sh --build-only"
case " $OS_ID " in
    *" ubuntu "*|*" debian "*) ok "supported distribution" ;;
    *) note_warn "untested distribution; continuing because apt is present" ;;
esac
ok "kernel $(uname -r)"
[ -e /dev/net/tun ] || note_warn "/dev/net/tun is missing. The build will still work, but nothing can connect until the tun module is loaded: sudo modprobe tun"

# ---------------------------------------------------------- apt plumbing ----

wait_for_apt() {
    # Ubuntu runs unattended-upgrades shortly after boot and on a timer. While
    # it holds the dpkg lock, apt-get simply fails - the single most common
    # reason this installer "worked yesterday and not today".
    local waited=0
    while $SUDO fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
        [ "$waited" -gt 0 ] || warn "another package manager is running (unattended-upgrades?); waiting for it"
        sleep 5
        waited=$((waited + 5))
        [ "$waited" -lt 600 ] || die "the dpkg lock is still held after 10 minutes. Wait for the other package operation to finish, or reboot, then re-run ./setup.sh"
    done
    [ "$waited" -eq 0 ] || ok "lock released after ${waited}s"
}

APT_UPDATED=0
apt_update() {
    [ "$APT_UPDATED" -eq 0 ] || return 0
    wait_for_apt
    # A stale or unreachable third-party repository must not stop the install;
    # what matters is whether the packages below can be found afterwards.
    if $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1; then
        ok "package lists updated"
    else
        note_warn "apt-get update reported errors (a broken third-party repository?); carrying on with the lists already on disk"
    fi
    APT_UPDATED=1
}

# Is there an installable candidate for this package name on this release?
#
# Plain `grep ... >/dev/null`, not `grep -q`: with `set -o pipefail`, grep -q
# exits on the first match, the writer upstream dies of SIGPIPE, and the
# pipeline reports 141 - so a match would read as a failure and every package
# would look unavailable.
apt_available() {
    apt-cache policy -- "$1" 2>/dev/null | grep 'Candidate: [^(]' >/dev/null
}

apt_installed() {
    dpkg-query -W -f='${db:Status-Status}\n' -- "$1" 2>/dev/null | grep -x installed >/dev/null
}

# Install packages, tolerating names that do not exist on a given release.
# Each argument may list alternatives separated by '|' and the first one that
# exists wins. That is what lets one script cover 20.04 through 25.04, where
# several libraries were renamed (libglib2.0-0 became libglib2.0-0t64 in the
# 64-bit time_t transition, libgl1-mesa-glx became libgl1, and so on).
#
#   apt_install required 'libglib2.0-0t64|libglib2.0-0' build-essential
#   apt_install optional python3-pyqtgraph
apt_install() {
    local mode="$1"; shift
    local spec name chosen
    local missing=() to_install=()

    apt_update
    for spec in "$@"; do
        chosen=''
        local IFS='|'
        # shellcheck disable=SC2206
        for name in $spec; do
            if apt_installed "$name"; then chosen="$name"; break; fi
            if apt_available "$name"; then chosen="$name"; to_install+=("$name"); break; fi
        done
        unset IFS
        [ -n "$chosen" ] || missing+=("$spec")
    done

    if [ "${#to_install[@]}" -gt 0 ]; then
        wait_for_apt
        if ! $SUDO env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
                apt-get install -y "${to_install[@]}"; then
            [ "$mode" = optional ] || die "could not install: ${to_install[*]}"
            note_warn "could not install optional packages: ${to_install[*]}"
            return 0
        fi
        ok "installed ${to_install[*]}"
    fi

    if [ "${#missing[@]}" -gt 0 ]; then
        [ "$mode" = optional ] || die "these packages are not available on $OS_PRETTY: ${missing[*]}"
        note_warn "not available on this release, skipped: ${missing[*]}"
    fi
}

# ------------------------------------------------------- the apt packages ----

if [ "$BUILD_ONLY" -eq 0 ]; then
    keep_sudo_alive

    step "Installing the build toolchain"
    # build-essential is what used to be missing: the old script installed
    # make but never a compiler, so the build only worked on machines that
    # happened to have gcc already.
    apt_install required build-essential make libsodium-dev
    # pkg-config is a virtual package on 24.04, where pkgconf provides it, so
    # it is asked for by both names and is not required either way: the
    # Makefiles do not call it.
    apt_install optional 'pkgconf|pkg-config' iproute2 iptables

    step "Installing Python"
    apt_install required python3
    apt_install optional python3-pip

    if [ "$WANT_GUI" -eq 1 ]; then
        step "Installing the GUI stack"
        # Distribution packages, not pip. Mixing a pip PyQt5 wheel with the
        # apt one is the other classic failure here: two copies of Qt in one
        # process, and the app dies with "could not load the Qt platform
        # plugin xcb". Everything the GUI imports exists in the archive.
        apt_install required \
            python3-pyqt5 \
            python3-pyqt5.qtmultimedia \
            python3-opencv \
            python3-numpy \
            python3-requests
        apt_install optional \
            python3-pyqtgraph \
            libqt5multimedia5-plugins \
            qtwayland5

        step "Installing the libraries Qt and OpenCV load at runtime"
        # Qt dlopen()s these, so a missing one surfaces as a blank window or a
        # platform-plugin error rather than as a packaging error. The
        # alternatives cover the renames across releases.
        apt_install optional \
            'libgl1|libgl1-mesa-glx' \
            'libglib2.0-0t64|libglib2.0-0' \
            libxcb-xinerama0 \
            libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
            libxcb-render-util0 libxcb-shape0 libxcb-xfixes0 libxcb-xkb1 \
            libxkbcommon-x11-0 \
            libsm6 libxrender1 libfontconfig1 \
            gstreamer1.0-plugins-good gstreamer1.0-libav
    fi
fi

# ---------------------------------------------------------------- python ----

py_has() { python3 -c "import $1" >/dev/null 2>&1; }

pip_install() {
    local pkgs=("$@")
    local flags=()
    python3 -m pip --version >/dev/null 2>&1 \
        || { note_warn "pip is not available, cannot install: ${pkgs[*]}"; return 0; }
    # --break-system-packages exists from pip 23 (Ubuntu 23.04 onwards).
    # Passing it to the pip on 20.04 or 22.04 is an immediate "no such option"
    # error, which is why the old script failed outright on those releases.
    if python3 -m pip install --help 2>/dev/null | grep -- '--break-system-packages' >/dev/null; then
        flags+=(--break-system-packages)
    fi
    if ! $SUDO python3 -m pip install "${flags[@]}" "${pkgs[@]}" >/dev/null 2>&1; then
        note_warn "pip could not install: ${pkgs[*]}"
        return 0
    fi
    ok "installed with pip: ${pkgs[*]}"
}

if [ "$BUILD_ONLY" -eq 0 ] && [ "$WANT_GUI" -eq 1 ]; then
    step "Checking the Python modules the GUI imports"
    declare -A PIP_NAME=(
        [PyQt5]=PyQt5
        [cv2]=opencv-python
        [numpy]=numpy
        [pyqtgraph]=pyqtgraph
        [requests]=requests
    )
    for mod in PyQt5 PyQt5.QtMultimediaWidgets cv2 numpy pyqtgraph requests; do
        if py_has "$mod"; then
            ok "$mod"
            continue
        fi
        warn "$mod is missing after the apt step; falling back to pip"
        pip_install "${PIP_NAME[${mod%%.*}]}"
        if py_has "$mod"; then
            ok "$mod"
        else
            note_warn "$mod is still missing: the GUI will not start, though the command-line client will"
        fi
    done
fi

# ----------------------------------------------------------------- build ----

command -v gcc >/dev/null 2>&1 || die "gcc is not installed. Re-run ./setup.sh without --build-only, or install build-essential."
[ -e /usr/include/sodium.h ] || note_warn "sodium.h was not found; if the build fails, install libsodium-dev"

# -march=native and -flto are in the Makefiles, and neither is universal: some
# compiler and architecture combinations reject -march=native, and -flto needs
# a working linker plugin. Probe both and drop whichever does not work, so the
# build succeeds everywhere instead of on x86 desktops only.
probe_cflag() {
    local src out rc=1
    src="$(mktemp --suffix=.c)"
    out="$(mktemp)"
    printf 'int main(void){return 0;}\n' > "$src"
    gcc "$@" -o "$out" "$src" >/dev/null 2>&1 && rc=0
    rm -f "$src" "$out"
    return "$rc"
}

step "Checking the compiler"
MAKE_ARGS=()
if probe_cflag -march=native; then
    ok "gcc accepts -march=native"
else
    note_warn "this compiler or architecture rejects -march=native; building portable code instead"
    MAKE_ARGS+=(ARCHFLAGS=)
fi
if probe_cflag -flto; then
    ok "gcc accepts -flto"
else
    note_warn "link-time optimisation is unavailable here; building without it"
    MAKE_ARGS+=(LTOFLAGS=)
fi

build() {
    local dir="$1" binary="$2"
    step "Building $dir"
    make -C "$SCRIPT_DIR/$dir" clean >/dev/null
    if ! make -C "$SCRIPT_DIR/$dir" "${MAKE_ARGS[@]}"; then
        die "$dir failed to build. The output above says why; the usual cause is a missing libsodium-dev."
    fi
    [ -x "$SCRIPT_DIR/$dir/$binary" ] || die "$dir/$binary was not produced"
    ok "$dir/$binary"
}

build chamlon_client vpn_client
build chamlon_server vpn_server

# ------------------------------------------------------------ conclusion ----

step "Done"
if [ "$WARNINGS" -gt 0 ]; then
    printf '    built successfully, with %d warning(s) above.\n' "$WARNINGS"
else
    printf '    everything installed and built.\n'
fi
cat <<'MSG'

    Start the server (root, for the TUN device and the NAT rules):
        cd chamlon_server && sudo ./vpn_server 0.0.0.0 55555

    Start the graphical client:
        ./chamlon

    The server prints its Ed25519 public key on startup: paste that into the
    client's options page, along with the server's address and port.
MSG
