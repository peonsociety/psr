#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# hermes-hunter.sh — universal, host-agnostic hermes persistence cleaner
#
# Detects:  processes, systemd system units, systemd user units (all users),
#           systemd timers, sysvinit scripts, rc.local, cron, supervisord,
#           pm2, docker containers, listening ports
# Detects by CONTENT (ExecStart body, cmdline, exe path, cwd, environ) not name.
#
# Run:      sudo ./hermes-hunter.sh              interactive
#           sudo ./hermes-hunter.sh -y           auto-confirm
#           sudo ./hermes-hunter.sh --dry-run    detect only
# ═══════════════════════════════════════════════════════════════════════════

set -uo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "must be root"; exit 1; }

AUTO=0; DRY=0
for a in "$@"; do
    case "$a" in
        -y|--yes)    AUTO=1 ;;
        --dry-run)   DRY=1 ;;
        -h|--help)   sed -n '4,12p' "$0"; exit 0 ;;
    esac
done

# ── colors & log ──────────────────────────────────────────────────────────
R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; M=$'\e[35m'
W=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'

LOG="/root/hermes-hunter-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

hdr(){ echo; echo "${W}${B}══ $* ══${N}"; }
ok(){  echo "  ${G}✓${N} $*"; }
wr(){  echo "  ${Y}⚠${N} $*"; }
er(){  echo "  ${R}✗${N} $*"; }
dim(){ echo "  ${D}·${N} $*"; }

# ═══════════════════════════════════════════════════════════════════════════
# UNIVERSAL DETECTORS
# ═══════════════════════════════════════════════════════════════════════════

# A PID is "hermes" if ANY of these hold (name-agnostic):
is_hermes_pid() {
    local p=$1
    [[ -d "/proc/$p" ]] || return 1
    [[ "$p" == "$$" || "$p" == "$PPID" ]] && return 1
    local cmd exe cwd env_str
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null) || return 1
    # skip editing/viewing tools whose args happen to contain "hermes"
    case "${cmd,,}" in
        *grep*|*vim*|*nano*|*emacs*|*less*|*more*|*tail*|*head*|*cat*|*htop*|*top*|*hermes-hunter*) return 1 ;;
    esac
    exe=$(readlink "/proc/$p/exe" 2>/dev/null || true)
    cwd=$(readlink "/proc/$p/cwd" 2>/dev/null || true)
    env_str=$(tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null || true)

    # multi-signal match
    [[ "${cmd,,}"     == *hermes*        ]] && return 0
    [[ "${exe,,}"     == *hermes*        ]] && return 0
    [[ "${exe,,}"     == *".hermes"*     ]] && return 0
    [[ "${cwd,,}"     == *".hermes"*     ]] && return 0
    [[ "${env_str,,}" == *hermes_home*   ]] && return 0
    [[ "${env_str,,}" == *"/.hermes"*    ]] && return 0
    [[ "${env_str,,}" == *"hermes_profile"* ]] && return 0
    return 1
}

# A unit file is "hermes" if it EXECUTES/RUNS/POINTS TO hermes
# (not just mentions it in Description=)
is_hermes_unit_file() {
    local f=$1
    [[ -f "$f" ]] || return 1
    grep -qE '^(ExecStart|ExecReload|ExecStop|ExecStopPost|ExecStartPre|WorkingDirectory)=.*(hermes|/\.hermes)' "$f" 2>/dev/null && return 0
    grep -qE '^Environment(=|File=).*HERMES' "$f" 2>/dev/null && return 0
    return 1
}

# Any file that runs hermes in shell/init/cron style
file_runs_hermes() {
    local f=$1
    [[ -f "$f" ]] || return 1
    grep -qE '(^|[[:space:]|&;])([^#]*[[:space:]])?(\S*/)?hermes([[:space:]]|$)|hermes_cli\.main|/\.hermes/' "$f" 2>/dev/null && return 0
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════
# ENVIRONMENT
# ═══════════════════════════════════════════════════════════════════════════
INIT_SYSTEM="other"
if [[ -d /run/systemd/system ]] && command -v systemctl &>/dev/null; then INIT_SYSTEM="systemd"
elif [[ -d /run/openrc ]]; then INIT_SYSTEM="openrc"
elif [[ -f /sbin/init ]] && file /sbin/init 2>/dev/null | grep -q sysv; then INIT_SYSTEM="sysvinit"
fi

# All real users (uid 1000-65533) + root
mapfile -t USERS < <(awk -F: '$3>=1000 && $3<65534 {print $1":"$3}' /etc/passwd)
USERS+=("root:0")

# usermap for iteration
user_home(){ getent passwd "$1" | cut -d: -f6; }

# ═══════════════════════════════════════════════════════════════════════════
# FINDINGS
# ═══════════════════════════════════════════════════════════════════════════
declare -a PROC_PIDS=()
declare -a SYS_UNITS=()
declare -a USER_UNITS=()      # user|uid|unit|file
declare -a TIMERS=()
declare -a SYSV=()
declare -a CRON_FILES=()
declare -a CRON_LINES=()      # file|line_number (for spool edits)
declare -a SUPERVISOR_CONF=()
declare -a PM2_APPS=()
declare -a DOCKERS=()
declare -a PORTS=()           # port|addr|pid
declare -a FSDIRS=()          # .hermes installs
declare -a SUSPICIOUS_KEYS=() # user|file

# ── filesystem installs ───────────────────────────────────────────────────
hdr "0. Filesystem — hermes install directories"
for base in /home /root /opt /srv /var/lib; do
    [[ -d "$base" ]] || continue
    while IFS= read -r d; do FSDIRS+=("$d"); done \
        < <(find "$base" -maxdepth 4 -type d -name '.hermes' 2>/dev/null)
done
if [[ ${#FSDIRS[@]} -gt 0 ]]; then
    for d in "${FSDIRS[@]}"; do wr "$d"; done
else dim "none"; fi

# ── processes ─────────────────────────────────────────────────────────────
hdr "1. Processes"
for d in /proc/[0-9]*; do
    p=${d#/proc/}
    is_hermes_pid "$p" && PROC_PIDS+=("$p")
done
if [[ ${#PROC_PIDS[@]} -gt 0 ]]; then
    for p in "${PROC_PIDS[@]}"; do
        wr "PID $p: $(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | cut -c1-140)"
    done
else dim "none"; fi

# ── systemd system units ──────────────────────────────────────────────────
hdr "2. Systemd system units"
if [[ "$INIT_SYSTEM" == "systemd" ]]; then
    for f in /etc/systemd/system/*.service /etc/systemd/system/*/*.service \
             /lib/systemd/system/*.service /usr/lib/systemd/system/*.service; do
        [[ -f "$f" ]] || continue
        is_hermes_unit_file "$f" && SYS_UNITS+=("$(basename "$f")|$f")
    done
    if [[ ${#SYS_UNITS[@]} -gt 0 ]]; then
        for e in "${SYS_UNITS[@]}"; do IFS='|' read -r u f <<<"$e"; wr "$u  ($f)"; done
    else dim "none"; fi
else dim "systemd not present ($INIT_SYSTEM)"; fi

# ── systemd user units (ALL users) ────────────────────────────────────────
hdr "3. Systemd user units (all users)"
if [[ "$INIT_SYSTEM" == "systemd" ]]; then
    for e in "${USERS[@]}"; do
        un=${e%:*}; uid=${e#*:}
        uh=$(user_home "$un"); [[ -d "$uh" ]] || continue
        udir="$uh/.config/systemd/user"
        [[ -d "$udir" ]] || continue
        while IFS= read -r f; do
            is_hermes_unit_file "$f" && USER_UNITS+=("$un|$uid|$(basename "$f")|$f")
        done < <(find "$udir" -maxdepth 1 -type f -name '*.service' 2>/dev/null)
    done
    if [[ ${#USER_UNITS[@]} -gt 0 ]]; then
        for e in "${USER_UNITS[@]}"; do IFS='|' read -r un _ u f <<<"$e"; wr "$un/$u  ($f)"; done
    else dim "none"; fi
fi

# ── systemd timers ────────────────────────────────────────────────────────
hdr "4. Systemd timers"
if [[ "$INIT_SYSTEM" == "systemd" ]]; then
    for f in /etc/systemd/system/*.timer /lib/systemd/system/*.timer /usr/lib/systemd/system/*.timer; do
        [[ -f "$f" ]] || continue
        grep -qiE 'hermes' "$f" 2>/dev/null && TIMERS+=("$f")
    done
    # also user timers
    for e in "${USERS[@]}"; do
        un=${e%:*}; uh=$(user_home "$un"); [[ -d "$uh" ]] || continue
        while IFS= read -r f; do
            grep -qiE 'hermes' "$f" 2>/dev/null && TIMERS+=("$f")
        done < <(find "$uh/.config/systemd/user" -maxdepth 1 -name '*.timer' 2>/dev/null)
    done
    if [[ ${#TIMERS[@]} -gt 0 ]]; then
        for t in "${TIMERS[@]}"; do wr "$t"; done
    else dim "none"; fi
fi

# ── sysvinit / openrc ─────────────────────────────────────────────────────
hdr "5. SysV / OpenRC init scripts"
for f in /etc/init.d/*; do
    [[ -f "$f" ]] || continue
    file_runs_hermes "$f" && SYSV+=("$f")
done
if [[ ${#SYSV[@]} -gt 0 ]]; then
    for s in "${SYSV[@]}"; do wr "$s"; done
else dim "none"; fi

# ── rc.local / profile.d / bashrc ────────────────────────────────────────
hdr "6. rc.local / profile / shell rc"
declare -a RC_HITS=()
for f in /etc/rc.local /etc/rc.d/rc.local /etc/profile \
         /etc/profile.d/*.sh /etc/bash.bashrc \
         /etc/bashrc /etc/zshrc; do
    [[ -f "$f" ]] || continue
    grep -vE '^\s*#' "$f" 2>/dev/null | grep -qiE 'hermes' && RC_HITS+=("$f")
done
for e in "${USERS[@]}"; do
    un=${e%:*}; uh=$(user_home "$un"); [[ -d "$uh" ]] || continue
    for f in "$uh/.bashrc" "$uh/.bash_profile" "$uh/.profile" "$uh/.zshrc"; do
        [[ -f "$f" ]] || continue
        grep -vE '^\s*#' "$f" 2>/dev/null | grep -qiE 'hermes' && RC_HITS+=("$f")
    done
done
if [[ ${#RC_HITS[@]} -gt 0 ]]; then
    for f in "${RC_HITS[@]}"; do
        wr "$f"; grep -niE 'hermes' "$f" 2>/dev/null | head -3 | sed 's/^/      /'
    done
else dim "none"; fi

# ── cron (all paths, cross-distro) ────────────────────────────────────────
hdr "7. Cron"
CRON_DIRS=(
    /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
    /var/spool/cron /var/spool/cron/crontabs /var/spool/cron.d
)
[[ -f /etc/crontab ]] && file_runs_hermes /etc/crontab && CRON_FILES+=("/etc/crontab")
for d in "${CRON_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        file_runs_hermes "$f" && CRON_FILES+=("$f")
    done < <(find "$d" -maxdepth 2 -type f 2>/dev/null)
done
# user crontabs via crontab -l
for e in "${USERS[@]}"; do
    un=${e%:*}; id "$un" &>/dev/null || continue
    ct=$(crontab -u "$un" -l 2>/dev/null || true)
    [[ -z "$ct" ]] && continue
    if echo "$ct" | grep -qiE 'hermes'; then
        CRON_FILES+=("crontab:$un")
    fi
done
# dedupe
[[ ${#CRON_FILES[@]} -gt 0 ]] && mapfile -t CRON_FILES < <(printf '%s\n' "${CRON_FILES[@]}" | sort -u)
if [[ ${#CRON_FILES[@]} -gt 0 ]]; then
    for f in "${CRON_FILES[@]}"; do wr "$f"; done
else dim "none"; fi

# ── supervisord ───────────────────────────────────────────────────────────
hdr "8. supervisord"
for d in /etc/supervisor/conf.d /etc/supervisord.d /etc/supervisor.d; do
    [[ -d "$d" ]] || continue
    while IFS= read -r f; do
        grep -qiE 'hermes' "$f" 2>/dev/null && SUPERVISOR_CONF+=("$f")
    done < <(find "$d" -maxdepth 2 -type f 2>/dev/null)
done
if [[ ${#SUPERVISOR_CONF[@]} -gt 0 ]]; then
    for f in "${SUPERVISOR_CONF[@]}"; do wr "$f"; done
else dim "none"; fi

# ── pm2 ───────────────────────────────────────────────────────────────────
hdr "9. pm2"
for e in "${USERS[@]}"; do
    un=${e%:*}; id "$un" &>/dev/null || continue
    uh=$(user_home "$un")
    if command -v pm2 &>/dev/null && [[ -d "$uh/.pm2" ]]; then
        pm2list=$(sudo -u "$un" pm2 jlist 2>/dev/null || true)
        if echo "$pm2list" | grep -qiE 'hermes'; then
            PM2_APPS+=("$un")
        fi
    fi
done
if [[ ${#PM2_APPS[@]} -gt 0 ]]; then
    for u in "${PM2_APPS[@]}"; do wr "pm2 running hermes under user $u"; done
else dim "none"; fi

# ── docker ────────────────────────────────────────────────────────────────
hdr "10. Docker"
if command -v docker &>/dev/null; then
    while IFS=$'\t' read -r name image; do
        [[ -z "$name" ]] && continue
        # match name, image, or environment
        if [[ "${name,,}" == *hermes* || "${image,,}" == *hermes* ]] || \
           docker exec "$name" sh -c 'env 2>/dev/null | grep -qi hermes' 2>/dev/null; then
            DOCKERS+=("$name")
        fi
    done < <(docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null)
    if [[ ${#DOCKERS[@]} -gt 0 ]]; then
        for c in "${DOCKERS[@]}"; do wr "container: $c"; done
    else dim "none"; fi
else dim "docker not installed"; fi

# ── ports whose owner is hermes ───────────────────────────────────────────
hdr "11. Ports owned by hermes"
if command -v ss &>/dev/null; then
    SNAP=$(ss -tlnp 2>/dev/null | tail -n +2)
elif command -v netstat &>/dev/null; then
    SNAP=$(netstat -tlnp 2>/dev/null | tail -n +3)
else SNAP=""; fi
while IFS= read -r line; do
    pid=$(grep -oP 'pid=\K[0-9]+|\K[0-9]+(?=/[^/]+$)' <<<"$line" | head -1)
    [[ -z "$pid" ]] && continue
    is_hermes_pid "$pid" || continue
    addr=$(awk '{print $4}' <<<"$line")
    port=${addr##*:}
    PORTS+=("$port|$addr|$pid")
done <<<"$SNAP"
if [[ ${#PORTS[@]} -gt 0 ]]; then
    for e in "${PORTS[@]}"; do IFS='|' read -r port addr pid <<<"$e"; wr ":$port ($addr) ← PID $pid"; done
else dim "none"; fi

# ── ssh authorized_keys (report-only — never auto-delete) ─────────────────
hdr "12. SSH authorized_keys (report only)"
for e in "${USERS[@]}"; do
    un=${e%:*}; uh=$(user_home "$un"); [[ -d "$uh" ]] || continue
    ak="$uh/.ssh/authorized_keys"
    [[ -f "$ak" ]] || continue
    cnt=$(grep -cE '^[^#]' "$ak" 2>/dev/null || echo 0)
    [[ "$cnt" -eq 0 ]] && continue
    wr "$un: $ak ($cnt key(s))"
    grep -E '^[^#]' "$ak" 2>/dev/null | awk '{print "      "substr($1,1,25)"... "substr($0,index($0,$2),50)}' | head -5
done

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
hdr "SUMMARY"
TOTAL=0
add(){ printf '  %-28s %d\n' "$1" "$2"; TOTAL=$((TOTAL+$2)); }
add "Filesystem installs"    ${#FSDIRS[@]}
add "Processes"              ${#PROC_PIDS[@]}
add "System systemd units"   ${#SYS_UNITS[@]}
add "User systemd units"     ${#USER_UNITS[@]}
add "Systemd timers"         ${#TIMERS[@]}
add "SysV/OpenRC scripts"    ${#SYSV[@]}
add "rc.local / shell rc"    ${#RC_HITS[@]}
add "Cron files"             ${#CRON_FILES[@]}
add "Supervisor configs"     ${#SUPERVISOR_CONF[@]}
add "pm2 users"              ${#PM2_APPS[@]}
add "Docker containers"      ${#DOCKERS[@]}
add "Listening ports"        ${#PORTS[@]}
echo

if [[ $TOTAL -eq 0 ]]; then echo "${G}✓ Nothing found — clean.${N}"; exit 0; fi

if [[ $DRY -eq 1 ]]; then echo "${Y}--dry-run: no changes made. Log: $LOG${N}"; exit 0; fi

if [[ $AUTO -eq 0 ]]; then
    read -r -p "${W}${Y}Disable and remove ALL of the above? (y/N): ${N}" ans </dev/tty || ans=""
    [[ ! "$ans" =~ ^[Yy]$ ]] && { echo "Aborted."; exit 0; }
else
    echo "${Y}-y: proceeding without prompt.${N}"
fi

# ═══════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════
usysctl(){ local un=$1 uid=$2; shift 2
    local rt="/run/user/$uid"; [[ -d "$rt" ]] || return 1
    sudo -u "$un" XDG_RUNTIME_DIR="$rt" DBUS_SESSION_BUS_ADDRESS="unix:path=$rt/bus" \
        systemctl --user "$@"
}

# 1) SUPERVISORS FIRST (prevents respawn)
hdr "CLEANUP 1/6 — disable supervisors"
for e in "${SYS_UNITS[@]}"; do
    IFS='|' read -r u f <<<"$e"
    systemctl stop "$u" 2>/dev/null && ok "stop $u"
    systemctl disable "$u" 2>/dev/null && ok "disable $u"
    systemctl mask "$u" 2>/dev/null && ok "mask $u"
done
for e in "${USER_UNITS[@]}"; do
    IFS='|' read -r un uid u f <<<"$e"
    usysctl "$un" "$uid" stop    "$u" 2>/dev/null && ok "stop $un/$u"
    usysctl "$un" "$uid" disable "$u" 2>/dev/null && ok "disable $un/$u"
    usysctl "$un" "$uid" mask    "$u" 2>/dev/null && ok "mask $un/$u"
done
for t in "${TIMERS[@]}"; do
    systemctl stop    "$(basename "$t")" 2>/dev/null
    systemctl disable "$(basename "$t")" 2>/dev/null
    systemctl mask    "$(basename "$t")" 2>/dev/null && ok "mask $t"
done
for s in "${SYSV[@]}"; do
    if command -v rc-service &>/dev/null; then rc-service "$(basename "$s")" stop 2>/dev/null; rc-update del "$(basename "$s")" 2>/dev/null
    else service "$(basename "$s")" stop 2>/dev/null; update-rc.d "$(basename "$s")" disable 2>/dev/null
    fi
    ok "disabled $s"
done
for u in "${PM2_APPS[@]}"; do
    sudo -u "$u" pm2 delete all 2>/dev/null && ok "pm2 delete all ($u)"
    sudo -u "$u" pm2 save 2>/dev/null
done
if command -v supervisorctl &>/dev/null; then
    for f in "${SUPERVISOR_CONF[@]}"; do
        names=$(grep -oP '^\[program:\K[^]]+' "$f" 2>/dev/null || true)
        for n in $names; do supervisorctl stop "$n" 2>/dev/null && ok "supervisorctl stop $n"; done
    done
    supervisorctl update 2>/dev/null
fi

# 2) DELETE unit/timer files
hdr "CLEANUP 2/6 — delete unit / timer / init files"
for e in "${SYS_UNITS[@]}"; do IFS='|' read -r _ f <<<"$e"; rm -f "$f" && ok "rm $f"; done
for e in "${USER_UNITS[@]}"; do IFS='|' read -r un uid u f <<<"$e"; rm -f "$f" && ok "rm $f"
    rm -f "$(dirname "$f")/default.target.wants/$u" 2>/dev/null; done
for t in "${TIMERS[@]}"; do rm -f "$t" && ok "rm $t"; done
for s in "${SYSV[@]}"; do rm -f "$s" && ok "rm $s"; done
for f in "${SUPERVISOR_CONF[@]}"; do
    grep -viE 'hermes' "$f" > "$f.tmp" 2>/dev/null && mv "$f.tmp" "$f" && ok "scrubbed $f"
done
command -v systemctl &>/dev/null && systemctl daemon-reload && ok "systemctl daemon-reload"
for e in "${USERS[@]}"; do un=${e%:*}; uid=${e#*:}; usysctl "$un" "$uid" daemon-reload 2>/dev/null; done

# 3) SCRUB shell rc / cron (never delete entire file, only remove matched lines)
hdr "CLEANUP 3/6 — scrub rc / cron"
for f in "${RC_HITS[@]}"; do
    cp -a "$f" "$f.hermes-bak.$(date +%s)" 2>/dev/null
    sed -i '/^[^#].*hermes/I d' "$f" 2>/dev/null && ok "scrubbed $f"
done
for f in "${CRON_FILES[@]}"; do
    case "$f" in
        crontab:*)
            un=${f#crontab:}
            current=$(crontab -u "$un" -l 2>/dev/null || true)
            echo "$current" | sed '/hermes/I d' | crontab -u "$un" - 2>/dev/null \
                && ok "scrubbed crontab -u $un"
            ;;
        *)
            cp -a "$f" "$f.hermes-bak.$(date +%s)" 2>/dev/null
            sed -i '/hermes/I d' "$f" 2>/dev/null && ok "scrubbed $f"
            ;;
    esac
done
systemctl reload cron 2>/dev/null || systemctl reload crond 2>/dev/null || true

# 4) STOP containers
hdr "CLEANUP 4/6 — docker containers"
for c in "${DOCKERS[@]}"; do
    docker stop "$c" &>/dev/null && ok "stopped $c"
    docker update --restart=no "$c" &>/dev/null
done

# 5) KILL processes (loop to catch fast respawns)
hdr "CLEANUP 5/6 — kill processes"
for round in 1 2 3 4 5; do
    declare -a ALIVE=()
    for d in /proc/[0-9]*; do p=${d#/proc/}; is_hermes_pid "$p" && ALIVE+=("$p"); done
    [[ ${#ALIVE[@]} -eq 0 ]] && { ok "no hermes processes remaining"; break; }
    echo "  round $round: ${#ALIVE[@]} process(es)"
    for p in "${ALIVE[@]}"; do
        parent=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
        pcmd=$(ps -o comm= -p "$parent" 2>/dev/null || echo "?")
        kill -9 "$p" 2>/dev/null && ok "kill -9 $p (parent $parent: $pcmd)"
    done
    sleep 1
done

# 6) belt & suspenders — kill anything still bound to a hermes-owned port
hdr "CLEANUP 6/6 — port sweep"
for e in "${PORTS[@]}"; do
    IFS='|' read -r port addr pid <<<"$e"
    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null && ok "killed lingering PID $pid on :$port"
    fi
done

# ═══════════════════════════════════════════════════════════════════════════
# VERIFY
# ═══════════════════════════════════════════════════════════════════════════
hdr "VERIFY"
sleep 2
STILL=()
for d in /proc/[0-9]*; do p=${d#/proc/}; is_hermes_pid "$p" && STILL+=("$p"); done
if [[ ${#STILL[@]} -gt 0 ]]; then
    er "STILL RUNNING after cleanup:"
    for p in "${STILL[@]}"; do
        ps -o pid,ppid,user,args -p "$p" 2>/dev/null | tail -n +2 | sed 's/^/    /'
        parent=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
        echo "      parent $parent: $(ps -o comm= -p "$parent" 2>/dev/null)"
    done
    echo
    wr "A supervisor above these is respawning them. Suspects:"
    wr "  /etc/inittab, /etc/rc.local, systemd override, or a shell daemon"
else
    ok "no hermes processes"
fi
if command -v ss &>/dev/null; then
    P=$(ss -tlnp 2>/dev/null | grep -iE 'hermes')
    [[ -z "$P" ]] && ok "no hermes-owned listeners" || { er "listeners still up:"; echo "$P" | sed 's/^/    /'; }
fi

hdr "DONE"
echo "${G}✓ Log: $LOG${N}"
echo
echo "${Y}Next steps:${N}"
echo "  ${D}1.${N} reboot"
echo "  ${D}2.${N} post-reboot: ss -tlnp | grep -i hermes   (should be empty)"
echo "  ${D}3.${N} rotate ALL credentials (LLM keys, telegram bot token, DB, n8n, OAuth)"
echo "  ${D}4.${N} review: journalctl -u <unit>; /var/log/nginx/access.log; /var/log/auth.log"
[[ ${#STILL[@]} -gt 0 ]] && exit 2 || exit 0
