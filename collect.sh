#!/bin/sh
# privmap snapshot collector — POSIX-compliant, no dependencies
# Run as root on the target system to collect privilege-relevant data.
set -eu
trap 'rm -rf "${OUTDIR:-}" 2>/dev/null || true' EXIT INT TERM

HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
DATE=$(date +%Y%m%d_%H%M%S)
OUTDIR="privmap_snapshot_${HOSTNAME}_${DATE}"
ARCHIVE="${OUTDIR}.tar.gz"

echo "[*] privmap snapshot collector"
echo "[*] Output: ${ARCHIVE}"

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] WARNING: Not running as root. Results will be incomplete."
fi

mkdir -p "${OUTDIR}"/{etc,proc,suid,caps,cron,systemd,initd,acl}

# ── Identity and access ──
echo "[+] Collecting identity files..."
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/login.defs; do
    [ -r "$f" ] && cp "$f" "${OUTDIR}/etc/" 2>/dev/null || true
done

if [ -r /etc/sudoers ]; then
    cp /etc/sudoers "${OUTDIR}/etc/"
fi
if [ -d /etc/sudoers.d ]; then
    mkdir -p "${OUTDIR}/etc/sudoers.d"
    cp -r /etc/sudoers.d/* "${OUTDIR}/etc/sudoers.d/" 2>/dev/null || true
fi

# ── Cron jobs ──
echo "[+] Collecting cron jobs..."
for f in /etc/crontab; do
    [ -r "$f" ] && cp "$f" "${OUTDIR}/cron/" 2>/dev/null || true
done
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$d" ]; then
        mkdir -p "${OUTDIR}/cron/$(basename "$d")"
        cp -r "$d"/* "${OUTDIR}/cron/$(basename "$d")/" 2>/dev/null || true
    fi
done
if [ -d /var/spool/cron/crontabs ]; then
    mkdir -p "${OUTDIR}/cron/user_crontabs"
    cp -r /var/spool/cron/crontabs/* "${OUTDIR}/cron/user_crontabs/" 2>/dev/null || true
fi

# ── Systemd units ──
echo "[+] Collecting systemd units..."
for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system; do
    if [ -d "$d" ]; then
        dirname=$(echo "$d" | tr '/' '_')
        mkdir -p "${OUTDIR}/systemd/${dirname}"
        find "$d" -maxdepth 2 -name '*.service' -o -name '*.timer' -o -name '*.path' 2>/dev/null | while read -r f; do
            cp "$f" "${OUTDIR}/systemd/${dirname}/" 2>/dev/null || true
        done
    fi
done

# ── Init.d scripts ──
echo "[+] Collecting init.d scripts..."
if [ -d /etc/init.d ]; then
    cp -r /etc/init.d/* "${OUTDIR}/initd/" 2>/dev/null || true
fi

# ── SUID/SGID binaries ──
echo "[+] Scanning for SUID/SGID binaries..."
find / -perm -4000 -type f 2>/dev/null > "${OUTDIR}/suid/suid_binaries.txt" || true
find / -perm -2000 -type f 2>/dev/null > "${OUTDIR}/suid/sgid_binaries.txt" || true

# ── World-writable files ──
echo "[+] Scanning for world-writable files..."
find /etc /usr /opt /var /tmp -perm -0002 -type f 2>/dev/null > "${OUTDIR}/suid/world_writable_files.txt" || true
find /etc /usr /opt /var /tmp -perm -0002 -type d 2>/dev/null > "${OUTDIR}/suid/world_writable_dirs.txt" || true

# ── Capabilities ──
echo "[+] Collecting capabilities..."
if command -v getcap >/dev/null 2>&1; then
    getcap -r / 2>/dev/null > "${OUTDIR}/caps/file_capabilities.txt" || true
fi

# ── /proc data ──
echo "[+] Collecting process information..."
for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    if [ -r "${pid_dir}/status" ] && [ -r "${pid_dir}/cmdline" ]; then
        mkdir -p "${OUTDIR}/proc/${pid}"
        cp "${pid_dir}/status" "${OUTDIR}/proc/${pid}/" 2>/dev/null || true
        cat "${pid_dir}/cmdline" | tr '\0' ' ' > "${OUTDIR}/proc/${pid}/cmdline.txt" 2>/dev/null || true
        readlink "${pid_dir}/exe" > "${OUTDIR}/proc/${pid}/exe_link.txt" 2>/dev/null || true
    fi
done

# ── PATH binaries ──
echo "[+] Collecting PATH information..."
echo "$PATH" > "${OUTDIR}/etc/path.txt"

# ── File permissions on sensitive dirs ──
echo "[+] Collecting detailed file permissions..."
for d in /etc /usr/local/bin /usr/local/sbin /opt; do
    if [ -d "$d" ]; then
        find "$d" -maxdepth 3 -printf '%m %u %g %p\n' 2>/dev/null >> "${OUTDIR}/suid/permissions.txt" || \
        find "$d" -maxdepth 3 -exec stat -c '%a %U %G %n' {} \; 2>/dev/null >> "${OUTDIR}/suid/permissions.txt" || true
    fi
done

# ── ACLs ──
echo "[+] Collecting ACLs..."
if command -v getfacl >/dev/null 2>&1; then
    for d in /etc /usr/local /opt /var; do
        [ -d "$d" ] && getfacl -R "$d" 2>/dev/null >> "${OUTDIR}/acl/acls.txt" || true
    done
fi

# ── Symlinks to sensitive files ──
echo "[+] Scanning for symlinks to sensitive targets..."
find /tmp /var/tmp /dev/shm -type l 2>/dev/null | while read -r link; do
    target=$(readlink -f "$link" 2>/dev/null || echo "unresolved")
    echo "$link -> $target"
done > "${OUTDIR}/suid/symlinks.txt" 2>/dev/null || true

# ── Package into archive ──
echo "[+] Creating archive..."
tar czf "${ARCHIVE}" "${OUTDIR}"
rm -rf "${OUTDIR}"

echo "[*] Snapshot complete: ${ARCHIVE}"
echo "[*] Transfer this file to your analysis workstation and run:"
echo "    privmap --snapshot ${ARCHIVE}"
