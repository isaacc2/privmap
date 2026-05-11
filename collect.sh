#!/bin/sh
# privmap snapshot collector. POSIX-compliant, no dependencies.
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

# POSIX shells (dash, ash, etc.) do not expand brace lists. Use an explicit
# loop so this script behaves identically under /bin/sh, bash, zsh, and any
# other POSIX shell.
for d in etc proc suid caps cron systemd initd acl meta boot path pam network ssh container; do
    mkdir -p "${OUTDIR}/${d}"
done

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

# ── Group-writable files (excluding root group ownership) ──
echo "[+] Scanning for group-writable files..."
# Format: mode owner group path
find /etc /usr /opt /var -perm -0020 -type f ! -group root 2>/dev/null \
    -printf '%m %u %g %p\n' > "${OUTDIR}/suid/group_writable_files.txt" 2>/dev/null \
    || find /etc /usr /opt /var -perm -0020 -type f ! -group root 2>/dev/null \
        -exec stat -c '%a %U %G %n' {} \; > "${OUTDIR}/suid/group_writable_files.txt" 2>/dev/null || true
find /etc /usr /opt /var -perm -0020 -type d ! -group root 2>/dev/null \
    -printf '%m %u %g %p\n' > "${OUTDIR}/suid/group_writable_dirs.txt" 2>/dev/null \
    || find /etc /usr /opt /var -perm -0020 -type d ! -group root 2>/dev/null \
        -exec stat -c '%a %U %G %n' {} \; > "${OUTDIR}/suid/group_writable_dirs.txt" 2>/dev/null || true

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

# ── v2.0 extra surfaces ──
# These mirror the target's natural /etc layout so the ingester's
# self._abs(path) resolves correctly in both live and snapshot mode.

echo "[+] Collecting login-time scripts..."
for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/csh.cshrc /etc/csh.login; do
    [ -r "$f" ] && cp "$f" "${OUTDIR}/etc/" 2>/dev/null || true
done
if [ -d /etc/zsh ]; then
    mkdir -p "${OUTDIR}/etc/zsh"
    cp -r /etc/zsh/* "${OUTDIR}/etc/zsh/" 2>/dev/null || true
fi
for d in /etc/profile.d /etc/bashrc.d /etc/skel; do
    if [ -d "$d" ]; then
        mkdir -p "${OUTDIR}${d}"
        cp -r "$d"/* "${OUTDIR}${d}/" 2>/dev/null || true
    fi
done

echo "[+] Collecting library-loading control files..."
for f in /etc/ld.so.preload /etc/ld.so.conf; do
    [ -r "$f" ] && cp "$f" "${OUTDIR}/etc/" 2>/dev/null || true
done
if [ -d /etc/ld.so.conf.d ]; then
    mkdir -p "${OUTDIR}/etc/ld.so.conf.d"
    cp -r /etc/ld.so.conf.d/* "${OUTDIR}/etc/ld.so.conf.d/" 2>/dev/null || true
fi

echo "[+] Collecting polkit rules..."
for d in /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d /etc/polkit-1/localauthority; do
    if [ -d "$d" ]; then
        mkdir -p "${OUTDIR}${d}"
        cp -r "$d"/* "${OUTDIR}${d}/" 2>/dev/null || true
    fi
done

echo "[+] Collecting doas configuration..."
[ -r /etc/doas.conf ] && cp /etc/doas.conf "${OUTDIR}/etc/" 2>/dev/null || true

echo "[+] Capturing sudo version..."
if command -v sudo >/dev/null 2>&1; then
    sudo --version 2>/dev/null | head -1 > "${OUTDIR}/meta/sudo_version.txt" || true
fi

echo "[+] Collecting PAM files..."
if [ -d /etc/pam.d ]; then
    mkdir -p "${OUTDIR}/etc/pam.d"
    cp -r /etc/pam.d/* "${OUTDIR}/etc/pam.d/" 2>/dev/null || true
fi

echo "[+] Collecting security configs..."
if [ -d /etc/security ]; then
    mkdir -p "${OUTDIR}/etc/security"
    cp -r /etc/security/* "${OUTDIR}/etc/security/" 2>/dev/null || true
fi

echo "[+] Collecting SSH configs..."
if [ -d /etc/ssh ]; then
    mkdir -p "${OUTDIR}/etc/ssh"
    [ -r /etc/ssh/sshd_config ] && cp /etc/ssh/sshd_config "${OUTDIR}/etc/ssh/sshd_config" 2>/dev/null || true
    # Capture host-key metadata without the keys themselves.
    find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*' 2>/dev/null \
        -printf '%m %u %g %p\n' >> "${OUTDIR}/etc/ssh/host_keys_meta.txt" 2>/dev/null \
        || find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*' 2>/dev/null \
            -exec stat -c '%a %U %G %n' {} \; >> "${OUTDIR}/etc/ssh/host_keys_meta.txt" 2>/dev/null || true
fi

echo "[+] Collecting network configs..."
for f in /etc/exports /etc/fstab /etc/hosts.equiv /etc/shosts.equiv /etc/hosts; do
    [ -r "$f" ] && cp "$f" "${OUTDIR}/etc/" 2>/dev/null || true
done
mkdir -p "${OUTDIR}/proc/net"
for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    [ -r "$f" ] && cp "$f" "${OUTDIR}/proc/net/" 2>/dev/null || true
done

echo "[+] Capturing container markers..."
[ -e /.dockerenv ] && touch "${OUTDIR}/.dockerenv"
[ -e /run/.containerenv ] && mkdir -p "${OUTDIR}/run" && touch "${OUTDIR}/run/.containerenv"
mkdir -p "${OUTDIR}/proc/1"
[ -r /proc/1/cgroup ] && cp /proc/1/cgroup "${OUTDIR}/proc/1/cgroup" 2>/dev/null || true
[ -r /proc/self/status ] && cp /proc/self/status "${OUTDIR}/proc/1/status" 2>/dev/null || true

echo "[+] Capturing process environments..."
for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    if [ -r "${pid_dir}/environ" ]; then
        mkdir -p "${OUTDIR}/proc/${pid}" 2>/dev/null
        cp "${pid_dir}/environ" "${OUTDIR}/proc/${pid}/environ.txt" 2>/dev/null || true
    fi
done

# ── Package into archive ──
echo "[+] Creating archive..."
tar czf "${ARCHIVE}" "${OUTDIR}"
rm -rf "${OUTDIR}"

echo "[*] Snapshot complete: ${ARCHIVE}"
echo "[*] Transfer this file to your analysis workstation and run:"
echo "    privmap --snapshot ${ARCHIVE}"
