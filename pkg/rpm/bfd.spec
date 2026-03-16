%define name    bfd
%define version 2.0.1
%define release 1%{?dist}

# Legacy install path used by install.sh — symlink farm target
%define legacy_path /usr/local/bfd

Name:           %{name}
Version:        %{version}
Release:        %{release}
Summary:        Brute Force Detection - modular shell-based brute force attack monitor
License:        GPLv2+
URL:            https://github.com/rfxn/bfd
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

Requires:       bash >= 4.1
Requires:       coreutils
Requires:       grep
Requires:       gawk
Requires:       findutils
Requires:       util-linux
Requires:       iproute
Requires:       sed
Requires:       procps-ng
%if 0%{?rhel} >= 8 || 0%{?fedora}
Recommends:     cronie
Recommends:     logrotate
Suggests:       mailx
%endif

%description
BFD (Brute Force Detection) is a modular shell-based daemon that parses
authentication logs and detects brute-force login attempts. It uses an
exponential-decay pressure scoring model to distinguish real attacks from
typos, and bans offending IPs via configurable firewall backends (APF,
CSF, firewalld, UFW, nftables, iptables, or route blackhole). BFD runs
in watch mode (~10s detection) or via cron (~2m detection) and includes
per-rule pressure weights, country-based multipliers, ban escalation,
and email alerting.

%prep
%setup -q -n %{name}-%{version}

%build
# Apply FHS path transforms to copies — never modify source files
cp files/internals/internals.conf files/internals.conf.pkg
sed -i \
    -e 's|\$INSTALL_PATH/rules|/usr/share/bfd/rules|' \
    -e 's|\$INSTALL_PATH/tlog|/usr/lib/bfd/tlog|' \
    -e 's|\$INSTALL_PATH/tmp|/var/lib/bfd/tmp|' \
    -e 's|\$INSTALL_PATH/alert"|/usr/lib/bfd/alert"|' \
    -e 's|\$INSTALL_PATH/exclude\.files|/etc/bfd/exclude.files|' \
    -e 's|\$INSTALL_PATH/lock\.utime|/var/lib/bfd/lock.utime|' \
    -e 's|\$INSTALL_PATH/pressure\.conf|/etc/bfd/pressure.conf|' \
    -e 's|\$INSTALL_PATH/thresholds\.conf|/etc/bfd/thresholds.conf|' \
    files/internals.conf.pkg

cp files/exclude.files files/exclude.files.pkg
sed -i 's|/usr/local/bfd/ignore\.hosts|/etc/bfd/ignore.hosts|g' files/exclude.files.pkg

cp cron cron.pkg
sed -i 's|/usr/local/sbin/bfd|/usr/sbin/bfd|g' cron.pkg

cp cron.daily cron.daily.pkg
sed -i 's|INSTALL_PATH="\${INSTALL_PATH:-/usr/local/bfd}"|INSTALL_PATH="${INSTALL_PATH:-/var/lib/bfd}"|' cron.daily.pkg

cp bfd.service bfd.service.pkg
sed -i 's|/usr/local/sbin/bfd|/usr/sbin/bfd|g' bfd.service.pkg

cp bfd-watch.service bfd-watch.service.pkg
sed -i 's|/usr/local/sbin/bfd|/usr/sbin/bfd|g' bfd-watch.service.pkg

cp bfd-watch.init bfd-watch.init.pkg
sed -i 's|/usr/local/sbin/bfd|/usr/sbin/bfd|g' bfd-watch.init.pkg

%install
rm -rf %{buildroot}

# Executable
install -D -m 755 files/bfd %{buildroot}/usr/sbin/bfd

# Library files
install -D -m 644 files/internals/bfd.lib.sh %{buildroot}/usr/lib/bfd/internals/bfd.lib.sh
install -D -m 644 files/internals/tlog_lib.sh %{buildroot}/usr/lib/bfd/internals/tlog_lib.sh
install -D -m 644 files/internals/elog_lib.sh %{buildroot}/usr/lib/bfd/internals/elog_lib.sh
install -D -m 755 files/tlog %{buildroot}/usr/lib/bfd/tlog
install -D -m 644 files/internals/alert_lib.sh %{buildroot}/usr/lib/bfd/internals/alert_lib.sh
install -D -m 644 files/internals/bfd_alert.sh %{buildroot}/usr/lib/bfd/internals/bfd_alert.sh
install -D -m 644 files/internals/geoip_lib.sh %{buildroot}/usr/lib/bfd/internals/geoip_lib.sh
install -D -m 644 files/internals/pkg_lib.sh %{buildroot}/usr/lib/bfd/internals/pkg_lib.sh
install -d -m 755 %{buildroot}/usr/lib/bfd/alert
for tpl in files/alert/*.tpl; do
    install -m 644 "$tpl" %{buildroot}/usr/lib/bfd/alert/
done
install -d -m 755 %{buildroot}/usr/lib/bfd/alert/custom.d
install -D -m 755 files/update-ipcountry.sh %{buildroot}/usr/lib/bfd/update-ipcountry.sh
install -D -m 755 importconf %{buildroot}/usr/lib/bfd/importconf

# Config files (noreplace)
install -D -m 640 files/conf.bfd %{buildroot}/etc/bfd/conf.bfd
install -D -m 640 files/internals.conf.pkg %{buildroot}/etc/bfd/internals.conf
install -D -m 640 files/pressure.conf %{buildroot}/etc/bfd/pressure.conf
install -D -m 640 files/pressure-country.conf %{buildroot}/etc/bfd/pressure-country.conf
install -D -m 640 files/exclude.files.pkg %{buildroot}/etc/bfd/exclude.files
install -D -m 640 files/ignore.hosts %{buildroot}/etc/bfd/ignore.hosts

# Data files
install -D -m 644 files/ipcountry.dat %{buildroot}/usr/share/bfd/ipcountry.dat
install -d -m 755 %{buildroot}/usr/share/bfd/rules
for rule in files/rules/*; do
    install -m 644 "$rule" %{buildroot}/usr/share/bfd/rules/
done

# State directories
install -d -m 750 %{buildroot}/var/lib/bfd/tmp
install -d -m 750 %{buildroot}/var/lib/bfd/stats

# Systemd units
install -D -m 644 bfd.service.pkg %{buildroot}/usr/lib/systemd/system/bfd.service
install -D -m 644 bfd.timer %{buildroot}/usr/lib/systemd/system/bfd.timer
install -D -m 644 bfd-watch.service.pkg %{buildroot}/usr/lib/systemd/system/bfd-watch.service

# SysVinit script (CentOS 7)
%if 0%{?el7}
install -D -m 755 bfd-watch.init.pkg %{buildroot}/etc/init.d/bfd-watch
%endif

# Cron
install -D -m 644 cron.pkg %{buildroot}/etc/cron.d/bfd
install -D -m 755 cron.daily.pkg %{buildroot}/etc/cron.daily/bfd

# Logrotate
install -D -m 644 logrotate.d.bfd %{buildroot}/etc/logrotate.d/bfd

# Man page
install -D -m 644 bfd.1 %{buildroot}/usr/share/man/man1/bfd.1

# Bash completion
install -D -m 644 bfd.bash-completion %{buildroot}/usr/share/bash-completion/completions/bfd

# Docs
install -D -m 644 README %{buildroot}/usr/share/doc/bfd/README
install -D -m 644 CHANGELOG %{buildroot}/usr/share/doc/bfd/CHANGELOG
# COPYING.GPL handled by %license directive — not installed to doc/

# Symlink farm at /usr/local/bfd for backward compatibility
install -d -m 755 %{buildroot}%{legacy_path}
install -d -m 755 %{buildroot}%{legacy_path}/internals
ln -s /usr/lib/bfd/internals/bfd.lib.sh %{buildroot}%{legacy_path}/internals/bfd.lib.sh
ln -s /usr/lib/bfd/internals/tlog_lib.sh %{buildroot}%{legacy_path}/internals/tlog_lib.sh
ln -s /usr/lib/bfd/internals/elog_lib.sh %{buildroot}%{legacy_path}/internals/elog_lib.sh
ln -s /usr/lib/bfd/internals/alert_lib.sh %{buildroot}%{legacy_path}/internals/alert_lib.sh
ln -s /usr/lib/bfd/internals/bfd_alert.sh %{buildroot}%{legacy_path}/internals/bfd_alert.sh
ln -s /usr/lib/bfd/internals/geoip_lib.sh %{buildroot}%{legacy_path}/internals/geoip_lib.sh
ln -s /usr/lib/bfd/internals/pkg_lib.sh %{buildroot}%{legacy_path}/internals/pkg_lib.sh
ln -s /etc/bfd/internals.conf %{buildroot}%{legacy_path}/internals/internals.conf
ln -s /usr/lib/bfd/tlog %{buildroot}%{legacy_path}/tlog
ln -s /usr/lib/bfd/alert %{buildroot}%{legacy_path}/alert
ln -s /usr/lib/bfd/update-ipcountry.sh %{buildroot}%{legacy_path}/update-ipcountry.sh
ln -s /usr/lib/bfd/importconf %{buildroot}%{legacy_path}/importconf
ln -s /etc/bfd/conf.bfd %{buildroot}%{legacy_path}/conf.bfd
ln -s /etc/bfd/pressure.conf %{buildroot}%{legacy_path}/pressure.conf
ln -s /etc/bfd/pressure-country.conf %{buildroot}%{legacy_path}/pressure-country.conf
ln -s /etc/bfd/exclude.files %{buildroot}%{legacy_path}/exclude.files
ln -s /etc/bfd/ignore.hosts %{buildroot}%{legacy_path}/ignore.hosts
ln -s /usr/share/bfd/ipcountry.dat %{buildroot}%{legacy_path}/ipcountry.dat
ln -s /usr/share/bfd/rules %{buildroot}%{legacy_path}/rules
ln -s /var/lib/bfd/tmp %{buildroot}%{legacy_path}/tmp
ln -s /var/lib/bfd/stats %{buildroot}%{legacy_path}/stats

# /usr/local/sbin/bfd -> /usr/sbin/bfd
install -d -m 755 %{buildroot}/usr/local/sbin
ln -s /usr/sbin/bfd %{buildroot}/usr/local/sbin/bfd

%pre
# Detect and back up existing install.sh-based installation
if [ -f "%{legacy_path}/bfd" ] && [ ! -L "%{legacy_path}/internals/bfd.lib.sh" ] && [ ! -L "%{legacy_path}/bfd.lib.sh" ]; then
    # This is a real (non-package) install — back up
    _bkdir="%{legacy_path}.bk.$(date +%%Y%%m%%d-%%s)"
    echo "Backing up existing install.sh installation to $_bkdir"
    cp -a "%{legacy_path}" "$_bkdir"
    rm -f "%{legacy_path}.bk.last"
    ln -s "$_bkdir" "%{legacy_path}.bk.last"
    # Preserve state files
    if [ -d "%{legacy_path}/tmp" ]; then
        mkdir -p /var/lib/bfd/tmp
        cp -a "%{legacy_path}"/tmp/* /var/lib/bfd/tmp/ 2>/dev/null || true
    fi
    if [ -d "%{legacy_path}/stats" ]; then
        mkdir -p /var/lib/bfd/stats
        cp -a "%{legacy_path}"/stats/* /var/lib/bfd/stats/ 2>/dev/null || true
    fi
    # Stop SysVinit services if present
    for _initdir in /etc/rc.d/init.d /etc/init.d; do
        if [ -f "$_initdir/bfd-watch" ]; then
            "$_initdir/bfd-watch" stop 2>/dev/null || true
            if command -v chkconfig >/dev/null 2>&1; then
                chkconfig --del bfd-watch 2>/dev/null || true
            elif command -v update-rc.d >/dev/null 2>&1; then
                update-rc.d -f bfd-watch remove 2>/dev/null || true
            fi
        fi
    done
    # Stop systemd services before removing old install
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop bfd-watch.service 2>/dev/null || true
        systemctl stop bfd.timer 2>/dev/null || true
    fi
    # Remove old install — package will lay down new files
    rm -rf "%{legacy_path}"
fi

%post
# Run importconf if migrating from install.sh backup
if [ -d "%{legacy_path}.bk.last" ]; then
    if [ -x /usr/lib/bfd/importconf ]; then
        INSTALL_PATH="%{legacy_path}" /usr/lib/bfd/importconf || true
    fi
fi
# Reload systemd if available
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
fi

%preun
# On full removal (not upgrade), stop services
if [ "$1" = "0" ]; then
    # Stop SysVinit services if present
    for _initdir in /etc/rc.d/init.d /etc/init.d; do
        if [ -f "$_initdir/bfd-watch" ]; then
            "$_initdir/bfd-watch" stop 2>/dev/null || true
            if command -v chkconfig >/dev/null 2>&1; then
                chkconfig --del bfd-watch 2>/dev/null || true
            elif command -v update-rc.d >/dev/null 2>&1; then
                update-rc.d -f bfd-watch remove 2>/dev/null || true
            fi
        fi
    done
    # Stop systemd services
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop bfd-watch.service 2>/dev/null || true
        systemctl stop bfd.timer 2>/dev/null || true
        systemctl disable bfd-watch.service 2>/dev/null || true
        systemctl disable bfd.timer 2>/dev/null || true
    fi
fi

%postun
# On full removal (not upgrade), clean up symlink farm
if [ "$1" = "0" ]; then
    rm -rf %{legacy_path} 2>/dev/null || true
    rm -f /usr/local/sbin/bfd 2>/dev/null || true
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
    fi
fi

%files
%license COPYING.GPL
/usr/sbin/bfd
/usr/lib/bfd/internals/bfd.lib.sh
/usr/lib/bfd/internals/tlog_lib.sh
/usr/lib/bfd/internals/elog_lib.sh
/usr/lib/bfd/internals/alert_lib.sh
/usr/lib/bfd/internals/bfd_alert.sh
/usr/lib/bfd/internals/geoip_lib.sh
/usr/lib/bfd/internals/pkg_lib.sh
/usr/lib/bfd/tlog
/usr/lib/bfd/alert/
%dir %attr(755,root,root) /usr/lib/bfd/alert/custom.d
/usr/lib/bfd/update-ipcountry.sh
/usr/lib/bfd/importconf
%config(noreplace) /etc/bfd/conf.bfd
%config(noreplace) /etc/bfd/internals.conf
%config(noreplace) /etc/bfd/pressure.conf
%config(noreplace) /etc/bfd/pressure-country.conf
%config(noreplace) /etc/bfd/exclude.files
%config(noreplace) /etc/bfd/ignore.hosts
/usr/share/bfd/ipcountry.dat
/usr/share/bfd/rules/
/usr/share/man/man1/bfd.1*
/usr/share/bash-completion/completions/bfd
%doc /usr/share/doc/bfd/README
%doc /usr/share/doc/bfd/CHANGELOG
/usr/lib/systemd/system/bfd.service
/usr/lib/systemd/system/bfd.timer
/usr/lib/systemd/system/bfd-watch.service
%if 0%{?el7}
/etc/init.d/bfd-watch
%endif
/etc/cron.d/bfd
/etc/cron.daily/bfd
/etc/logrotate.d/bfd
%dir %attr(750,root,root) /var/lib/bfd/tmp
%dir %attr(750,root,root) /var/lib/bfd/stats
# Symlink farm
%{legacy_path}/internals/bfd.lib.sh
%{legacy_path}/internals/tlog_lib.sh
%{legacy_path}/internals/elog_lib.sh
%{legacy_path}/internals/alert_lib.sh
%{legacy_path}/internals/bfd_alert.sh
%{legacy_path}/internals/geoip_lib.sh
%{legacy_path}/internals/pkg_lib.sh
%{legacy_path}/internals/internals.conf
%{legacy_path}/tlog
%{legacy_path}/alert
%{legacy_path}/update-ipcountry.sh
%{legacy_path}/importconf
%{legacy_path}/conf.bfd
%{legacy_path}/pressure.conf
%{legacy_path}/pressure-country.conf
%{legacy_path}/exclude.files
%{legacy_path}/ignore.hosts
%{legacy_path}/ipcountry.dat
%{legacy_path}/rules
%{legacy_path}/tmp
%{legacy_path}/stats
/usr/local/sbin/bfd

%changelog
* Thu Feb 26 2026 R-fx Networks <proj@rfxn.com> - 2.0.1-1
- Initial RPM package with FHS layout and symlink farm
- Pressure model with exponential-decay scoring
- 8 firewall backends with auto-detection
- Watch mode daemon with ~10s detection latency
- 57 service detection rules
- Country-based pressure multipliers
