#!/bin/bash
# Brute Force Detection 2.0.1 <bfd@rfxn.com>
###
# Copyright (C) 1999-2026, R-fx Networks <proj@rfxn.com>
# Copyright (C) 2026, Ryan MacDonald <ryan@rfxn.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
###
#
INSPATH="${INSTALL_PATH:-/usr/local/bfd}"
BINPATH="${BIN_PATH:-/usr/local/sbin/bfd}"
APPN="BFD"

if [ "$(id -u)" -ne 0 ]; then
	echo "error: uninstall.sh must be run as root."
	exit 1
fi

# Source pkg_lib for standardized uninstall primitives
if [ -f "$INSPATH/internals/pkg_lib.sh" ]; then
	# shellcheck disable=SC1091
	. "$INSPATH/internals/pkg_lib.sh"
elif [ -f "files/internals/pkg_lib.sh" ]; then
	# shellcheck disable=SC1091
	. ./files/internals/pkg_lib.sh
fi

uninstall(){
pkg_uninstall_confirm "$APPN" || exit 0

if [ -d "$INSPATH" ]; then
	# Remove services (systemd units, SysV init scripts, chkconfig/update-rc.d)
	pkg_service_uninstall "bfd"
	pkg_service_uninstall "bfd-watch"
	# Remove legacy /etc/systemd/system/ units from pre-pkg_lib installs
	command rm -f /etc/systemd/system/bfd.service \
	      /etc/systemd/system/bfd.timer \
	      /etc/systemd/system/bfd-watch.service 2>/dev/null  # safe: may not exist
	# Additional SysV state files
	command rm -f /var/run/bfd-watch.pid /var/lock/subsys/bfd-watch

	# Remove man page, bash completion, logrotate
	pkg_uninstall_man "1" "bfd"
	pkg_uninstall_completion "bfd"
	pkg_uninstall_logrotate "bfd"

	# Remove custom log path if configured (grep+sed, no eval/source)
	local _custom_log=""
	if [ -f "$INSPATH/conf.bfd" ]; then
		_custom_log=$(grep -E '^BFD_LOG_PATH=' "$INSPATH/conf.bfd" 2>/dev/null \
			| tail -1 | sed 's/^BFD_LOG_PATH=//; s/^"//; s/"$//; s/^'"'"'//; s/'"'"'$//') || true
	fi
	if [ -n "$_custom_log" ] && [ "$_custom_log" != "/var/log/bfd_log" ]; then
		command rm -f "$_custom_log"
	fi

	# Remove cron files, install directory, symlink, backups, default log
	pkg_uninstall_cron /etc/cron.d/bfd /etc/cron.daily/bfd
	pkg_uninstall_files "$INSPATH".bk.* "$INSPATH".[0-9]* "$INSPATH" "$BINPATH" /var/log/bfd_log

	pkg_success "$APPN has been uninstalled."
else
	echo "$APPN does not appear to be installed."
fi
}

uninstall
