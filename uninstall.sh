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

uninstall(){
echo "Remove $APPN from this system; are you sure ?"
echo "Press any key to continue or ^C to abort."
read -r _

if [ -d "$INSPATH" ]; then
	# clean up SysVinit init script if present
	local _initdir
	for _initdir in /etc/rc.d/init.d /etc/init.d; do
		if [ -f "$_initdir/bfd-watch" ]; then
			"$_initdir/bfd-watch" stop 2>/dev/null || true
			if command -v chkconfig >/dev/null 2>&1; then
				chkconfig --del bfd-watch 2>/dev/null || true
			elif command -v update-rc.d >/dev/null 2>&1; then
				update-rc.d -f bfd-watch remove 2>/dev/null || true
			fi
			rm -f "$_initdir/bfd-watch"
		fi
	done
	rm -f /var/run/bfd-watch.pid /var/lock/subsys/bfd-watch
	# clean up systemd units if present
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop bfd.service 2>/dev/null || true
		systemctl disable bfd.service 2>/dev/null || true
		systemctl stop bfd.timer 2>/dev/null || true
		systemctl disable bfd.timer 2>/dev/null || true
		systemctl stop bfd-watch.service 2>/dev/null || true
		systemctl disable bfd-watch.service 2>/dev/null || true
		rm -f /etc/systemd/system/bfd.service /etc/systemd/system/bfd.timer /etc/systemd/system/bfd-watch.service
		systemctl daemon-reload 2>/dev/null || true
	fi
	rm -f /usr/share/man/man1/bfd.1
	rm -rf "$INSPATH".bk.* "$INSPATH" "$BINPATH" /etc/cron.d/bfd /etc/cron.daily/bfd /etc/logrotate.d/bfd /var/log/bfd_log
	echo "$APPN has been uninstalled."
else
	echo "$APPN does not appear to be installed."
fi
}

uninstall
