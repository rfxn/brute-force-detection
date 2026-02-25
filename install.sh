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
set -eu
cd "$(dirname "$0")"

INSPATH="${INSTALL_PATH:-/usr/local/bfd}"
BINPATH="${BIN_PATH:-/usr/local/sbin/bfd}"

if [ "$(id -u)" -ne 0 ]; then
	echo "error: install.sh must be run as root."
	exit 1
fi

backup(){
if [ -d "$INSPATH" ]; then
        DVAL=$(date +"%d%m%Y-%s")
	mv "$INSPATH" "$INSPATH.bk.$DVAL"
	rm -f "$INSPATH.bk.last"
	ln -s "$INSPATH.bk.$DVAL" "$INSPATH.bk.last"
	# shellcheck disable=SC2034
	OBK=1
fi
}

install(){
        rm -rf "$INSPATH"
        mkdir "$INSPATH"
        mkdir -p "$INSPATH/tmp"
        mkdir -p "$INSPATH/stats"
	cp logrotate.d.bfd /etc/logrotate.d/bfd
        cp -R files/* "$INSPATH"
	cp README CHANGELOG COPYING.GPL "$INSPATH"
	rm -f /etc/cron.daily/bfd
	cp cron.daily /etc/cron.daily/bfd
	chmod 755 /etc/cron.daily/bfd
        find "$INSPATH" -maxdepth 1 -type f -exec chmod 640 {} +
        chmod 750 "$INSPATH/tlog"
        chmod 750 "$INSPATH/bfd"
	chmod 750 "$INSPATH/rules"
	chmod 640 "$INSPATH"/rules/*
	chmod 750 "$INSPATH/tmp"
	chmod 750 "$INSPATH/stats"
	chmod 640 "$INSPATH/alert.bfd"
	mkdir -p "$(dirname "$BINPATH")"
        ln -fs "$INSPATH/bfd" "$BINPATH"
	if [ -f "uninstall.sh" ]; then
		cp uninstall.sh "$INSPATH/"
		chmod 750 "$INSPATH/uninstall.sh"
	fi
	# install man page
	if [ -f "bfd.1" ] && [ -d /usr/share/man/man1 ]; then
		cp bfd.1 /usr/share/man/man1/bfd.1
		chmod 644 /usr/share/man/man1/bfd.1
	fi
	# install bash tab completion
	if [ -f "bfd.bash-completion" ] && [ -d /etc/bash_completion.d ]; then
		cp bfd.bash-completion /etc/bash_completion.d/bfd
		chmod 644 /etc/bash_completion.d/bfd
	fi
	if [ -f "cron" ]; then
		cp cron /etc/cron.d/bfd
		chmod 644 /etc/cron.d/bfd
	fi
	# install systemd units if systemd is available
	if command -v systemctl >/dev/null 2>&1; then
		if [ -f "bfd.service" ] && [ -f "bfd.timer" ]; then
			cp bfd.service /etc/systemd/system/bfd.service
			cp bfd.timer /etc/systemd/system/bfd.timer
			chmod 644 /etc/systemd/system/bfd.service /etc/systemd/system/bfd.timer
			if [ -f "bfd-watch.service" ]; then
				cp bfd-watch.service /etc/systemd/system/bfd-watch.service
				chmod 644 /etc/systemd/system/bfd-watch.service
			fi
		fi
	else
		# SysVinit: install init script for watch mode
		if [ -f "bfd-watch.init" ]; then
			local _initdir=""
			if [ -d "/etc/rc.d/init.d" ]; then
				_initdir="/etc/rc.d/init.d"
			elif [ -d "/etc/init.d" ]; then
				_initdir="/etc/init.d"
			fi
			if [ -n "$_initdir" ]; then
				cp bfd-watch.init "$_initdir/bfd-watch"
				chmod 755 "$_initdir/bfd-watch"
			fi
		fi
	fi
	# replace default paths when installing to a custom location
	if [ "$INSPATH" != "/usr/local/bfd" ]; then
		sed -i "s|/usr/local/bfd|$INSPATH|g" \
			"$INSPATH/bfd" "$INSPATH/bfd.lib.sh" \
			"$INSPATH/internals.conf" "$INSPATH/tlog" \
			"$INSPATH/exclude.files" /etc/cron.daily/bfd
		if [ -f /usr/share/man/man1/bfd.1 ]; then
			sed -i "s|/usr/local/bfd|$INSPATH|g" /usr/share/man/man1/bfd.1
		fi
		if [ -f /etc/bash_completion.d/bfd ]; then
			sed -i "s|/usr/local/bfd|$INSPATH|g" /etc/bash_completion.d/bfd
		fi
	fi
	if [ "$BINPATH" != "/usr/local/sbin/bfd" ]; then
		sed -i "s|/usr/local/sbin/bfd|$BINPATH|g" /etc/cron.d/bfd
		if command -v systemctl >/dev/null 2>&1; then
			sed -i "s|/usr/local/sbin/bfd|$BINPATH|g" \
				/etc/systemd/system/bfd.service \
				/etc/systemd/system/bfd.timer \
				/etc/systemd/system/bfd-watch.service 2>/dev/null || true
		fi
		# update init script if installed
		local _idir
		for _idir in /etc/rc.d/init.d /etc/init.d; do
			if [ -f "$_idir/bfd-watch" ]; then
				sed -i "s|/usr/local/sbin/bfd|$BINPATH|g" "$_idir/bfd-watch"
			fi
		done
	fi
	# daemon-reload after sed so systemd sees final paths
	if command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload 2>/dev/null || true
	fi
}

_enable_services(){
	_WATCH_STATE=""
	if command -v systemctl >/dev/null 2>&1; then
		local _watch_enabled _timer_enabled
		_watch_enabled=$(systemctl is-enabled bfd-watch.service 2>/dev/null) || true
		_timer_enabled=$(systemctl is-enabled bfd.timer 2>/dev/null) || true
		if [ "$_watch_enabled" = "enabled" ]; then
			systemctl restart bfd-watch.service 2>/dev/null || true
			_WATCH_STATE="restarted"
		elif [ "$_timer_enabled" = "enabled" ]; then
			_WATCH_STATE="timer-active"
		else
			systemctl enable --now bfd-watch.service 2>/dev/null || true
			_WATCH_STATE="enabled"
		fi
	else
		local _initdir="" _pid=""
		for _initdir in /etc/rc.d/init.d /etc/init.d; do
			if [ -f "$_initdir/bfd-watch" ]; then
				break
			fi
			_initdir=""
		done
		if [ -n "$_initdir" ]; then
			if [ -f /var/run/bfd-watch.pid ]; then
				_pid=$(cat /var/run/bfd-watch.pid 2>/dev/null) || true
			fi
			if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null; then
				"$_initdir/bfd-watch" restart 2>/dev/null || true
				_WATCH_STATE="restarted"
			else
				if command -v chkconfig >/dev/null 2>&1; then
					chkconfig bfd-watch on 2>/dev/null || true
				elif command -v update-rc.d >/dev/null 2>&1; then
					update-rc.d bfd-watch defaults 2>/dev/null || true
				fi
				"$_initdir/bfd-watch" start 2>/dev/null || true
				_WATCH_STATE="enabled"
			fi
		else
			_WATCH_STATE="cron-only"
		fi
	fi
}

postinfo(){
	echo ".: BFD installed"
	echo "Install path:    $INSPATH"
	echo "Config path:     $INSPATH/conf.bfd"
	echo "Executable:      $BINPATH"
	echo ""
	case "${_WATCH_STATE:-}" in
		enabled)
			echo "Watch mode:      enabled and started (~10s detection latency)"
			echo "Cron fallback:   active (skipped while watch runs)"
			;;
		restarted)
			echo "Watch mode:      restarted with updated installation"
			echo "Cron fallback:   active (skipped while watch runs)"
			;;
		timer-active)
			echo "Timer mode:      active (bfd.timer)"
			echo "Cron fallback:   active"
			echo ""
			echo "  Recommendation: switch to watch mode for ~10s latency:"
			echo "    systemctl disable bfd.timer"
			echo "    systemctl enable --now bfd-watch.service"
			;;
		cron-only)
			echo "Watch mode:      not available (no init system detected)"
			echo "Cron fallback:   active (~2m detection latency)"
			;;
		*)
			echo "Cron fallback:   active (~2m detection latency)"
			;;
	esac
}

if [ -d "$INSPATH" ]; then
	backup
	install
	./importconf
	_enable_services
	postinfo
else
	install
	_enable_services
	postinfo
fi
