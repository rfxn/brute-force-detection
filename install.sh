#!/bin/bash
# Brute Force Detection 1.6-1 <bfd@rfxn.com>
###
# Copyright (C) 1999-2026, R-fx Networks <proj@r-fx.org>
# Copyright (C) 2026, Ryan MacDonald <ryan@r-fx.org>
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

INSPATH="/usr/local/bfd"
BINPATH="/usr/local/sbin/bfd"

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
	cp logrotate.d.bfd /etc/logrotate.d/bfd
        cp -R files/* "$INSPATH"
	cp README CHANGELOG COPYING.GPL "$INSPATH"
	rm -f /etc/cron.daily/bfd
	cp cron.daily /etc/cron.daily/bfd
	chmod 755 /etc/cron.daily/bfd
        chmod 640 "$INSPATH"/*
        chmod 750 "$INSPATH/tlog"
        chmod 750 "$INSPATH/bfd"
	chmod 750 "$INSPATH/rules"
	chmod 750 "$INSPATH/tmp"
	chmod 750 "$INSPATH/alert.bfd"
        ln -fs "$INSPATH/bfd" "$BINPATH"
	if [ -f "uninstall.sh" ]; then
		cp uninstall.sh "$INSPATH/"
		chmod 750 "$INSPATH/uninstall.sh"
	fi
	if [ -f "cron" ]; then
		cp cron /etc/cron.d/bfd
		chmod 644 /etc/cron.d/bfd
	fi
	# install systemd timer if systemd is available
	if command -v systemctl >/dev/null 2>&1; then
		if [ -f "bfd.service" ] && [ -f "bfd.timer" ]; then
			cp bfd.service /etc/systemd/system/bfd.service
			cp bfd.timer /etc/systemd/system/bfd.timer
			chmod 644 /etc/systemd/system/bfd.service /etc/systemd/system/bfd.timer
			systemctl daemon-reload
			echo "  systemd timer installed (enable with: systemctl enable --now bfd.timer)"
		fi
	fi
}

postinfo(){
	echo ".: BFD installed"
	echo "Install path:    $INSPATH"
	echo "Config path:     $INSPATH/conf.bfd"
	echo "Executable path: $BINPATH"
}

if [ -d "$INSPATH" ]; then
	backup
	install
	postinfo
	./importconf
else
	install
	postinfo
fi
