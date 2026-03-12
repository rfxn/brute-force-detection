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
VER="2.0.1"

if [ "$(id -u)" -ne 0 ]; then
	echo "error: install.sh must be run as root."
	exit 1
fi

# Source pkg_lib for standardized installer primitives
# shellcheck disable=SC1091
# shellcheck disable=SC2034 # consumed by pkg_lib.sh pkg_backup()
PKG_BACKUP_SYMLINK="bfd.bk.last"
. ./files/internals/pkg_lib.sh

install_files(){
	# Remove stale install directory (backup already taken by caller)
	rm -rf "$INSPATH"

	# Copy source tree and documentation
	pkg_copy_tree "./files" "$INSPATH"
	/usr/bin/cp README CHANGELOG COPYING.GPL "$INSPATH"

	# Create runtime directories
	pkg_create_dirs "750" "$INSPATH/tmp" "$INSPATH/stats"

	# Set permissions: 750 dirs, 640 files, then executable overrides
	pkg_set_perms "$INSPATH" "750" "640" \
		"bfd" "tlog" "update-ipcountry.sh"

	# Custom template override directory (preserved across upgrades via importconf)
	[ -d "$INSPATH/alert/custom.d" ] || mkdir -p "$INSPATH/alert/custom.d"
	chmod 750 "$INSPATH/alert/custom.d"

	# Install uninstall.sh into install path
	if [ -f "uninstall.sh" ]; then
		/usr/bin/cp uninstall.sh "$INSPATH/"
		chmod 750 "$INSPATH/uninstall.sh"
	fi

	# CLI symlink
	mkdir -p "$(dirname "$BINPATH")"
	pkg_symlink "$INSPATH/bfd" "$BINPATH"

	# Logrotate configuration
	pkg_logrotate_install "logrotate.d.bfd" "bfd"

	# Man page (gzipped, with optional path substitution)
	if [ -f "bfd.1" ]; then
		if [ "$INSPATH" != "/usr/local/bfd" ]; then
			pkg_man_install "bfd.1" "1" "bfd" "/usr/local/bfd|$INSPATH"
		else
			pkg_man_install "bfd.1" "1" "bfd"
		fi
	fi

	# Bash tab completion
	if [ -f "bfd.bash-completion" ]; then
		pkg_bash_completion "bfd.bash-completion" "bfd"
		# path replacement for completion file if custom install path
		if [ "$INSPATH" != "/usr/local/bfd" ] && [ -f /etc/bash_completion.d/bfd ]; then
			pkg_sed_replace "/usr/local/bfd" "$INSPATH" /etc/bash_completion.d/bfd
		fi
	fi

	# Cron: preserve user's existing schedule before overwriting (F-078)
	local _old_cron_sched=""
	if [ "${_IS_UPGRADE:-0}" = "1" ] && [ -f /etc/cron.d/bfd ]; then
		pkg_cron_preserve_schedule /etc/cron.d/bfd _old_cron_sched || true
	fi
	# cron.daily rotation script
	pkg_cron_install "cron.daily" "/etc/cron.daily/bfd"
	# cron.d periodic scan entry
	if [ -f "cron" ]; then
		pkg_cron_install "cron" "/etc/cron.d/bfd"
	fi

	# Service units: systemd or SysVinit
	pkg_detect_init
	if [ "$_PKG_INIT_SYSTEM" = "systemd" ]; then
		local _unit_dir
		_unit_dir=$(_pkg_systemd_unit_dir)
		if [ -f "bfd.service" ] && [ -f "bfd.timer" ]; then
			pkg_service_install_multi "bfd" \
				"bfd.service" "bfd.timer"
			if [ -f "bfd-watch.service" ]; then
				pkg_service_install "bfd-watch" "bfd-watch.service"
			fi
		fi
		# Clean legacy /etc/systemd/system/ units from pre-pkg_lib installs
		# to prevent systemd priority conflict with auto-detected unit dir
		if [ "${_IS_UPGRADE:-0}" = "1" ]; then
			rm -f /etc/systemd/system/bfd.service \
			      /etc/systemd/system/bfd.timer \
			      /etc/systemd/system/bfd-watch.service 2>/dev/null  # safe: may not exist
		fi
	else
		# SysVinit: install init script for watch mode
		if [ -f "bfd-watch.init" ]; then
			pkg_service_install "bfd-watch" "bfd-watch.init"
		fi
	fi

	# tlog: replace default BASERUN for cursor storage security
	sed -i "s|BASERUN=\"\${BASERUN:-/tmp}\"|BASERUN=\"\${BASERUN:-$INSPATH/tmp}\"|" "$INSPATH/tlog"

	# Replace default paths when installing to a custom location
	if [ "$INSPATH" != "/usr/local/bfd" ]; then
		pkg_sed_replace "/usr/local/bfd" "$INSPATH" \
			"$INSPATH/bfd" "$INSPATH/internals/bfd.lib.sh" \
			"$INSPATH/internals/internals.conf" \
			"$INSPATH/exclude.files" \
			"$INSPATH/update-ipcountry.sh" /etc/cron.daily/bfd
	fi
	if [ "$BINPATH" != "/usr/local/sbin/bfd" ]; then
		pkg_sed_replace "/usr/local/sbin/bfd" "$BINPATH" /etc/cron.d/bfd
		if [ "$_PKG_INIT_SYSTEM" = "systemd" ]; then
			pkg_sed_replace "/usr/local/sbin/bfd" "$BINPATH" \
				"${_unit_dir}/bfd.service" \
				"${_unit_dir}/bfd.timer" \
				"${_unit_dir}/bfd-watch.service"
		fi
		# update init script if installed
		local _idir
		for _idir in /etc/rc.d/init.d /etc/init.d; do
			if [ -f "$_idir/bfd-watch" ]; then
				pkg_sed_replace "/usr/local/sbin/bfd" "$BINPATH" "$_idir/bfd-watch"
			fi
		done
	fi

	# Restore user-customized cron schedule after all sed operations (F-078)
	if [ -n "${_old_cron_sched:-}" ] && [ -f /etc/cron.d/bfd ]; then
		pkg_cron_restore_schedule /etc/cron.d/bfd "$_old_cron_sched" || true
	fi

	# daemon-reload after sed so systemd sees final paths
	if [ "$_PKG_INIT_SYSTEM" = "systemd" ]; then
		systemctl daemon-reload 2>/dev/null || true  # safe: refresh unit cache
	fi
}

_stop_services(){
	# stop bfd-watch before installing to avoid delay and output leaks
	if command -v systemctl >/dev/null 2>&1; then
		if systemctl is-active bfd-watch.service >/dev/null 2>&1; then
			echo -n "Stopping bfd-watch... "
			systemctl stop bfd-watch.service 2>/dev/null || true
			echo "done"
		fi
	else
		local _initdir=""
		for _initdir in /etc/rc.d/init.d /etc/init.d; do
			if [ -f "$_initdir/bfd-watch" ]; then
				break
			fi
			_initdir=""
		done
		if [ -n "$_initdir" ]; then
			local _pid=""
			if [ -f /var/run/bfd-watch.pid ]; then
				_pid=$(cat /var/run/bfd-watch.pid 2>/dev/null) || true
			fi
			if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null; then
				echo -n "Stopping bfd-watch... "
				"$_initdir/bfd-watch" stop 2>/dev/null || true
				echo "done"
			fi
		fi
	fi
}

_enable_services(){
	_WATCH_STATE=""
	if command -v systemctl >/dev/null 2>&1; then
		local _watch_enabled _timer_enabled
		_watch_enabled=$(systemctl is-enabled bfd-watch.service 2>/dev/null) || true
		_timer_enabled=$(systemctl is-enabled bfd.timer 2>/dev/null) || true
		if [ "$_watch_enabled" = "enabled" ]; then
			echo -n "Starting bfd-watch... "
			systemctl start bfd-watch.service 2>/dev/null || true
			echo "done"
			_WATCH_STATE="restarted"
		elif [ "$_timer_enabled" = "enabled" ]; then
			_WATCH_STATE="timer-active"
		else
			echo -n "Enabling bfd-watch... "
			systemctl enable --now bfd-watch.service 2>/dev/null || true
			echo "done"
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
				echo -n "Starting bfd-watch... "
				"$_initdir/bfd-watch" start 2>/dev/null || true
				echo "done"
				_WATCH_STATE="restarted"
			else
				echo -n "Enabling bfd-watch... "
				if command -v chkconfig >/dev/null 2>&1; then
					chkconfig bfd-watch on 2>/dev/null || true
				elif command -v update-rc.d >/dev/null 2>&1; then
					update-rc.d bfd-watch defaults 2>/dev/null || true
				fi
				"$_initdir/bfd-watch" start 2>/dev/null || true
				echo "done"
				_WATCH_STATE="enabled"
			fi
		else
			_WATCH_STATE="cron-only"
		fi
	fi
}

postinfo(){
	echo ""
	pkg_item "Install path" "$INSPATH"
	pkg_item "Config path" "$INSPATH/conf.bfd"
	pkg_item "Executable" "$BINPATH"
	case "${_WATCH_STATE:-}" in
		enabled)
			pkg_item "Watch mode" "enabled and started (~10s detection latency)"
			pkg_item "Config reload" "kill -HUP \$(cat /var/run/bfd-watch.pid)"
			pkg_item "Cron fallback" "active (skipped while watch runs)"
			if [ "${_IS_UPGRADE:-0}" = "1" ]; then
				echo ""
				echo "  NOTE: Watch mode is new in BFD 2.x and has been enabled for"
				echo "  this upgrade. It replaces cron-only scheduling (~2m latency)"
				echo "  with a persistent daemon (~10s latency). The cron fallback"
				echo "  remains active and resumes automatically if the daemon stops."
				echo ""
				echo "  To revert to cron-only scheduling:"
				if command -v systemctl >/dev/null 2>&1; then
					echo "    systemctl disable --now bfd-watch.service"
				else
					echo "    service bfd-watch stop"
					if command -v chkconfig >/dev/null 2>&1; then
						echo "    chkconfig bfd-watch off"
					elif command -v update-rc.d >/dev/null 2>&1; then
						echo "    update-rc.d bfd-watch disable"
					fi
				fi
			fi
			;;
		restarted)
			pkg_item "Watch mode" "restarted with updated installation"
			pkg_item "Config reload" "kill -HUP \$(cat /var/run/bfd-watch.pid)"
			pkg_item "Cron fallback" "active (skipped while watch runs)"
			;;
		timer-active)
			pkg_item "Timer mode" "active (bfd.timer)"
			pkg_item "Cron fallback" "active"
			echo ""
			echo "  Tip: switch to watch mode for ~10s latency:"
			echo "    systemctl disable bfd.timer"
			echo "    systemctl enable --now bfd-watch.service"
			;;
		cron-only)
			pkg_item "Watch mode" "not available (no init system detected)"
			pkg_item "Cron fallback" "active (~2m detection latency)"
			;;
		*)
			pkg_item "Cron fallback" "active (~2m detection latency)"
			;;
	esac
}

if [ -d "$INSPATH" ]; then
	_IS_UPGRADE=1
	pkg_header "BFD" "$VER" "upgrade"
	_stop_services
	pkg_section "Backing up existing installation"
	pkg_backup "$INSPATH"
	pkg_section "Installing files"
	install_files
	pkg_section "Importing configuration"
	BK_LAST=$(pkg_backup_path "$INSPATH") ./importconf
	_enable_services
	postinfo
	pkg_success "BFD ${VER} upgrade complete"
else
	pkg_header "BFD" "$VER" "install"
	pkg_section "Installing files"
	install_files
	_enable_services
	postinfo
	pkg_success "BFD ${VER} installation complete"
fi

# Non-blocking initial country database download (runs in background).
# If download fails (no network, no curl/wget), the stub ipcountry.dat
# remains and BFD operates without country data. || true prevents
# background failure from propagating; disown avoids set -e interaction.
# Subshell output redirected before & to prevent pipe-inherited fd hang.
if [ -x "$INSPATH/update-ipcountry.sh" ]; then
	echo "Downloading IP country database in background..."
	( "$INSPATH/update-ipcountry.sh" >/dev/null 2>&1 || true ) &  # non-fatal: network may be unavailable
	disown 2>/dev/null  # safe: may not be available in all shells
fi
