#!/bin/bash
# BFD 0.4 <bfd@rfxn.com>
###
# Copyright (C) 1999-2008, R-fx Networks <proj@r-fx.org>
# Copyright (C) 2008, Ryan MacDonald <ryan@r-fx.org>
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
INSPATH="/usr/local/bfd"
BINPATH="/usr/local/sbin/bfd"
APPN="BFD"

uninstall(){
echo "Remove $APPN from this system; are you sure ?"
echo "Press any key to continue or ^C to abort."
read val

if [ -d "$INSPATH" ]; then
	rm -rf $INSPATH $BINPATH /etc/cron.d/bfd /etc/logrotate.d/bfd /var/log/bfd_log
	echo "$APPN has been uninstalled."
else
	echo "$APPN does not appear to be installed."
fi
}

uninstall
