#!/bin/bash
# BFD 1.5-2 <bfd@rfxn.com>
###
# Copyright (C) 1999-2008 R-fx Networks <proj@r-fx.org>
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

backup(){
if [ -d "/usr/local/bfd" ]; then
        DVAL=`date +"%d%m%Y-%s"`
	mv /usr/local/bfd/ /usr/local/bfd.bk.$DVAL
	rm -f /usr/local/bfd.bk.last
	ln -s /usr/local/bfd.bk.$DVAL /usr/local/bfd.bk.last
	OBK=1
fi
}

install(){
        rm -rf $INSPATH
        mkdir $INSPATH
	cp logrotate.d.bfd /etc/logrotate.d/bfd
        cp -R files/* $INSPATH
	cp README CHANGELOG COPYING.GPL $INSPATH
	rm -f /etc/cron.daily/bfd
	cp cron.daily /etc/cron.daily/bfd
	chmod 755 /etc/cron.daily/bfd
        chmod 640 $INSPATH/*
        chmod 750 $INSPATH/tlog
        chmod 750 $INSPATH/bfd
	chmod 750 $INSPATH/rules
	chmod 750 $INSPATH/tmp
	chmod 750 $INSPATH/alert.bfd
        ln -fs $INSPATH/bfd $BINPATH
	if [ -f "uninstall.sh" ]; then
		cp uninstall.sh $INSPATH/
		chmod 750 $INSPATH/uninstall.sh
	fi
	if [ -f "cron" ]; then
		cp cron /etc/cron.d/bfd
		chmod 644 /etc/cron.d/bfd
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
