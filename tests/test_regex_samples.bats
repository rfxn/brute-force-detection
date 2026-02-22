#!/usr/bin/env bats
#
# Automated regex pattern validation using tests/regex_samples.txt
# Each test feeds a sample log line through the rule's FAILREGEX patterns
# and verifies the expected IP is extracted by extract_hosts().
#

load 'helpers/bfd-common'

setup() {
	TEST_TMPDIR=$(mktemp -d)
	INSTALL_PATH="$TEST_TMPDIR/bfd"
	state_init "$INSTALL_PATH"
	BFD_LOG_PATH="$TEST_TMPDIR/bfd.log"
	touch "$BFD_LOG_PATH"
	OUTPUT_SYSLOG="0"
	OUTPUT_SYSLOG_FILE="/dev/null"
	IGNOREREGEX=""
}

teardown() {
	rm -rf "$TEST_TMPDIR"
}

# --- sshd ---

@test "regex: sshd - Failed password" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2" | \
		extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ "$result" = "192.168.1.100" ]
}

@test "regex: sshd - Invalid user" {
	local result
	result=$(echo "Feb 22 10:15:05 myhost sshd[12345]: Invalid user admin from 10.0.0.5 port 54321 ssh2" | \
		extract_hosts "sshd.*Invalid user .* from <HOST>")
	[ "$result" = "10.0.0.5" ]
}

@test "regex: sshd - DenyUsers" {
	local result
	result=$(echo "Feb 22 10:15:07 myhost sshd[12345]: User root from 172.16.0.1 not allowed because listed in DenyUsers" | \
		extract_hosts "DenyUsers.*User .* from <HOST>")
	[ -z "$result" ]
}

@test "regex: sshd - DenyUsers (alt pattern)" {
	local result
	result=$(echo "Feb 22 10:15:07 myhost sshd[12345]: User root from 172.16.0.1 not allowed because listed in DenyUsers" | \
		extract_hosts "sshd.*User .* from <HOST> not allowed")
	[ "$result" = "172.16.0.1" ]
}

# --- dovecot ---

@test "regex: dovecot - pop3-login auth failed" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost dovecot: pop3-login: Aborted login (auth failed, 1 attempts): user=<admin>, method=PLAIN, rip=192.168.1.100, lip=10.0.0.1" | \
		extract_hosts "pop3-login.*auth failed.*rip=<HOST>")
	[ "$result" = "192.168.1.100" ]
}

@test "regex: dovecot - imap-login auth failed" {
	local result
	result=$(echo "Feb 22 10:15:05 myhost dovecot: imap-login: Disconnected (auth failed, 3 attempts): user=<test>, method=PLAIN, rip=10.0.0.5, lip=10.0.0.1" | \
		extract_hosts "imap-login.*auth failed.*rip=<HOST>")
	[ "$result" = "10.0.0.5" ]
}

@test "regex: dovecot - IGNOREREGEX filters no auth attempts" {
	IGNOREREGEX="no auth attempts"
	local result
	result=$(echo "Feb 22 myhost dovecot: pop3-login: Aborted login (no auth attempts): user=<>, rip=10.0.0.5, lip=10.0.0.1" | \
		extract_hosts "pop3-login.*auth failed.*rip=<HOST>")
	[ -z "$result" ]
}

# --- postfix ---

@test "regex: postfix - SASL LOGIN auth failed" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost postfix/smtpd[9876]: warning: unknown[192.168.1.50]: SASL LOGIN authentication failed: authentication failure" | \
		extract_hosts "\[<HOST>\].*SASL.*authentication failed")
	[ "$result" = "192.168.1.50" ]
}

@test "regex: postfix - SASL PLAIN auth failed" {
	local result
	result=$(echo "Feb 22 10:15:05 myhost postfix/smtpd[9877]: warning: mail.example.com[10.20.30.40]: SASL PLAIN authentication failed: UGFzc3dvcmQ6" | \
		extract_hosts "\[<HOST>\].*SASL.*authentication failed")
	[ "$result" = "10.20.30.40" ]
}

# --- exim_authfail ---

@test "regex: exim_authfail - login authenticator failed" {
	local result
	result=$(echo "2024-02-22 10:15:03 login authenticator failed for (test) [192.168.1.100]:12345: 535 Incorrect authentication data (set_id=test@example.com)" | \
		extract_hosts "login authenticator failed.*\[<HOST>\]")
	[ "$result" = "192.168.1.100" ]
}

# --- exim_nxuser ---

@test "regex: exim_nxuser - No such person" {
	local result
	result=$(echo "2024-02-22 10:15:03 H=mail.example.com [10.0.0.5] F=<sender@example.com> rejected RCPT <nobody@example.com>: No such person at this address" | \
		extract_hosts "\[<HOST>\].*No such person at this address")
	[ "$result" = "10.0.0.5" ]
}

# --- vsftpd ---

@test "regex: vsftpd - PAM authentication failure" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost vsftpd: pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=admin rhost=192.168.1.50" | \
		extract_hosts "vsftpd.*authentication failure.*rhost=<HOST>")
	[ "$result" = "192.168.1.50" ]
}

# --- vsftpd2 ---

@test "regex: vsftpd2 - FAIL LOGIN" {
	local result
	result=$(echo 'Wed Feb 22 10:15:03 2024 [pid 12345] FAIL LOGIN: Client "10.0.0.5"' | \
		extract_hosts 'FAIL LOGIN: Client "<HOST>"')
	[ "$result" = "10.0.0.5" ]
}

# --- proftpd ---

@test "regex: proftpd - no such user" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost proftpd[12345]: myhost (172.16.0.1[172.16.0.1]) - USER admin: no such user found from 172.16.0.1 [172.16.0.1] to 10.0.0.1:21" | \
		extract_hosts "proftpd.*no such user found from <HOST>")
	[ "$result" = "172.16.0.1" ]
}

# --- pure-ftpd ---

@test "regex: pure-ftpd - Authentication failed" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost pure-ftpd: (?@192.168.1.100) [WARNING] Authentication failed for user [admin]" | \
		extract_hosts "pure-ftpd.*@<HOST>.*WARNING.*Authentication failed")
	[ "$result" = "192.168.1.100" ]
}

# --- sendmail ---

@test "regex: sendmail - relaying denied" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost sendmail[12345]: ruleset=check_rcpt, arg1=<user@example.com>, relay=[192.168.1.50], reject=550 relaying denied" | \
		extract_hosts "sendmail.*relay=\[<HOST>\]")
	[ "$result" = "192.168.1.50" ]
}

# --- courier ---

@test "regex: courier - LOGIN FAILED" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost imapd: LOGIN FAILED, user=admin, ip=[192.168.1.100]" | \
		extract_hosts "LOGIN FAILED.*\[<HOST>\]")
	[ "$result" = "192.168.1.100" ]
}

# --- vpopmail ---

@test "regex: vpopmail - password fail" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost vchkpw-pop3: password fail admin@example.com:10.0.0.5" | \
		extract_hosts "vchkpw-pop3.*password fail.*:<HOST>")
	[ "$result" = "10.0.0.5" ]
}

@test "regex: vpopmail - user not found" {
	local result
	result=$(echo "Feb 22 10:15:05 myhost vchkpw-pop3: vpopmail user not found nobody@example.com:172.16.0.1" | \
		extract_hosts "vchkpw-pop3.*user not found.*:<HOST>")
	[ "$result" = "172.16.0.1" ]
}

# --- rh_imapd ---

@test "regex: rh_imapd - Login failed" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost imapd[12345]: Login failed user=admin auth=admin host=[192.168.1.100]" | \
		extract_hosts "imapd.*Login failed.*\[<HOST>\]")
	[ "$result" = "192.168.1.100" ]
}

# --- rh_ipop3d ---

@test "regex: rh_ipop3d - Login failed" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost ipop3d[12345]: Login failed user=admin auth=admin host=[10.0.0.5]" | \
		extract_hosts "ipop3d.*Login failed.*\[<HOST>\]")
	[ "$result" = "10.0.0.5" ]
}

# --- cpanel ---

@test "regex: cpanel - FAILED LOGIN" {
	local result
	result=$(echo "192.168.1.100 - admin [02/22/2024:10:15:03 -0000] FAILED LOGIN whostmgrd: ip - password" | \
		extract_hosts "<HOST> -.* FAILED LOGIN")
	[ "$result" = "192.168.1.100" ]
}

# --- modsec ---

@test "regex: modsec - ModSecurity Access denied" {
	local result
	result=$(echo '[Wed Feb 22 10:15:03.123456 2024] [security2:error] [pid 12345] [client 203.0.113.10:54321] ModSecurity: Access denied with code 403 (phase 2). [id "1234"]' | \
		extract_hosts "\[client <HOST>.*ModSecurity: Access denied")
	[ "$result" = "203.0.113.10" ]
}

# --- openvpnas ---

@test "regex: openvpnas - AUTH_FAILED" {
	local result
	result=$(echo "2024-02-22T10:15:03+0000 [] AUTH_FAILED,r=user,ip=10.0.0.5,cn=,key=" | \
		extract_hosts "AUTH_FAILED.*ip=<HOST>")
	[ "$result" = "10.0.0.5" ]
}

# --- asterisk_badauth ---

@test "regex: asterisk_badauth - Wrong password" {
	local result
	result=$(echo "[2024-02-22 10:15:03] NOTICE[12345] chan_sip.c: Wrong password for user 'admin' from '203.0.113.50':5060" | \
		extract_hosts "Wrong password.*'<HOST>'")
	[ "$result" = "203.0.113.50" ]
}

# --- asterisk_iax ---

@test "regex: asterisk_iax - failed MD5 authentication" {
	local result
	result=$(echo "[2024-02-22 10:15:03] NOTICE[12345] chan_iax2.c: Host 192.168.1.50 failed MD5 authentication for 'admin' (key 'abc123')" | \
		extract_hosts "Host <HOST> failed MD5 authentication")
	[ "$result" = "192.168.1.50" ]
}

# --- asterisk_nopeer ---

@test "regex: asterisk_nopeer - No matching peer" {
	local result
	result=$(echo "[2024-02-22 10:15:03] NOTICE[12345] chan_sip.c: No matching peer found from '10.0.0.5':5060" | \
		extract_hosts "chan_sip.*No matching peer found.*'<HOST>'")
	[ "$result" = "10.0.0.5" ]
}

# ============================================================
# NEW RULES (fail2ban/CSF-inspired)
# ============================================================

# --- apache-auth ---

@test "regex: apache-auth - AH01617 password mismatch" {
	local result
	result=$(echo '[Tue Sep 08 13:34:46.224312 2015] [auth_basic:error] [pid 2043:tid 140302748706560] [client 76.181.65.196:53340] AH01617: user mfoley: authentication failure for "/admin/": Password Mismatch' | \
		extract_hosts "\[client <HOST>.*AH0161[78]")
	[ "$result" = "76.181.65.196" ]
}

@test "regex: apache-auth - AH01618 user not found" {
	local result
	result=$(echo '[Thu Sep 11 01:29:56.950717 2014] [auth_basic:error] [pid 8153] [client 192.168.1.50] AH01618: user joe not found: /admin/' | \
		extract_hosts "\[client <HOST>.*AH0161[78]")
	[ "$result" = "192.168.1.50" ]
}

@test "regex: apache-auth - Apache 2.2 auth failure" {
	local result
	result=$(echo '[Mon Dec 02 10:44:23 2013] [error] [client 10.0.0.5] user admin: authentication failure for "/admin": Password Mismatch' | \
		extract_hosts "\[client <HOST>\].*authentication failure")
	[ "$result" = "10.0.0.5" ]
}

# --- nginx-http-auth ---

@test "regex: nginx-http-auth - password mismatch" {
	local result
	result=$(echo '2024/02/22 10:15:03 [error] 5596#560: *3 user "admin": password mismatch, client: 192.168.1.50, server: example.com, request: "GET /admin HTTP/1.1", host: "example.com"' | \
		extract_hosts "password mismatch, client: <HOST>")
	[ "$result" = "192.168.1.50" ]
}

@test "regex: nginx-http-auth - user not found" {
	local result
	result=$(echo '2024/02/22 10:15:05 [error] 5669#5669: *2829 user "testuser" was not found in "/etc/nginx/.htpasswd", client: 10.0.0.5, server: _, request: "GET /private/ HTTP/1.1", host: "example.com"' | \
		extract_hosts "was not found in .*, client: <HOST>")
	[ "$result" = "10.0.0.5" ]
}

@test "regex: nginx-http-auth - no user/password" {
	local result
	result=$(echo '2024/02/22 10:15:07 [error] 3057#0: *13 no user/password was provided for basic authentication, client: 1.2.3.4, server: domain.tld, request: "GET /protected/ HTTP/1.1", host: "domain.tld"' | \
		extract_hosts "no user/password was provided.*, client: <HOST>")
	[ "$result" = "1.2.3.4" ]
}

# --- mysqld-auth ---

@test "regex: mysqld-auth - Access denied (MySQL 5.7+)" {
	local result
	result=$(echo "2024-02-22 10:15:03 8 [Warning] Access denied for user 'root'@'192.168.1.50' (using password: YES)" | \
		extract_hosts "Access denied for user '[^']+'@'<HOST>'")
	[ "$result" = "192.168.1.50" ]
}

@test "regex: mysqld-auth - Access denied (older format)" {
	local result
	result=$(echo "130322 11:26:54 [Warning] Access denied for user 'admin'@'10.0.0.5' (using password: NO)" | \
		extract_hosts "Access denied for user '[^']+'@'<HOST>'")
	[ "$result" = "10.0.0.5" ]
}

# --- wordpress ---

@test "regex: wordpress - Authentication failure" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost wordpress(www.example.com)[1234]: Authentication failure for admin from 192.168.1.50" | \
		extract_hosts "wordpress.*Authentication failure .* from <HOST>")
	[ "$result" = "192.168.1.50" ]
}

@test "regex: wordpress - Blocked authentication" {
	local result
	result=$(echo "Feb 22 10:15:05 myhost wordpress(www.example.com)[1235]: Blocked authentication attempt for admin from 10.0.0.5" | \
		extract_hosts "wordpress.*Blocked authentication attempt .* from <HOST>")
	[ "$result" = "10.0.0.5" ]
}

@test "regex: wordpress - XML-RPC authentication" {
	local result
	result=$(echo "Feb 22 10:15:07 myhost wordpress(www.example.com)[1236]: XML-RPC authentication attempt for unknown user attacker from 203.0.113.10" | \
		extract_hosts "wordpress.*XML-RPC authentication .* from <HOST>")
	[ "$result" = "203.0.113.10" ]
}

# --- webmin ---

@test "regex: webmin - Invalid login" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost webmin[27643]: Invalid login as admin from 192.168.1.50" | \
		extract_hosts "webmin.*Invalid login as .* from <HOST>")
	[ "$result" = "192.168.1.50" ]
}

@test "regex: webmin - Non-existent login" {
	local result
	result=$(echo "Mar 15 09:22:11 myhost webmin[15673]: Non-existent login as toto from 86.0.6.217" | \
		extract_hosts "webmin.*Non-existent login as .* from <HOST>")
	[ "$result" = "86.0.6.217" ]
}

# --- directadmin ---

@test "regex: directadmin - failed login attempt" {
	local result
	result=$(echo "2014:05:08-01:40:09: '192.168.1.50' 15 failed login attempt on account 'admin'" | \
		extract_hosts "'<HOST>' [0-9]+ failed login attempt")
	[ "$result" = "192.168.1.50" ]
}

# --- cyrus-imap ---

@test "regex: cyrus-imap - badlogin SASL(-13)" {
	local result
	result=$(echo "Jan 15 10:30:22 mail cyrus/imap[7257]: badlogin: mail.example.com [192.168.1.50] plaintext admin SASL(-13): authentication failure: checkpass failed" | \
		extract_hosts "badlogin:.*\[<HOST>\].*SASL")
	[ "$result" = "192.168.1.50" ]
}

@test "regex: cyrus-imap - badlogin user not found" {
	local result
	result=$(echo "Jan 15 10:31:45 mail imap[5444]: badlogin: localhost [10.0.0.5] plaintext testuser SASL(-13): user not found: checkpass failed" | \
		extract_hosts "badlogin:.*\[<HOST>\].*SASL")
	[ "$result" = "10.0.0.5" ]
}

# --- roundcube ---

@test "regex: roundcube - Login failed (IMAP Error)" {
	local result
	result=$(echo "[22-Feb-2024 10:15:03 +0000]: IMAP Error: Login failed for user@example.com from 192.168.1.50. Could not connect to ssl://mail.example.com:993: Unknown reason" | \
		extract_hosts "Login failed for .+ from <HOST>")
	[ "$result" = "192.168.1.50" ]
}

@test "regex: roundcube - Failed login" {
	local result
	result=$(echo "[22-Feb-2024 10:15:05 +0000]: Failed login for admin@example.com from 10.0.0.5 in session abc123def" | \
		extract_hosts "Failed login for .+ from <HOST>")
	[ "$result" = "10.0.0.5" ]
}

# --- plesk ---

@test "regex: plesk - Failed login attempt" {
	local result
	result=$(echo "2024-02-22 10:15:03 ERR [panel] [Action Log] Failed login attempt with login 'admin' from IP 203.0.113.10" | \
		extract_hosts "Failed login attempt .* from IP <HOST>")
	[ "$result" = "203.0.113.10" ]
}

# --- dropbear ---

@test "regex: dropbear - Bad password attempt" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost dropbear[12345]: Bad password attempt for 'root' from 192.168.1.50:54321" | \
		extract_hosts "dropbear.*Bad password attempt .* from <HOST>")
	[ "$result" = "192.168.1.50" ]
}

@test "regex: dropbear - Login attempt nonexistent user" {
	local result
	result=$(echo "Feb 22 10:15:05 myhost dropbear[12346]: Login attempt for nonexistent user from 10.0.0.5:12345" | \
		extract_hosts "dropbear.*Login attempt for nonexistent user from <HOST>")
	[ "$result" = "10.0.0.5" ]
}

# ============================================================
# IPv6 PATTERNS — same rules, IPv6 source addresses
# ============================================================

@test "regex: sshd - Failed password (IPv6)" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost sshd[12345]: Failed password for root from 2001:db8::1 port 22 ssh2" | \
		extract_hosts "sshd.*Failed password for .* from <HOST>")
	[ "$result" = "2001:db8::1" ]
}

@test "regex: sshd - Invalid user (IPv6)" {
	local result
	result=$(echo "Feb 22 10:15:05 myhost sshd[12345]: Invalid user admin from 2607:f8b0:4004:800::200e port 54321 ssh2" | \
		extract_hosts "sshd.*Invalid user .* from <HOST>")
	[ "$result" = "2607:f8b0:4004:800::200e" ]
}

@test "regex: dovecot - pop3-login auth failed (IPv6)" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost dovecot: pop3-login: Aborted login (auth failed, 1 attempts): user=<admin>, method=PLAIN, rip=2001:db8::ff, lip=::1" | \
		extract_hosts "pop3-login.*auth failed.*rip=<HOST>")
	[ "$result" = "2001:db8::ff" ]
}

@test "regex: postfix - SASL auth failed (IPv6)" {
	local result
	result=$(echo "Feb 22 10:15:03 myhost postfix/smtpd[9876]: warning: unknown[2001:db8::abcd]: SASL LOGIN authentication failed: authentication failure" | \
		extract_hosts "\[<HOST>\].*SASL.*authentication failed")
	[ "$result" = "2001:db8::abcd" ]
}

@test "regex: nginx-http-auth - password mismatch (IPv6)" {
	local result
	result=$(echo '2024/02/22 10:15:03 [error] 5596#560: *3 user "admin": password mismatch, client: 2001:db8::50, server: example.com, request: "GET /admin HTTP/1.1", host: "example.com"' | \
		extract_hosts "password mismatch, client: <HOST>")
	[ "$result" = "2001:db8::50" ]
}
