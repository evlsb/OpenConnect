apt update -y
apt upgrade -y
apt install -y net-tools iproute2 iptables nano wget gnutls-bin certbot expect build-essential make pkg-config libgnutls28-dev libev-dev libpam0g-dev liblz4-dev libseccomp-dev libreadline-dev libnl-route-3-dev libkrb5-dev libradcli-dev libpcl1-dev libcjose-dev libjansson-dev liboath-dev libprotobuf-c-dev libtalloc-dev libhttp-parser-dev libcurlpp-dev libssl-dev libmaxminddb-dev libbsd-dev libsystemd-dev libwrap0-dev libuid-wrapper libpam-wrapper libnss-wrapper libsocket-wrapper gss-ntlmssp tcpdump protobuf-c-compiler iperf3 lcov ssl-cert libpam-oath
# configure: WARNING:
# ***
# *** serv
# *** 

# Scanning linux images...
#
# Running kernel seems to be up-to-date.
#
# Restarting services...
# Daemons using outdated libraries
# --------------------------------
#
#   1. systemd-journald.service  3. systemd-manager           5. systemd-resolved.service   7. user@1000.service
#   2. systemd-logind.service    4. systemd-networkd.service  6. systemd-timesyncd.service  8. none of the above
#
# (Enter the items or ranges you want to select, separated by spaces.)
#
# Which services should be restarted?  

wget -P /opt/ https://www.infradead.org/ocserv/download/ocserv-1.2.4.tar.xz
tar -xvf /opt/ocserv-1.2.4.tar.xz -C /opt/
cd /opt/ocserv-1.2.4

./configure --prefix= --enable-oidc-auth
make && make install

mkdir -p /etc/ocserv/
cp doc/sample.config /etc/ocserv/ocserv.conf
cp doc/sample.passwd doc/sample.otp doc/profile.xml /etc/ocserv/

useradd -r -M -U -s /usr/sbin/nologin ocserv
sed -i '747,$s/^/# /' /etc/ocserv/ocserv.conf

if grep -q "^#net.ipv4.ip_forward=1" /etc/sysctl.conf;
    then sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf;
elif ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf;
    then echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf;
fi

sysctl -p
mkdir /etc/ocserv/ssl/
cd /etc/ocserv/ssl/

printf "organization = \"Org\"\ncn = \"CA\"\nserial = 001\nexpiration_days = -1\nca\nsigning_key\ncert_signing_key\ncrl_signing_key\n" > /etc/ocserv/ssl/ca.tmpl
printf "organization = \"Server Org\"\ncn = \"server\"\nserial = 002\nexpiration_days = 3650\nca\nsigning_key\nencryption_key\ntls_www_server\nip_address = \"5.101.44.90\"\n" > /etc/ocserv/ssl/server.tmpl
printf "organization = \"Server Org\"\ncn = \"client1\"\nserial = 100\nexpiration_days = 3650\nca\nsigning_key\nencryption_key\ntls_www_client\nuid = \"client1\"\n" > /etc/ocserv/ssl/client.tmpl

certtool --generate-privkey --outfile ca-privkey.pem
certtool --generate-self-signed --load-privkey ca-privkey.pem --template ca.tmpl --outfile ca-cert.pem
certtool --generate-privkey --outfile server-privkey.pem
certtool --generate-certificate --load-privkey server-privkey.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-privkey.pem --template server.tmpl --outfile server-cert.pem
certtool --generate-privkey --outfile client1-privkey.pem
certtool --generate-certificate --load-privkey client1-privkey.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-privkey.pem --template client.tmpl --outfile client1-cert.pem

bash -c 'printf "auth = \"certificate\"\ntcp-port = 443\n#udp-port = 443\nrun-as-user = ocserv\nrun-as-group = ocserv\nsocket-file = /var/run/ocserv-socket\nserver-cert = /etc/ocserv/ssl/server-cert.pem\nserver-key = /etc/ocserv/ssl/server-privkey.pem\nca-cert = /etc/ocserv/ssl/ca-cert.pem\nisolate-workers = true\nmax-clients = 1024\nmax-same-clients = 0\nrate-limit-ms = 100\nserver-stats-reset-time = 604800\nkeepalive = 32400\ndpd = 90\nmobile-dpd = 1800\nswitch-to-tcp-timeout = 25\ntry-mtu-discovery = try\ncert-user-oid = 0.9.2342.19200300.100.1.1\ntls-priorities = \"NORMAL:%%SERVER_PRECEDENCE:%%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1\"\nauth-timeout = 240\nmin-reauth-time = 300\nmax-ban-score = 80\nban-reset-time = 1200\ncookie-timeout = 300\ndeny-roaming = false\nrekey-time = 172800\nrekey-method = ssl\nuse-occtl = true\npid-file = /var/run/ocserv.pid\nlog-level = 2\ndevice = vpns\npredictable-ips = true\ndefault-domain = openozna.ru\nipv4-network = 192.168.1.0\nipv4-netmask = 255.255.255.0\ntunnel-all-dns = true\ndns = 8.8.8.8\ndns = 8.8.4.4\nping-leases = false\ncisco-client-compat = true\ndtls-legacy = true\ncisco-svc-client-compat = false\nclient-bypass-protocol = false\ncamouflage = false\ncamouflage_secret = \"mysecretkey\"\ncamouflage_realm = \"Restricted Content\"\n" > /etc/ocserv/ocserv.conf'

iptables -t nat -A POSTROUTING -o $(ip route | awk '/default/ { print $5 }') -j MASQUERADE && 
cd /opt/ocserv-1.2.4 && 
cp doc/systemd/standalone/ocserv.service /lib/systemd/system/ && 
systemctl enable ocserv.service && 
systemctl start ocserv && 
systemctl status ocserv


cat << EOF > /etc/init.d/ocserv
#! /bin/sh
### BEGIN INIT INFO
# Provides:             ocserv
# Required-Start:       $remote_fs $syslog dbus
# Required-Stop:        $remote_fs $syslog dbus
# Default-Start:        2 3 4 5
# Default-Stop:         0 1 6
# Short-Description:    OpenConnect SSL VPN server
# Description:          secure, small, fast and configurable OpenConnect SSL VPN server
### END INIT INFO
set -e

NAME=ocserv
DESC="OpenConnect SSL VPN server"

DAEMON=/usr/sbin/ocserv
DAEMON_CONFIG=/etc/${NAME}/${NAME}.conf
DAEMON_PIDFILE=/run/${NAME}.pid
DAEMON_ARGS="--pid-file $DAEMON_PIDFILE --config $DAEMON_CONFIG"

test -x $DAEMON || exit 0

umask 022

. /lib/lsb/init-functions

export PATH="${PATH:+$PATH:}/usr/sbin:/sbin"

daemon_start()
{
    if [ ! -s "$DAEMON_CONFIG" ]; then
        log_failure_msg "please create ${DAEMON_CONFIG}, not starting..."
        log_end_msg 1
        exit 0
    fi
    log_daemon_msg "Starting $DESC" "$NAME" || true
    if start-stop-daemon --start --quiet --oknodo --pidfile $DAEMON_PIDFILE --exec $DAEMON -- $DAEMON_ARGS ; then
        log_end_msg 0 || true
    else
        log_end_msg 1 || true
    fi
}

case "$1" in
  start)
    daemon_start
    ;;
  stop)
    log_daemon_msg "Stopping $DESC" "$NAME" || true
    if start-stop-daemon --stop --quiet --oknodo --pidfile $DAEMON_PIDFILE; then
            log_end_msg 0 || true
        else
            log_end_msg 1 || true
        fi
        ;;

  reload|force-reload)
        log_daemon_msg "Reloading $DESC" "$NAME" || true
        if start-stop-daemon --stop --signal 1 --quiet --oknodo --pidfile $DAEMON_PIDFILE --exec $DAEMON; then
            log_end_msg 0 || true
        else
            log_end_msg 1 || true
        fi
        ;;

  restart)
        log_daemon_msg "Restarting $DESC" "$NAME" || true
        start-stop-daemon --stop --quiet --oknodo --retry 30 --pidfile $DAEMON_PIDFILE
        daemon_start
        ;;

  try-restart)
        log_daemon_msg "Restarting $DESC" "$NAME" || true
        RET=0
        start-stop-daemon --stop --quiet --retry 30 --pidfile $DAEMON_PIDFILE || RET="$?"
        case $RET in
            0)
                # old daemon stopped
                daemon_start
                ;;
            1)
                # daemon not running
                log_progress_msg "(not running)" || true
                log_end_msg 0 || true
                ;;
            *)
                # failed to stop
                log_progress_msg "(failed to stop)" || true
                log_end_msg 1 || true
                ;;
        esac
        ;;

  status)
        status_of_proc -p $DAEMON_PIDFILE $DAEMON $NAME && exit 0 || exit $?
        ;;

  *)
        log_action_msg "Usage: /etc/init.d/$NAME {start|stop|reload|force-reload|restart|try-restart|status}" || true
        exit 1
esac

exit 0
EOF

chmod +x /etc/init.d/ocserv && 
/etc/init.d/ocserv start && 
/etc/init.d/ocserv status