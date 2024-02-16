echo "START BUILD.."

# APT

apt update -y
apt upgrade -y
apt install -y net-tools iproute2 iptables nano wget gnutls-bin certbot expect build-essential make pkg-config libgnutls28-dev libev-dev libpam0g-dev liblz4-dev libseccomp-dev libreadline-dev libnl-route-3-dev libkrb5-dev \
 libradcli-dev libpcl1-dev libcjose-dev libjansson-dev liboath-dev libprotobuf-c-dev libtalloc-dev libhttp-parser-dev libcurlpp-dev libssl-dev libmaxminddb-dev libbsd-dev libsystemd-dev libwrap0-dev libuid-wrapper \
 libpam-wrapper libnss-wrapper libsocket-wrapper gss-ntlmssp tcpdump protobuf-c-compiler iperf3 lcov ssl-cert libpam-oath

# START

wget -P /opt/ https://www.infradead.org/ocserv/download/ocserv-1.2.4.tar.xz
tar -xvf /opt/ocserv-1.2.4.tar.xz -C /opt/
cd /opt/ocserv-1.2.4

./configure --prefix= --enable-oidc-auth
make && make install

# cp doc/sample.config /etc/ocserv/ocserv.conf
cp doc/sample.passwd doc/sample.otp doc/profile.xml /etc/ocserv/

useradd -r -M -U -s /usr/sbin/nologin ocserv
# sed -i '747,$s/^/# /' /etc/ocserv/ocserv.conf

if grep -q "^#net.ipv4.ip_forward=1" /etc/sysctl.conf;
    then sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf;
elif ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf;
    then echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf;
fi
sysctl -p

cd /etc/ocserv/ssl/
certtool --generate-privkey --outfile ca-privkey.pem
certtool --generate-self-signed --load-privkey ca-privkey.pem --template ca.tmpl --outfile ca-cert.pem
certtool --generate-privkey --outfile server-privkey.pem
certtool --generate-certificate --load-privkey server-privkey.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-privkey.pem --template server.tmpl --outfile server-cert.pem
certtool --generate-privkey --outfile client1-privkey.pem
certtool --generate-certificate --load-privkey client1-privkey.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-privkey.pem --template client.tmpl --outfile client1-cert.pem

# bash -c 'printf "auth = \"certificate\"\ntcp-port = 443\n#udp-port = 443\nrun-as-user = ocserv\nrun-as-group = ocserv\nsocket-file = /var/run/ocserv-socket\nserver-cert = /etc/ocserv/ssl/server-cert.pem\nserver-key = /etc/ocserv/ssl/server-privkey.pem\nca-cert = /etc/ocserv/ssl/ca-cert.pem\nisolate-workers = true\nmax-clients = 1024\nmax-same-clients = 0\nrate-limit-ms = 100\nserver-stats-reset-time = 604800\nkeepalive = 32400\ndpd = 90\nmobile-dpd = 1800\nswitch-to-tcp-timeout = 25\ntry-mtu-discovery = try\ncert-user-oid = 0.9.2342.19200300.100.1.1\ntls-priorities = \"NORMAL:%%SERVER_PRECEDENCE:%%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1\"\nauth-timeout = 240\nmin-reauth-time = 300\nmax-ban-score = 80\nban-reset-time = 1200\ncookie-timeout = 300\ndeny-roaming = false\nrekey-time = 172800\nrekey-method = ssl\nuse-occtl = true\npid-file = /var/run/ocserv.pid\nlog-level = 2\ndevice = vpns\npredictable-ips = true\ndefault-domain = openozna.ru\nipv4-network = 192.168.1.0\nipv4-netmask = 255.255.255.0\ntunnel-all-dns = true\ndns = 8.8.8.8\ndns = 8.8.4.4\nping-leases = false\ncisco-client-compat = true\ndtls-legacy = true\ncisco-svc-client-compat = false\nclient-bypass-protocol = false\ncamouflage = false\ncamouflage_secret = \"mysecretkey\"\ncamouflage_realm = \"Restricted Content\"\n" > /etc/ocserv/ocserv.conf'

iptables -t nat -A POSTROUTING -o $(ip route | awk '/default/ { print $5 }') -j MASQUERADE
cd /opt/ocserv-1.2.4
cp doc/systemd/standalone/ocserv.service /lib/systemd/system/
systemctl enable ocserv.service
systemctl start ocserv
systemctl status ocserv

chmod +x /etc/init.d/ocserv
/etc/init.d/ocserv start
/etc/init.d/ocserv status
