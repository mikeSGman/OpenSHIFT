#!/usr/bin/env bash

  ##GetOpts
myDomain=$1
osType=$2
nodeType=$3
installJenkinsComponents=$4
yourRouterIP=$5

  ##MISC
url_of_the_latest_epel_release_rpm='http://epel.mirror.freedomvoice.com/6/x86_64/epel-release-6-8.noarch.rpm'
brokerIP=$(ip a | grep eth0 | gawk '{ print $2 }' | cut -d"/" -f1 | grep -v eth0)

  ###  1.1. Setup Yum repositories  ###

if [ "${osType}" = "RHEL6" ]
then
cat <<EOF> /etc/yum.repos.d/openshift-origin-deps.repo
[openshift-origin-deps]
name=openshift-origin-deps
baseurl=https://mirror.openshift.com/pub/openshift-origin/nightly/rhel-6/dependencies/x86_64/
gpgcheck=0
enabled=1
EOF
fi

if [ "${osType}" = "Fedora" ]
then
cat <<EOF> /etc/yum.repos.d/openshift-origin-deps.repo
[openshift-origin-deps]
name=openshift-origin-deps
baseurl=https://mirror.openshift.com/pub/openshift-origin/nightly/fedora-19/dependencies/x86_64/
gpgcheck=0
enabled=1
EOF
fi

if [ "${osType}" = "RHEL6" ]
then
cat <<EOF> /etc/yum.repos.d/openshift-origin.repo
[openshift-origin]
name=openshift-origin
baseurl=https://mirror.openshift.com/pub/openshift-origin/nightly/rhel-6/latest/x86_64/
gpgcheck=0
enabled=1
EOF
fi

if [ "${osType}" = "Fedora" ]
then
cat <<EOF> /etc/yum.repos.d/openshift-origin.repo
[openshift-origin]
name=openshift-origin
baseurl=https://mirror.openshift.com/pub/openshift-origin/nightly/fedora-19/latest/x86_64/
gpgcheck=0
enabled=1
EOF
fi

if [ "${osType}" = "RHEL6" ]
then
yum install -y --nogpgcheck ${url_of_the_latest_epel_release_rpm}
fi

  ###  1.2. Updates and NTP  ###

  ###  1.2.1. Update the Operating System  ###

yum clean all
yum -y update

  ###  1.2.2. Configure the Clock to Avoid Time Skew  ###

if [ "${osType}" = "RHEL6" ]
then
yum install -y ntpdate ntp
ntpdate clock.redhat.com
chkconfig ntpd on
service ntpd start
fi

if [ "${osType}" = "Fedora" ]
then
yum install -y ntpdate ntp
ntpdate clock.redhat.com
systemctl enable ntpd.service
systemctl start  ntpd.service
fi

  ###  1.2.3. Setting up the Ruby Environment  ###

if [ "${osType}" = "RHEL6" ]
then
yum install -y ruby193

cat <<'EOF' > /etc/profile.d/scl193.sh
# Setup PATH, LD_LIBRARY_PATH and MANPATH for ruby-1.9
ruby19_dir=$(dirname `scl enable ruby193 "which ruby"`)
export PATH=$ruby19_dir:$PATH

ruby19_ld_libs=$(scl enable ruby193 "printenv LD_LIBRARY_PATH")
export LD_LIBRARY_PATH=$ruby19_ld_libs:$LD_LIBRARY_PATH

ruby19_manpath=$(scl enable ruby193 "printenv MANPATH")
export MANPATH=$ruby19_manpath:$MANPATH
EOF

cp -f /etc/profile.d/scl193.sh /etc/sysconfig/mcollective
chmod 0644 /etc/profile.d/scl193.sh /etc/sysconfig/mcollective
fi

  ###  2.1. DNS  ###

  ###  2.1.1. Install the BIND DNS Server  ###

yum install -y bind bind-utils

  ###  2.1.2. Create DNS environment variables and a DNSSEC key file  ###

domain=${myDomain}
keyfile=/var/named/${domain}.key
pushd /var/named
rm K${domain}*
dnssec-keygen -a HMAC-MD5 -b 512 -n USER -r /dev/urandom ${domain}
KEY="$(grep Key: K${domain}*.private | cut -d ' ' -f 2)"
popd
rndc-confgen -a -r /dev/urandom
restorecon -v /etc/rndc.* /etc/named.*
chown -v root:named /etc/rndc.key
chmod -v 640 /etc/rndc.key

  ###  2.1.3. Create a fowarders.conf file for host name resolution  ###

echo "forwarders { 8.8.8.8; 8.8.4.4; } ;" >> /var/named/forwarders.conf
restorecon -v /var/named/forwarders.conf
chmod -v 640 /var/named/forwarders.conf

  ###  2.1.4. Configure subdomain resolution and create an initial DNS database  ###

rm -rvf /var/named/dynamic
mkdir -vp /var/named/dynamic

cat <<EOF > /var/named/dynamic/${domain}.db
\$ORIGIN .
\$TTL 1 ; 1 seconds (for testing only)
${domain}       IN SOA  ns1.${domain}. hostmaster.${domain}. (
            2011112904 ; serial
            60         ; refresh (1 minute)
            15         ; retry (15 seconds)
            1800       ; expire (30 minutes)
            10         ; minimum (10 seconds)
            )
        NS  ns1.${domain}.
        MX  10 mail.${domain}.
\$ORIGIN ${domain}.
ns1         A   127.0.0.1
EOF

cat /var/named/dynamic/${domain}.db

cat <<EOF > /var/named/${domain}.key
key ${domain} {
  algorithm HMAC-MD5;
  secret "${KEY}";
};
EOF

chown -Rv named:named /var/named
restorecon -rv /var/named

  ###  2.1.5. Create the named configuration file  ###

cat <<EOF > /etc/named.conf
// named.conf
//
// Provided by Red Hat bind package to configure the ISC BIND named(8) DNS
// server as a caching only nameserver (as a localhost DNS resolver only).
//
// See /usr/share/doc/bind*/sample/ for example named configuration files.
//

options {
    listen-on port 53 { any; };
    directory   "/var/named";
    dump-file   "/var/named/data/cache_dump.db";
        statistics-file "/var/named/data/named_stats.txt";
        memstatistics-file "/var/named/data/named_mem_stats.txt";
    allow-query     { any; };
    recursion yes;

    /* Path to ISC DLV key */
    bindkeys-file "/etc/named.iscdlv.key";

    // set forwarding to the next nearest server (from DHCP response
    forward only;
    include "forwarders.conf";
};

logging {
        channel default_debug {
                file "data/named.run";
                severity dynamic;
        };
};

// use the default rndc key
include "/etc/rndc.key";

controls {
    inet 127.0.0.1 port 953
    allow { 127.0.0.1; } keys { "rndc-key"; };
};

include "/etc/named.rfc1912.zones";

include "${domain}.key";

zone "${domain}" IN {
    type master;
    file "dynamic/${domain}.db";
    allow-update { key ${domain} ; } ;
};
EOF

chown -v root:named /etc/named.conf
restorecon /etc/named.conf

  ###  2.1.6. Configure host name resolution to use new the BIND server  ###

sed -i 's/nameserver.*/nameserver 127.0.0.1/' /etc/resolv.conf

if [ "${osType}" = "RHEL6" ]
then
lokkit --service=dns
chkconfig named on
fi

if [ "${osType}" = "Fedora" ]
then
firewall-cmd --add-service=dns
firewall-cmd --permanent --add-service=dns
systemctl enable named.service
fi

  ###  2.1.7. Start the named service  ###

if [ "${osType}" = "RHEL6" ]
then
service named start
fi

if [ "${osType}" = "Fedora" ]
then
systemctl start named.service
fi

  ###  2.2. Add the Broker Node to DNS  ###

cat <<EOF|nsupdate -k ${keyfile} 
server 127.0.0.1 
update delete broker.${myDomain} A 
update add broker.${myDomain} 180 A ${brokerIP} 
send 
EOF

  ###  2.3. DHCP Client and Hostname  ###

  ###  2.3.1. Create dhclient-eth0.conf  ###

echo -e "prepend domain=name-servers ${brokerIP};\nsupersede host-name \"broker\";\nsupersede domain-name \"${myDomain}\";" >> /etc/dhcp/dhclient-eth0.conf

  ###  2.3.2. Update network configuration  ###

echo -e "PEERDNS=\"no\"\nDNS1=\"${yourRouterIP}\"" >> /etc/sysconfig/network-scripts/ifcfg-eth0

  ###  2.3.3. Set the host name for your server  ###

if [ "${osType}" = "RHEL6" ]
then
    sed -i -e 's/^HOSTNAME=.*$/HOSTNAME=broker.${myDomain}/' /etc/sysconfig/network
fi

if [ "${osType}" = "Fedora" ]
then
    echo "broker.${myDomain}" > /etc/hostname
fi

hostname broker.${myDomain}

  ###  3.1. Install the mongod server  ###

yum install -y mongodb-server mongodb libmongodb

if [ "${osType}" = "RHEL6" ]
then
  true
fi

if [ "${osType}" = "Fedora" ]
then
  true
fi

  ###  3.2. Configure mongod  ###

  ###  3.2.1. Setup MongoDB smallfiles option  ###

#smallfiles=true ##not needed in newer versions of mongodb

  ###  3.2.2. Setup MongoDB authentication  ###

#auth=true

service mongod start

/usr/bin/mongo localhost/openshift_broker_dev --eval 'db.addUser("openshift", "password")'
/usr/bin/mongo localhost/admin --eval 'db.addUser("openshift", "password")'

service mongod stop

sed -i 's/auth=true/#auth=true/' /etc/mongodb.conf

  ###  3.3. Firewall setup  ###

#bind_ip=127.0.0.1,10.4.59.x ##Not needed unless mongod is being
                             ##served on anther box.

if [ "${osType}" = "RHEL6" ]
then
lokkit --port=27017:tcp
fi

if [ "${osType}" = "Fedora" ]
then
firewall-cmd --add-port=27017/tcp
firewall-cmd --permanent --add-port=27017/tcp
fi

  ###  3.4. Set mongod to Start on Boot  ###

if [ "${osType}" = "RHEL6" ]
then
chkconfig mongod on
fi

if [ "${osType}" = "Fedora" ]
then
systemctl enable mongod.service
fi

if [ "${osType}" = "RHEL6" ]
then
service mongod status
fi

if [ "${osType}" = "Fedora" ]
then
systemctl status mongod.service
fi

if [ "${osType}" = "RHEL6" ]
then
service mongod start
fi

if [ "${osType}" = "Fedora" ]
then
systemctl start mongod.service
fi

  ###  4.1. Installation  ###

yum install -y activemq activemq-client

  ###  4.2. Configuration  ###

cd /etc/activemq
mv activemq.xml activemq.orig

curl -o /etc/activemq/activemq.xml http://openshift.github.io/documentation/files/activemq.xml
curl -o /etc/activemq/jetty.xml http://openshift.github.io/documentation/files/jetty.xml
curl -o /etc/activemq/jetty-realm.properties http://openshift.github.io/documentation/files/jetty-realm.properties

sed -i 's/<broker xmlns="http:\/\/activemq.apache.org\/schema\/core" brokerName="activemq.example.com" dataDirectory="${activemq.data}">/<broker xmlns="http:\/\/activemq.apache.org\/schema\/core" brokerName="${HOSTNAME}" dataDirectory="${activemq.data}">/' /etc/activemq/activemq.xml
sed -i 's/brokerName="activemq.${myDomain}"/brokerName="activemq.${myDomain}"/' /etc/activemq/activemq.xml
sed -i 's/<broker xmlns="http:\/\/activemq.apache.org\/schema\/core" brokerName="<your broker name> dataDirectory="${activemq.data}">"/<broker xmlns="http:\/\/activemq.apache.org\/schema\/core" brokerName="${HOSTNAME}" dataDirectory="${activemq.data}">/' /etc/activemq/activemq.xml
sed -i 's/<authenticationUser username="admin" password="<choose a password>" groups="mcollective,admin,everyone"\/>/<authenticationUser username="admin" password="admin" groups="mcollective,admin,everyone"/' /etc/activemq/activemq.xml

  ###  4.3. Firewall Rules / Start on Boot  ###

if [ "${osType}" = "RHEL6" ]
then
lokkit --port=61613:tcp
fi

if [ "${osType}" = "Fedora" ]
then
firewall-cmd --add-port=61613/tcp
firewall-cmd --permanent --add-port=61613/tcp
fi

chkconfig activemq on
service activemq start

  ###  4.4. Tmpfs setup  ###

if [ "${osType}" = "Fedora" ]
then
cat <<EOF >/etc/tmpfiles.d/activemq.conf
d /var/run/activemq 0755 activemq activemq -
EOF
fi

  ###  4.5. Verify that ActiveMQ is Working  ###

if [ "${osType}" = "RHEL6" ]
then
lokkit --port=8161:tcp
fi

if [ "${osType}" = "Fedora" ]
then
firewall-cmd --add-port=8161/tcp
firewall-cmd --permanent --add-port=8161/tcp
fi

  ###  5.1. Installation  ###

yum install -y mcollective-client

  ###  5.2. Configuration  ###

if [ "${osType}" = "Fedora" ]
then
cat <<EOF > /etc/mcollective/client.cfg
topicprefix = /topic/
main_collective = mcollective
collectives = mcollective
libdir = /usr/libexec/mcollective
#logfile = /var/log/mcollective-client.log
loglevel = debug

# Plugins
securityprovider = psk
plugin.psk = unset

connector = activemq
plugin.activemq.pool.size = 1
plugin.activemq.pool.1.host = broker.${myDomain}
plugin.activemq.pool.1.port = 61613
plugin.activemq.pool.1.user = mcollective
plugin.activemq.pool.1.password = marionette
EOF
fi

if [ "${osType}" = "RHEL6" ]
then
cat <<EOF > /etc/mcollective/client.cfg
topicprefix = /topic/
main_collective = mcollective
collectives = mcollective
libdir =/opt/rh/ruby193/root/usr/libexec/mcollective
#logfile = /var/log/mcollective-client.log
loglevel = debug

# Plugins
securityprovider = psk
plugin.psk = unset

connector = activemq
plugin.activemq.pool.size = 1
plugin.activemq.pool.1.host = broker.${myDomain}
plugin.activemq.pool.1.port = 61613
plugin.activemq.pool.1.user = mcollective
plugin.activemq.pool.1.password = marionette
EOF
fi

  ###  6.1. Install Necessary Packages  ###

if [ "${osType}" = "RHEL6" ]
then
yum install -y openshift-origin-broker openshift-origin-broker-util \
              rubygem-openshift-origin-auth-remote-user \
              rubygem-openshift-origin-auth-mongo \
              rubygem-openshift-origin-msg-broker-mcollective \
              rubygem-openshift-origin-dns-avahi \
              rubygem-openshift-origin-dns-nsupdate \
              rubygem-openshift-origin-dns-route53 \
              ruby193-rubygem-passenger ruby193-mod_passenger
fi

if [ "${osType}" = "Fedora" ]
then
yum install -y openshift-origin-broker openshift-origin-broker-util \
              rubygem-openshift-origin-auth-remote-user \
              rubygem-openshift-origin-auth-mongo \
              rubygem-openshift-origin-msg-broker-mcollective \
              rubygem-openshift-origin-dns-avahi \
              rubygem-openshift-origin-dns-nsupdate \
              rubygem-openshift-origin-dns-route53 \
              rubygem-passenger mod_passenger
fi

  ###  6.2. Configure the Firewall and Enable Service at Boot  ###

if [ "${osType}" = "RHEL6" ]
then
chkconfig network on
chkconfig sshd on
fi

if [ "${osType}" = "Fedora" ]
then
systemctl enable network.service
systemctl enable sshd.service
fi

if [ "${osType}" = "RHEL6" ]
then
lokkit --service=ssh
lokkit --service=https
lokkit --service=http
fi

if [ "${osType}" = "Fedora" ]
then
firewall-cmd --add-service=ssh
firewall-cmd --add-service=http
firewall-cmd --add-service=https
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
fi

  ###  6.3. Generate access keys  ###

openssl genrsa -out /etc/openshift/server_priv.pem 2048
openssl rsa -in /etc/openshift/server_priv.pem -pubout > /etc/openshift/server_pub.pem
ssh-keygen -t rsa -b 2048 -f ~/.ssh/rsync_id_rsa
cp ~/.ssh/rsync_id_rsa* /etc/openshift/

  ###  6.4. Configure SELinux  ###

setsebool -P  httpd_unified=on httpd_can_network_connect=on httpd_can_network_relay=on \
              httpd_run_stickshift=on named_write_master_zones=on allow_ypbind=on \
              httpd_verify_dns=on httpd_enable_homedirs=on httpd_execmem=on

if [ "${osType}" = "RHEL6" ]
then
fixfiles -R ruby193-rubygem-passenger restore
fixfiles -R ruby193-mod_passenger restore
restorecon -rv /var/run
fi

if [ "${osType}" = "Fedora" ]
then
fixfiles -R rubygem-passenger restore
fixfiles -R mod_passenger restore
restorecon -rv /var/run
fi

  ###  6.5. Understand and Change the Broker Configuration  ###

  ###  6.5.1. Gear Sizes  ###

# Comma separated list of valid gear sizes
sed -i 's/VALID_GEAR_SIZES=/VALID_GEAR_SIZES="small,medium"/' /etc/openshift/broker.conf

  ###  6.5.2. Cloud Domain  ###

# Domain suffix to use for applications (Must match node config)
sed -i 's/CLOUD_DOMAIN=/CLOUD_DOMAIN="${myDomain}"/' /etc/openshift/broker.conf

  ###  6.5.3. MongoDB settings  ###

# Comma seperated list of replica set servers. Eg: "<host-1>:<port-1>,<host-2>:<port-2>,..."
sed -i 's/MONGO_HOST_PORT=/MONGO_HOST_PORT="${HOSTNAME}:27017/"' /etc/openshift/broker.conf

#Mongo DB user configured earlier
sed -i 's/MONGO_USER=/MONGO_USER="openshift"/' /etc/openshift/broker.conf

#Password for user configured earlier
sed -i 's/MONGO_PASSWORD=/MONGO_PASSWORD="password"/' /etc/openshift/broker.conf

#Broker metadata database
sed -i 's/MONGO_DB=/MONGO_DB="openshift_broker_dev"/' /etc/openshift/broker.conf

  ###  6.5.4. Authentication Salt  ###

AUTH_SALT_DUDE=$(openssl rand -base64 64)

sed -i 's/AUTH_SALT=/AUTH_SALT="${AUTH_SALT_DUDE}"/' /etc/openshift/broker.conf

  ###  6.5.5. Session Secret  ###

SS_SEC=$(openssl rand -base64 64)

sed -i 's/SESSION_SECRET=/SESSION_SECRET="${SS_SEC}"/' /etc/openshift/broker.conf

  ###  7.1. Create Configuration Files  ###

cp openshift-origin-auth-remote-user.conf.example /etc/openshift/plugins.d/openshift-origin-auth-remote-user.conf
cp openshift-origin-msg-broker-mcollective.conf.example /etc/openshift/plugins.d/openshift-origin-msg-broker-mcollective.conf

  ###  7.2. Configure the DNS plugin  ###

mkdir -p /etc/openshift
cd /etc/openshift/plugins.d
cat << EOF > openshift-origin-dns-nsupdate.conf
BIND_SERVER="127.0.0.1"
BIND_PORT=53
BIND_KEYNAME="${domain}"
BIND_KEYVALUE="${KEY}"
BIND_ZONE="${domain}"
EOF

  ###  7.3. Configure an Authentication Plugin  ###

cp /var/www/openshift/broker/httpd/conf.d/openshift-origin-auth-remote-user-basic.conf.sample /var/www/openshift/broker/httpd/conf.d/openshift-origin-auth-remote-user.conf

htpasswd -c /etc/openshift/htpasswd demo

  ###  7.4. Configure the Administrative Console  ###

  ###  7.4.1. Running the Admin Console  ###

if [ "${osType}" = "RHEL6" ]
then
  yum install -y rubygem-openshift-origin-admin-console
  service openshift-broker restart
fi

  ###  7.4.2. Adding to an existing deployment  ###

if [ "${osType}" = "Fedora" ]
then
  yum install -y rubygem-openshift-origin-admin-console
  cd /var/www/openshift/broker
  rm Gemfile.lock
  bundle --local
  service openshift-broker restart
fi

  ###  7.4.3. Browsing to the Admin Console  ###

cat <<EOF>/etc/httpd/conf.d/000002_openshift_origin_broker_proxy.conf
#
# This configuration is to proxy to an OpenShift broker
# (and optional developer console) running in a separate
# httpd instance.
#
# Passenger will sever connections, returning 500
# exceptions, when graceful restarting under load.

<Directory />
    Options FollowSymLinks
    AllowOverride None
</Directory>

<VirtualHost *:80>
  # ServerName we will inherit from other config;
  # ServerAlias is to make sure "localhost" traffic goes here regardless.
  ServerAlias localhost
  ServerAdmin root@localhost
  DocumentRoot /var/www/html
  RewriteEngine              On
  RewriteRule     ^/$    https://%{HTTP_HOST}/console [R,L]
  RewriteRule     ^(.*)$     https://%{HTTP_HOST}$1 [R,L]
</VirtualHost>

<VirtualHost *:443>
  # ServerName we will inherit from other config;
  # ServerAlias is to make sure "localhost" traffic goes here regardless.
  ServerAlias localhost
  ServerAdmin root@localhost
  DocumentRoot /var/www/html
  RewriteEngine              On
  RewriteRule     ^/$    https://%{HTTP_HOST}/console [R,L]
  SSLEngine on
  SSLProxyEngine on
  SSLCertificateFile /etc/pki/tls/certs/localhost.crt
  SSLCertificateKeyFile /etc/pki/tls/private/localhost.key
  RequestHeader set X_FORWARDED_PROTO 'https'
  RequestHeader set Front-End-Https "On"
  ProxyTimeout 300
  ProxyPass /console http://127.0.0.1:8118/console
  ProxyPassReverse /console http://127.0.0.1:8118/console

  ProxyPass /broker http://127.0.0.1:8080/broker
  ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>

ProxyPreserveHost On
TraceEnable off
EOF

cat <<EOF>/var/lib/openshift/.httpd.d/nodes.txt
__default__ REDIRECT:/console
__default__/console TOHTTPS:127.0.0.1:8118/console
__default__/broker TOHTTPS:127.0.0.1:8080/broker
EOF

httxt2dbm -f DB -i  -o /var/lib/openshift/.httpd.d/nodes.db

  ###  7.5. Run the Ruby Bundler  ###

if [ "${osType}" = "Fedora" ]
then
cd /var/www/openshift/broker
bundle --local
fi

  ###  7.6. Set Services to Start on Boot  ###

if [ "${osType}" = "RHEL6" ]
then
chkconfig openshift-broker on
fi

if [ "${osType}" = "Fedora" ]
then
systemctl enable openshift-broker.service
fi

if [ "${osType}" = "RHEL6" ]
then
service openshift-broker start
fi

if [ "${osType}" = "Fedora" ]
then
systemctl start openshift-broker.service
fi

  ###  7.7. Verify the Broker REST API  ###
  #### Redacted by MM on 2013/12/11 1550 EST ###

  ###  7.8. Start apache  ###

if [ "${osType}" = "RHEL6" ]
then
chkconfig httpd on
service httpd start
fi

if [ "${osType}" = "Fedora" ]
then
systemctl enable httpd.service
systemctl start httpd.service
fi

  ###  8.1. Install the Web Console RPMs  ###

yum install -y openshift-origin-console

  ###  8.2. Configure Authentication for the Console  ###

cd /var/www/openshift/console/httpd/conf.d
cp openshift-origin-auth-remote-user-basic.conf.sample openshift-origin-auth-remote-user-basic.conf

  ###  8.3. Verify the Ruby Bundler  ###

cd /var/www/openshift/console
bundle --local

  ###  8.4. Set Console to Start on Boot  ###

if [ "${osType}" = "RHEL6" ]
then
chkconfig openshift-console on
service openshift-console start
fi

if [ "${osType}" = "Fedora" ]
then
systemctl enable openshift-console.service
systemctl start openshift-console.service
fi

  ###  9.1. Register a DNS entry for the Node Host  ###

if [ "${nodeType}" = "Broker" ] || [ "${nodeType}" = "Node" ]
then
keyfile=/var/named/${myDomain}.key
nodeIP=$(ip a | grep eth0 | gawk '{ print $2 }' | cut -d"/" -f1 | grep -v eth0)
oo-register-dns -h node -d ${myDomain} -n ${nodeIP} -k ${keyfile}
fi

  ###  9.2. Configure SSH Key Authentication  ###

$ mkdir -m 0700 -p /root/.ssh

if [ "${nodeType}" = "Broker" ] || [ "${nodeType}" = "Node" ]
then
scp /etc/openshift/rsync_id_rsa.pub root@node.${myDomain}:/root/.ssh
fi

if [ "${nodeType}" = "AIO" ]
then
cp -f /etc/openshift/rsync_id_rsa.pub /root/.ssh/
fi

cat /root/.ssh/rsync_id_rsa.pub >> /root/.ssh/authorized_keys

  ###  9.3. Configure DNS Resolution on the Node  ###
  
if [ "${nodeType}" = "Broker" ] || [ "${nodeType}" = "Node" ]
then
sed -i 'i/nameserver/nameserver ${brokerIP}/' /etc/resolv.conf
fi

  ###  9.4. Configure the DHCP Client and Hostname  ###
  
if [ "${nodeType}" = "Node" ]
  then 
    echo -e "prepend domain=name-servers ${brokerIP};\nsupersede host-name \"node\";\nsupersede domain-name \"${myDomain}\";" >> /etc/dhcp/dhclient-eth0.conf
    echo -e "PEERDNS=\"no\"\nDNS1=\"${yourRouterIP}\"" >> /etc/sysconfig/network-scripts/ifcfg-eth0

    elif [ "${osType}" = "RHEL6" ]
      then
        sed -i 's/^HOSTNAME=.*$/HOSTNAME=node.${myDomain}/' /etc/sysconfig/network

    elif [ "${osType}" = "Fedora" ]
      then
        echo "node.${myDomain}" > /etc/hostname
    fi
hostname node.${myDomain}
fi

  ###  9.5. MCollective on the Node Host  ###

  ###  9.5.1. Install MCollective  ###

yum install -y openshift-origin-msg-node-mcollective

  ###  9.6. Configure MCollective  ###

if [ "${osType}" = "Fedora" ]
then
cat <<EOF >/etc/mcollective/server.cfg
topicprefix = /topic/
main_collective = mcollective
collectives = mcollective
libdir = /usr/libexec/mcollective
logfile = /var/log/mcollective.log
loglevel = debug
daemonize = 0
direct_addressing = 1
registerinterval = 30

# Plugins
securityprovider = psk
plugin.psk = unset

connector = activemq
plugin.activemq.pool.size = 1
plugin.activemq.pool.1.host = broker.${myDomain}
plugin.activemq.pool.1.port = 61613
plugin.activemq.pool.1.user = mcollective
plugin.activemq.pool.1.password = marionette

# Facts
factsource = yaml
plugin.yaml = /etc/mcollective/facts.yaml
EOF
fi

if [ "${osType}" = "RHEL6" ]
then
cat <<EOF >/etc/mcollective/server.cfg
topicprefix = /topic/
main_collective = mcollective
collectives = mcollective
libdir = /opt/rh/ruby193/root/usr/libexec/mcollective
logfile = /var/log/mcollective.log
loglevel = debug
daemonize = 1
direct_addressing = 1
registerinterval = 30

# Plugins
securityprovider = psk
plugin.psk = unset

connector = activemq
plugin.activemq.pool.size = 1
plugin.activemq.pool.1.host = broker.${myDomain}
plugin.activemq.pool.1.port = 61613
plugin.activemq.pool.1.user = mcollective
plugin.activemq.pool.1.password = marionette

# Facts
factsource = yaml
plugin.yaml = /etc/mcollective/facts.yaml
EOF
fi

if [ "${osType}" = "Fedora" ]
then
cat <<EOF > /usr/lib/systemd/system/mcollective.service
[Unit]
Description=The Marionette Collective
After=network.target

[Service]
Type=simple
StandardOutput=syslog
StandardError=syslog
ExecStart=/usr/sbin/mcollectived --config=/etc/mcollective/server.cfg --pidfile=/var/run/mcollective.pid
ExecReload=/bin/kill -USR1 $MAINPID
PIDFile=/var/run/mcollective.pid
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl --system daemon-reload

if [ "${osType}" = "RHEL6" ]
then
chkconfig mcollective on
service mcollective start
fi

if [ "${osType}" = "Fedora" ]
then
systemctl enable mcollective.service
systemctl start mcollective.service
fi

  ###  9.7. Node Host Packages  ###

  ###  9.7.1. Install the Core Packages  ###

yum install -y rubygem-openshift-origin-node \
               rubygem-passenger-native \
               openshift-origin-port-proxy \
               openshift-origin-node-util \
               rubygem-openshift-origin-container-selinux

  ###  9.7.2. Select and Install Built-In Cartridges to be Supported  ###

yum install -y openshift-origin-cartridge-cron

if [ "${installJenkinsComponents}" = "Jenkins" ]
then
curl -o /etc/yum.repos.d/jenkins.repo http://pkg.jenkins-ci.org/redhat/jenkins.repo
rpm --import http://pkg.jenkins-ci.org/redhat/jenkins-ci.org.key
yum install -y jenkins-1.510
fi

if [ "${osType}" = "Fedora" ]
then
yum install -y openshift-origin-cartridge-haproxy openshift-origin-cartridge-php openshift-origin-cartridge-mariadb
fi

if [ "${osType}" = "RHEL6" ]
then
yum install -y openshift-origin-cartridge-haproxy openshift-origin-cartridge-php openshift-origin-cartridge-mysql
fi

# yum search origin-cartridge

yum install -y openshift-origin-cartridge-\*

/usr/sbin/oo-admin-cartridge --recursive -a install -s /usr/libexec/openshift/cartridges/

  ###  9.8. Start Required Services  ###

if [ "${osType}" = "RHEL6" ]
then
lokkit --service=ssh
lokkit --service=https
lokkit --service=http
lokkit --port=8000:tcp
lokkit --port=8443:tcp
chkconfig httpd on
chkconfig network on
chkconfig sshd on
chkconfig oddjobd on
chkconfig openshift-node-web-proxy on
fi

if [ "${osType}" = "Fedora" ]
then
firewall-cmd --add-service=ssh
firewall-cmd --add-service=http
firewall-cmd --add-service=https
firewall-cmd --add-port=8000/tcp
firewall-cmd --add-service=8443/tcp
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-port=8000/tcp
firewall-cmd --permanent --add-port=8443/tcp
systemctl enable network.service
systemctl enable sshd.service
systemctl enable oddjobd.service
systemctl enable openshift-node-web-proxy.service
fi

  ###  10.1. Install augeas tools  ###

yum install -y augeas

  ###  10.2. Configure PAM Modules  ###

cat <<EOF | augtool
set /files/etc/pam.d/sshd/#comment[.='pam_selinux.so close should be the first session rule'] 'pam_openshift.so close should be the first session rule'
ins 01 before /files/etc/pam.d/sshd/*[argument='close']
set /files/etc/pam.d/sshd/01/type session
set /files/etc/pam.d/sshd/01/control required
set /files/etc/pam.d/sshd/01/module pam_openshift.so
set /files/etc/pam.d/sshd/01/argument close
set /files/etc/pam.d/sshd/01/#comment 'Managed by openshift_origin'

set /files/etc/pam.d/sshd/#comment[.='pam_selinux.so open should only be followed by sessions to be executed in the user context'] 'pam_openshift.so open should only be followed by sessions to be executed in the user context'
ins 02 before /files/etc/pam.d/sshd/*[argument='open']
set /files/etc/pam.d/sshd/02/type session
set /files/etc/pam.d/sshd/02/control required
set /files/etc/pam.d/sshd/02/module pam_openshift.so
set /files/etc/pam.d/sshd/02/argument[1] open
set /files/etc/pam.d/sshd/02/argument[2] env_params
set /files/etc/pam.d/sshd/02/#comment 'Managed by openshift_origin'

rm /files/etc/pam.d/sshd/*[module='pam_selinux.so']

set /files/etc/pam.d/sshd/03/type session
set /files/etc/pam.d/sshd/03/control required
set /files/etc/pam.d/sshd/03/module pam_namespace.so
set /files/etc/pam.d/sshd/03/argument[1] no_unmount_on_close
set /files/etc/pam.d/sshd/03/#comment 'Managed by openshift_origin'

set /files/etc/pam.d/sshd/04/type session
set /files/etc/pam.d/sshd/04/control optional
set /files/etc/pam.d/sshd/04/module pam_cgroup.so
set /files/etc/pam.d/sshd/04/#comment 'Managed by openshift_origin'

set /files/etc/pam.d/runuser/01/type session
set /files/etc/pam.d/runuser/01/control required
set /files/etc/pam.d/runuser/01/module pam_namespace.so
set /files/etc/pam.d/runuser/01/argument[1] no_unmount_on_close
set /files/etc/pam.d/runuser/01/#comment 'Managed by openshift_origin'

set /files/etc/pam.d/runuser-l/01/type session
set /files/etc/pam.d/runuser-l/01/control required
set /files/etc/pam.d/runuser-l/01/module pam_namespace.so
set /files/etc/pam.d/runuser-l/01/argument[1] no_unmount_on_close
set /files/etc/pam.d/runuser-l/01/#comment 'Managed by openshift_origin'

set /files/etc/pam.d/su/01/type session
set /files/etc/pam.d/su/01/control required
set /files/etc/pam.d/su/01/module pam_namespace.so
set /files/etc/pam.d/su/01/argument[1] no_unmount_on_close
set /files/etc/pam.d/su/01/#comment 'Managed by openshift_origin'

set /files/etc/pam.d/system-auth-ac/01/type session
set /files/etc/pam.d/system-auth-ac/01/control required
set /files/etc/pam.d/system-auth-ac/01/module pam_namespace.so
set /files/etc/pam.d/system-auth-ac/01/argument[1] no_unmount_on_close
set /files/etc/pam.d/system-auth-ac/01/#comment 'Managed by openshift_origin'
save
EOF

cat <<EOF > /etc/security/namespace.d/sandbox.conf
# /sandbox        \$HOME/.sandbox/      user:iscript=/usr/sbin/oo-namespace-init       root,adm,apache
EOF

cat <<EOF > /etc/security/namespace.d/tmp.conf
/tmp        \$HOME/.tmp/      user:iscript=/usr/sbin/oo-namespace-init root,adm,apache
EOF

cat <<EOF > /etc/security/namespace.d/vartmp.conf
/var/tmp    \$HOME/.tmp/   user:iscript=/usr/sbin/oo-namespace-init root,adm,apache
EOF

  ###  10.3. Enable Control Groups (cgroups)  ###

if [ "${osType}" = "RHEL6" ]
then
chkconfig cgconfig on
chkconfig cgred on
service cgconfig restart
service cgred restart
fi

if [ "${osType}" = "Fedora" ]
then
systemctl enable cgconfig.service
systemctl enable cgred.service
systemctl start cgconfig.service
systemctl start cgred.service
fi

  ###  10.4. Configure Disk Quotas  ###

if [ "${osType}" = "RHEL6" ]
  then
    sed -i 's/\/dev\/mapper\/VolGroup-lv_root \/                       ext4    defaults        1 1/\/dev\/mapper\/VolGroup-lv_root \/                       ext4    defaults,usrquota        1 1/' /etc/fstab
  mount -o remount /
  quotacheck -cmug /
fi

if [ "${osType}" = "Fedora" ]
  then
    sed -i 's/\/dev\/mapper\/fedora-root \/                       ext4    defaults        1 1/\/dev\/mapper\/fedora-root \/                       ext4    defaults,usrquota        1 1/' /etc/fstab
    mount -o remount /
  quotacheck -cmug /
fi

  ###  10.5. Configure SELinux and System Control Settings  ###

  ###  10.5.1. Configuring SELinux  ###

setsebool -P httpd_unified=on httpd_can_network_connect=on httpd_can_network_relay=on \
             httpd_read_user_content=on httpd_enable_homedirs=on httpd_run_stickshift=on \
             allow_polyinstantiation=on httpd_run_stickshift=on httpd_execmem=on
restorecon -rv /var/run
restorecon -rv /usr/sbin/mcollectived /var/log/mcollective.log /var/run/mcollectived.pid
restorecon -rv /var/lib/openshift /etc/openshift/node.conf /etc/httpd/conf.d/openshift

  ###  10.5.2. Configuring System Control Settings  ###

cat <<EOF | augtool
set /files/etc/sysctl.conf/kernel.sem "250  32000 32  4096"
set /files/etc/sysctl.conf/net.ipv4.ip_local_port_range "15000 35530"
set /files/etc/sysctl.conf/net.netfilter.nf_conntrack_max "1048576"
save
EOF

sysctl -p /etc/sysctl.conf

  ###  10.6. Configure SSH, OpenShift Port Proxy, and Node Configuration  ###

  ###  10.6.1. Configuring SSH to Pass Through the GIT_SSH Environment Variable  ###

cat <<EOF >> /etc/ssh/sshd_config
AcceptEnv GIT_SSH
EOF

cat <<EOF | augtool
set /files/etc/ssh/sshd_config/MaxSessions 40
save
EOF

  ###  10.7. Initialize Traffic Control  ###

if [ "${osType}" = "RHEL6" ]
then
chkconfig openshift-tc on
fi

if [ "${osType}" = "Fedora" ]
then
systemctl enable openshift-tc.service
fi

  ###  10.7.1. Configuring the Port Proxy  ###

if [ "${osType}" = "RHEL6" ]
then
lokkit --port=35531-65535:tcp
chkconfig openshift-port-proxy on
service openshift-port-proxy start
fi

if [ "${osType}" = "Fedora" ]
then
firewall-cmd --add-port=35531-65535/tcp
firewall-cmd --permanent --add-port=35531-65535/tcp
systemctl enable openshift-port-proxy.service
systemctl restart  openshift-port-proxy.service
fi

if [ "${osType}" = "RHEL6" ]
then
chkconfig openshift-gears on
fi

if [ "${osType}" = "Fedora" ]
then
systemctl enable openshift-gears.service
fi

  ###  10.7.2. Configuring Node Settings for Domain Name  ###

if [ "${nodeType}" = "Broker" ] || [ "${nodeType}" = "Node" ]
  then
    devNIC=$(ip a | cut -d " " -f2 | grep -v lo | gawk '!/^ *#/ && NF' | cut -d ":" -f1)
  sed -i 's/PUBLIC_HOSTNAME=/PUBLIC_HOSTNAME="node.${myDomain}"            # The node host\'s public hostname/' /etc/openshift/node.conf
    sed -i 's/PUBLIC_IP=/PUBLIC_IP="${nodeIP}"                         # The node host\'s public IP address/' /etc/openshift/node.conf
    sed -i 's/BROKER_HOST=/BROKER_HOST="broker.${myDomain}"              # IP or DNS name of broker host for REST API/' /etc/openshift/node.conf
    sed -i 's/EXTERNAL_ETH_DEV=/EXTERNAL_ETH_DEV="${devNIC}"        # Update to match name of external network device/' /etc/openshift/node.conf
fi

if [ "${nodeType}" = "AIO" ]
then
    devNIC=$(ip a | cut -d " " -f2 | grep -v lo | gawk '!/^ *#/ && NF' | cut -d ":" -f1)
  sed -i 's/PUBLIC_HOSTNAME=/PUBLIC_HOSTNAME="broker.${myDomain}"            # The broker host\'s public hostname/' /etc/openshift/node.conf
    sed -i 's/PUBLIC_IP=/PUBLIC_IP="${brokerIP}"                         # The broker host\'s public IP address/' /etc/openshift/node.conf
    sed -i 's/BROKER_HOST=/BROKER_HOST="broker.${myDomain}"              # IP or DNS name of broker host for REST API/' /etc/openshift/node.conf
    sed -i 's/EXTERNAL_ETH_DEV=/EXTERNAL_ETH_DEV="${devNIC}"        # Update to match name of external network device/' /etc/openshift/node.conf
fi

  ###  10.8. Update login.defs  ###

cat <<EOF | augtool
set /files/etc/login.defs/UID_MIN 500
set /files/etc/login.defs/GID_MIN 500
save
EOF

  ###  10.9. Update the facter Database  ###

/etc/cron.minutely/openshift-facts

  ###  10.10. Setup Routes for All-In-One setup  ###

cat <<EOF > /tmp/nodes.broker_routes.txt
__default__ REDIRECT:/console
__default__/console TOHTTPS:127.0.0.1:8118/console
__default__/broker TOHTTPS:127.0.0.1:8080/broker
EOF

cat /etc/httpd/conf.d/openshift/nodes.txt /tmp/nodes.broker_routes.txt > /etc/httpd/conf.d/openshift/nodes.txt.new
mv -f /etc/httpd/conf.d/openshift/nodes.txt.new /etc/httpd/conf.d/openshift/nodes.txt
httxt2dbm -f DB -i /etc/httpd/conf.d/openshift/nodes.txt -o /etc/httpd/conf.d/openshift/nodes.db.new
chown root:apache /etc/httpd/conf.d/openshift/nodes.txt /etc/httpd/conf.d/openshift/nodes.db.new
chmod 750 /etc/httpd/conf.d/openshift/nodes.txt /etc/httpd/conf.d/openshift/nodes.db.new
mv -f /etc/httpd/conf.d/openshift/nodes.db.new /etc/httpd/conf.d/openshift/nodes.db

