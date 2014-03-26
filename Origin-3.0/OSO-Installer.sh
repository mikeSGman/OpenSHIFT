#!/usr/bin/env bash

clear

if [ $# -ne 4 ]; then
  echo "**************************************************************"
  echo "          Sorry, but I need four arguments to run."
  echo "" 
  echo "  Usage:"
  echo "" 
  echo "  $0 <hostname> <domain> <nightly|stable> <aio|broker|node>"
  echo "" 
  echo "**************************************************************"
  exit 1
fi

hostName=$1
domainName=$2
version2install=$3
nodeType=$4
fqdn=${hostName}.${domainName}
router='192.168.1.1'

confirm1 (){
  echo ""
  echo "Please type 'Y/y' or 'Yes/yes' to continue."
  echo ""
  read -r -p "${1:-[Y/n]} " response
  case $response in
    [yY][eE][sS]|[yY]) ;;
    *) echo ""; exit 1 ;;
  esac
}

buildCorrectRepo(){
if [ ${version2install} = 'nightly' ] && [ "$(grep -i fedora /etc/redhat-release)" ]; then
  cat <<EOF>/etc/yum.repos.d/openshift-origin-latest-2.0.repo
[Mike-OSO-2.0-Latest]
name=OSO 2.0 Latest Repo
baseurl=https://mirror.openshift.com/pub/origin-server/nightly/fedora-latest/latest/x86_64/
enabled=1
gpgcheck=0
EOF
  cat <<EOF>/etc/yum.repos.d/openshift-origin-latest-2.0-deps.repo
[Mike-OSO-2.0-Latest-Deps]
name=OSO 2.0 Stable Repo
baseurl=https://mirror.openshift.com/pub/origin-server/nightly/fedora-latest/dependencies/x86_64/
enabled=1
gpgcheck=0
EOF
  elif [ ${version2install} = 'stable' ] && [ "$(grep -i fedora /etc/redhat-release)" ]; then
    cat <<EOF>/etc/yum.repos.d/openshift-origin-sr-2.0.repo
[Mike-OSO-2.0-Stable]
name=OSO 2.0 Stable Repo
baseurl=https://mirror.openshift.com/pub/origin-server/release/2/fedora-19/packages/x86_64
enabled=1
gpgcheck=0
EOF
    cat <<EOF>/etc/yum.repos.d/openshift-origin-sr-2.0-deps.repo
[Mike-OSO-2.0-Stable-Deps]
name=OSO 2.0 Stable Repo
baseurl=https://mirror.openshift.com/pub/origin-server/release/2/fedora-19/dependencies/x86_64/
enabled=1
gpgcheck=0
EOF
  elif [ ${version2install} = 'nightly' ] && [ "$(grep -i "Red Hat Enterprise Linux" /etc/redhat-release)" ] || [ "$(grep -i "CentOS" /etc/redhat-release)" ]; then
    cat <<EOF>/etc/yum.repos.d/openshift-origin-latest-2.0.repo
[Mike-OSO-2.0-Latest]
name=OSO 2.0 Latest Repo
baseurl=https://mirror.openshift.com/pub/origin-server/nightly/rhel-6/latest/x86_64/
enabled=1
gpgcheck=0
exclude=*mcollective* activemq
EOF
    cat <<EOF>/etc/yum.repos.d/openshift-origin-latest-2.0-deps.repo
[Mike-OSO-2.0-Latest-Deps]
name=OSO Latest 2.0 Dependencies Repo
baseurl=https://mirror.openshift.com/pub/origin-server/nightly/rhel-6/dependencies/x86_64/
enabled=1
gpgcheck=0
exclude=*mcollective* activemq
EOF
  elif [ ${version2install} = 'stable' ] && [ "$(grep -i "Red Hat Enterprise Linux" /etc/redhat-release)" ] || [ "$(grep -i "CentOS" /etc/redhat-release)" ]; then
    cat <<EOF>/etc/yum.repos.d/openshift-origin-sr-2.0-nightly.repo
[Mike-OSO-2.0-Stable]
name=OSO Stable-Release 2.0 Repo
baseurl=https://mirror.openshift.com/pub/origin-server/release/2/rhel-6/packages/x86_64/
enabled=1
gpgcheck=0
exclude=*mcollective* activemq
EOF
    cat <<EOF>/etc/yum.repos.d/openshift-origin-sr-2.0-deps.repo
[Mike-OSO-2.0-Stable-Deps]
name=OSO Stable-Release 2.0 Dependencies Repo
baseurl=https://mirror.openshift.com/pub/origin-server/release/2/rhel-6/dependencies/x86_64/
enabled=1
gpgcheck=0
exclude=*mcollective* activemq
EOF

fi

restorecon -Rv /etc/yum.repos.d/
}

buildEPELrepoIfNeeded(){
  if [ "$(grep -i "Red Hat Enterprise Linux" /etc/redhat-release)" ] || [ "$(grep -i "CentOS" /etc/redhat-release)" ]; then
    yum -y localinstall http://mirror.steadfast.net/epel/6/x86_64/epel-release-6-8.noarch.rpm
  fi
}

sethostname(){
if [ "$(grep -i "Fedora" /etc/redhat-release)" ]; then
  cat <<EOF>/etc/hostname
${fqdn}
EOF

elif [ "$(grep -i "Red Hat Enterprise Linux" /etc/redhat-release)" ] || [ "$(grep -i "CentOS" /etc/redhat-release)" ]; then
  cat <<EOF>/etc/sysconfig/network
NETWORKING=yes
HOSTNAME=${fqdn}
EOF
fi

$(hostname "${fqdn}")
}

yumStuff(){
  yum -y install bind puppet facter tar httpd-tools wget unzip mlocate; yum -y update  
}

puppetStuff(){
  if [ ! -d /etc/puppet/modules ]; then
		mkdir -p /etc/puppet/modules
		restorecon -Rv /etc/puppet
	fi
puppet module install openshift/openshift_origin
}

doDNSstuff(){
  if [ ${nodeType} = 'broker' -o 'aio' ]; then
    /usr/sbin/dnssec-keygen -a HMAC-MD5 -b 512 -n USER -r /dev/urandom -K /var/named ${domainName}
    puppetTSIGKey=$(cat /var/named/K${domainName}.*.key  | awk '{print $8}')
  elif [ ${nodeType} = 'node' ]; then
    read -r -p "Please paste the broker's TSIG key here: " brokerDnsSecKey
  fi
}

createPPM(){
  if [ ${nodeType} = 'broker' ]; then
    cat <<EOF>~/configure_origin.pp
class { 'openshift_origin' :
  roles     => ['broker','named','activemq','datastore'],
  bind_key  => '${puppetTSIGKey}',
  domain    => '${domainName}',
  register_host_with_named  => true,
  conf_named_upstream_dns   => ['${router}'],
  broker_hostname     => '${fqdn}',
  named_hostname		  => '${fqdn}',
  datastore_hostname  => '${fqdn}',
  activemq_hostname		=> '${fqdn}',
  broker_auth_plugin  => 'htpasswd',
  openshift_user1     => 'openshift',
  openshift_password1 => 'password',
  development_mode    => true,
  }
EOF

  elif [ ${nodeType} = 'node' ]; then
    cat <<EOF>~/configure_origin.pp
class { 'openshift_origin' :
  roles               => ['node'],
  named_ip_addr       => '192.168.1.113',
  bind_key            => '${brokerDnsSecKey}',
  domain              => '${domainName}',
  register_host_with_named    => true,
  broker_hostname     => '${fqdn}',
  activemq_hostname   => '${fqdn}',
  node_hostname       => '${fqdn}',
  install_method      => 'yum',
  jenkins_repo_base   => 'http://pkg.jenkins-ci.org/redhat',
  development_mode    => true,
  #conf_node_external_eth_dev   => 'eth0',
  }
EOF

  elif [ ${nodeType} = 'aio' ]; then
		cat <<EOF>~/configure_origin.pp
class { 'openshift_origin' :
  roles      => ['broker','named','activemq','datastore','node'],
  broker_hostname            => '${fqdn}',
  node_hostname              => '${fqdn}',
  named_hostname             => '${fqdn}',
  datastore_hostname         => '${fqdn}',
  activemq_hostname          => '${fqdn}',
  bind_key                   => '${puppetTSIGKey}',
  domain                     => '${domainName}',
  register_host_with_named   => true,
  conf_named_upstream_dns    => ['192.168.1.1'],
  broker_auth_plugin         => 'htpasswd',
  openshift_user1            => 'openshift',
  openshift_password1        => 'password',
  install_method             => 'yum',
  jenkins_repo_base          => 'http://pkg.jenkins-ci.org/redhat',
  development_mode           => true,
  }
EOF

fi
}

puppetApply(){
  puppet apply --verbose ~/configure_origin.pp
}

echo "*********************************************"
echo "*     Welcome to Mike's OSO installer       *"
echo "*********************************************"
echo ""
echo "This script will sanitize your environment"
echo "based on the OS type and the build type."
echo "It's intended to serve as a wrapper, which"
echo "will then build an OSO ${version2install} ${nodeType} box"
echo "leveraging the publicly maintained Puppet"
echo "Repos at the same time."
echo ""
echo "*********************************************"

confirm1
buildCorrectRepo
sethostname
yumStuff
buildEPELrepoIfNeeded
puppetStuff
doDNSstuff
createPPM

confirm2(){
  echo ""
  echo "The installer is ready to work!"
  echo ""
  echo "To Recap:"
  echo ""
  echo "You're about to build a ${version2install} box."
  echo ""
  echo "It will be be assigned the FQDN: ${fqdn}."
  echo ""
  echo "Please type 'Y','y', 'Yes' or 'yes' and press <enter> to continue."
  echo ""
  read -r -p "${1:-[Y/n]} " response
  case $response in
    [yY][eE][sS]|[yY]) ;;
    *) echo ""; exit 1 ;;
  esac
}

confirm2
puppetApply

exit 0
