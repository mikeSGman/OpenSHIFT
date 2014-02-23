###
#Cool Ass Shit.  Sed rocks.
###
1 {
  i#!/usr/bin/env bash\n
  imyDomain=$1
  iosType=$2
  inodeType=$3
  iinstallJenkinsComponents=$4
  iyourRouterIP=$5
  iurl_of_the_latest_epel_release_rpm='http://epel.mirror.freedomvoice.com/6/x86_64/epel-release-6-8.noarch.rpm'\n
  itheIP=$(ip a | grep eth0 | gawk '{ print $2 }' | cut -d"\/" -f1 | grep -v eth0)
}

/<div class="listingblock">/ {

:next_line
  n
  /^<\/div>/b end_next_line

  /<div class="title">\(RHEL.\?\|Fedora\|All-In-One Setup\|Seperate Broker and Node Setup\|Jenkins\)/ {
    s/<div class="title">Fedora<\/div>/if [ "${osType}" = "Fedora" ]\nthen/
    s/<div class="title">RHEL.\?<\/div>/if [ "${osType}" = "RHEL6" ]\nthen/
    s/<div class="title">All-In-One Setup<\/div>/if [ "${nodeType}" = "AIO" ]\nthen/
    s/<div class="title">Seperate Broker and Node Setup<\/div>/if [ [ "${nodeType}" = "Broker" ] || [ "${nodeType}" = "Node" ] ]\nthen/
    s/<div class="title">Jenkins<\/div>/if [ "${installJenkinsComponents}" = "Jenkins" ]\nthen/
    p

:if_block_commands_loop
    /<\/pre>/b end_if_block_commands_loop
    N
    b if_block_commands_loop

:end_if_block_commands_loop
    /\[epel\]/b end_next_line  # Skip repo file example text
    /ping/b end_next_line
    /dig/b end_next_line
    s/^.*<pre>\(.*\)<\/pre>.*$/\1/
    s/&lt;/</g
    s/&gt;/>/g
    s/example.com/${myDomain}/g
    s/\(.*\)${\([^}]*\)-\([^}]*\)}\(.*\)/\1${\2_\3}\4/g
    s/^.*Package Name.*$/  true/
    /^$ORIGIN/b end_next_line
    p
    afi
    a
    b end_next_line
  }

  /<pre>/ {

:generic_commands_loop
    /<\/pre>/b end_generic_commands_loop
    N
    b generic_commands_loop

:end_generic_commands_loop
    /\[epel\]/b end_next_line  # Skip repo file example text
    /ping/b end_next_line
    /dig/b end_next_line
    /HOSTNAME=localhost.localdomain/b end_next_line
    s/^.*<pre>\(.*\)<\/pre>.*$/\1/
    s/&lt;/</g
    s/&gt;/>/g
    s/HOSTNAME=broker.example.com/if [ "${osType}" = "RHEL" ]\nthen\n    sed -i -e "s\/^HOSTNAME=.*\$\/HOSTNAME=broker.\${myDomain}\/"\nfi/
    s/\(echo "broker.example.com" > \/etc\/hostname\)/if [ "${osType}" = "Fedora" ]\nthen\n    \1\nfi/
    s/example.com/${myDomain}/g
    s/^.*dhclient-.*\.conf$//
    s/^prepend.*$/echo -e "prepend domain=name-servers ${theIP};\\nsupersede host-name \\\"broker\\\";\\nsupersede domain-name \\\"${myDomain}\\\";" >> \/etc\/dhcp\/dhclient-eth0.conf/
    s/^PEERDNS="no".*$/echo -e "PEERDNS=\\\"no\\\"\\nDNS1=\\\"${yourRouterIP}\\\"" >> \/etc\/sysconfig\/network-scripts\/ifcfg-eth0/
    s/\(.*\)${\([^}]*\)-\([^}]*\)}\(.*\)/\1${\2_\3}\4/g
    /^$ORIGIN/b end_next_line
    s/^nameserver 127.0.0.1$/sed -i 's\/nameserver.*\/nameserver 127.0.0.1\/' \/etc\/resolv.conf/
    s/^.*# nsupdate -k ${keyfile}.*$/cat <<EOF|nsupdate -k $\{keyfile\} \
server 127.0.0.1 \
update delete broker.${myDomain} A \
update add broker.${myDomain} 180 A ${theIP} \
send \
EOF/
    p
    a
  }

  b next_line

:end_next_line
}

/^.*<h[34].*class="anchor".*<\/a>.*<\/h[34]>.*$/ {
  s/^.*<h[34].*class="anchor".*<\/a>\(.*\)<\/h[34]>.*$/  ###  \1  ###/
  p
  a
}
