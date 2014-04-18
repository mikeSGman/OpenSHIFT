#!/usr/bin/env python

##########################################################################
## Copyright Michael McConachie, 2013
##           Patrick Head, 2013
##
## This program is free software; you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published by the
## Free Software Foundation; either version 2, or (at your option) any
## later version.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; see the file COPYING. If not, write to the
## Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
##
##########################################################################

import os
import sys
import commands

def usage():
  print "**************************************************************"
  print "          Sorry, but I need four arguments to run."
  print ""
  print "Usage:"
  print ""
  print "  $0 <fqdn> <nightly|stable> <aio|broker|node>"
  print ""
  print "**************************************************************"

if len(sys.argv) != 4:
  usage()
  sys.exit(1)

fqdn = sys.argv[1]
version2install = sys.argv[2]
nodeType = sys.argv[3]
hostName = fqdn.split(".")[0]
domainName = fqdn.split(".")[1:]
domainName = ".".join(domainName)
router = '192.168.1.1'
intf_ip = None
intf_data = commands.getoutput("ip address").split()
idx = intf_data.index('inet') + 1
while idx:
  if intf_data[idx].split('/')[0] != "127.0.0.1":
    intf_ip = intf_data[idx].split('/')[0]
    break
  idx = intf_data.index('inet', idx) + 1
if not intf_ip:
  print "No valid IP address found, bailing out!"
  sys.exit(1)

def greeter():
  print ""
  print "*********************************************"
  print "*     Welcome to Mike's OSO installer       *"
  print "*********************************************"
  print ""
  print "This script will sanitize your environment"
  print "based on the OS type, and the build type."
  print ""
  print "It's intended to serve as a wrapper to the puppet"
  print "pieces which will then build an OSO {0} {1}".format(version2install, nodeType)
  print "leveraging the publicly maintained Puppet Repos"
  print "at the same time."
  print ""
  print "*********************************************"
  print ""

greeter ()

def confirm():
  print ""
  print "Please type 'Y/y' or 'Yes/yes' to continue:",
  response = raw_input()
  response = response.lower()
  if (response == "y") or (response == "yes"):
    return True
  return False

def setHostName():
  global distro
  with open("/etc/redhat-release", "r") as f:
    distro = f.readline()
  if distro.find("Fedora") >= 0:
    with open("/etc/hostname", "w") as f:
      f.write(fqdn + "\n")
  elif distro.find("Red Hat")  >= 0 or distro.find("CentOS") >= 0:
    with open("/etc/sysconfig/network", "w") as f:
      f.write("NETWORKING=yes\n")
      f.write("HOSTNAME=" + fqdn + "\n")

if not confirm():
  print "exiting now ..."
  sys.exit(1)

def yumStuff():
  os.system("yum -y install bind puppet facter tar httpd-tools wget git unzip mlocate; yum -y update")

def puppetStuff():
  if not os.path.exists("/etc/puppet/modules"):
    os.makedirs("/etc/puppet/modules")
  os.system("/sbin/restorecon -Rv /etc/puppet")
  os.system("/usr/bin/puppet module install openshift/openshift_origin")
  #os.system("git clone https://github.com/openshift/puppet-openshift_origin.git /etc/puppet/modules/openshift_origin")

def buildEPELrepoIfNeeded():
  if distro.find("Red Hat") >= 0 or distro.find("CentOS") >= 0:
    os.system("yum -y localinstall http://epel.mirror.freedomvoice.com/6/x86_64/epel-release-6-8.noarch.rpm")

    fo = open("/tmp/epel.repo", "w")
    for line in open("/etc/yum.repos.d/epel.repo", "r"):
      fo.write(line)
      if line.startswith('failover'):
        fo.write("exclude=*passenger* nodejs*\n")
    fo.close()

    os.rename("/tmp/epel.repo", "/etc/yum.repos.d/epel.repo")

def doDNSstuff():
  global puppetTSIGKey
  if (nodeType == "broker") or (nodeType == "aio"):
    with os.popen("/usr/sbin/dnssec-keygen -a HMAC-MD5 -b 512 -n USER -r /dev/urandom -K /var/named " + domainName) as p:
      keyFileForDnsSec = p.read().rstrip()
    with open("/var/named/" + keyFileForDnsSec + ".key") as f:
      line = f.readline().rstrip()
    puppetTSIGKey = line.split(" ")[7]

def createPPM():
  if (nodeType == "broker"):
    with open(os.environ['HOME'] + "/configure_origin.pp" ,"w") as f:
      f.write("class { 'openshift_origin' :\n")
      f.write("  roles     => ['broker','named','activemq','datastore'],\n")
      f.write("  bind_key  => '" + puppetTSIGKey + "',\n")
      f.write("  domain    => '" + domainName + "',\n")
      f.write("  register_host_with_named  => true,\n")
      f.write("  conf_named_upstream_dns   => ['" + router + "'],\n")
      f.write("  broker_hostname     => '" + fqdn + "',\n")
      f.write("  named_hostname      => '" + fqdn + "',\n")
      f.write("  datastore_hostname  => '" + fqdn + "',\n")
      f.write("  activemq_hostname   => '" + fqdn + "',\n")
      f.write("  broker_auth_plugin  => 'htpasswd',\n")
      f.write("  openshift_user1     => 'openshift',\n")
      f.write("  openshift_password1 => 'password',\n")
      f.write("  development_mode    => true,\n")
      f.write("  }\n")
  elif (nodeType == "node"):
    with open(os.environ['HOME'] + "/configure_origin.pp" ,"w") as f:
      f.write("class { 'openshift_origin' :\n")
      f.write("  roles     => ['datastore'],\n")
      f.write("  named_ip_addr       => '" + intf_ip +" ',\n")
      f.write("  bind_key            => '" + brokerDnsSecKey + "',\n")
      f.write("  domain              => '" + domainName + "',\n")
      f.write("  register_host_with_named    => true,\n")
      f.write("  broker_hostname     => '" + fqdn + "',\n")
      f.write("  activemq_hostname   => '" + fqdn + "',\n")
      f.write("  node_hostname       => '" + fqdn + "',\n")
      f.write("  install_method      => 'yum',\n")
      f.write("  jenkins_repo_base   => 'http://pkg.jenkins-ci.org/redhat',\n")
      f.write("  development_mode    => true,\n")
      f.write("  #conf_node_external_eth_dev   => 'eth0',\n")
  elif (nodeType == "aio"):
    with open(os.environ['HOME'] + "/configure_origin.pp" ,"w") as f:
      f.write("class { 'openshift_origin' :\n")
      f.write("  roles      => ['broker','named','activemq','datastore','node'],\n")
      f.write("  broker_hostname            => '" + fqdn + "',\n")
      f.write("  node_hostname              => '" + fqdn + "',\n")
      f.write("  named_hostname             => '" + fqdn + "',\n")
      f.write("  datastore_hostname         => '" + fqdn + "',\n")
      f.write("  activemq_hostname          => '" + fqdn + "',\n")
      f.write("  bind_key                   => '" + puppetTSIGKey + "',\n")
      f.write("  domain                     => '" + domainName + "',\n")
      f.write("  register_host_with_named   => true,\n")
      f.write("  conf_named_upstream_dns    => ['192.168.1.1'],\n")
      f.write("  broker_auth_plugin         => 'htpasswd',\n")
      f.write("  openshift_user1            => 'openshift',\n")
      f.write("  openshift_password1        => 'password',\n")
      f.write("  install_method             => 'yum',\n")
      f.write("  jenkins_repo_base          => 'http://pkg.jenkins-ci.org/redhat',\n")
      f.write("  development_mode           => true,\n")
      f.write("  }\n")

def oo_repos():
  with open("/etc/yum.repos.d/openshift.repo" ,"w") as f:
    f.write("[Openshift_Origin_2.0]\n")
    f.write("name=OSO Repo\n")
    if distro.find("Fedora") >= 0 and (version2install == "stable"):
      f.write("baseurl=https://mirror.openshift.com/pub/origin-server/release/2/fedora-19/packages/x86_64/\n")
    elif distro.find("Red Hat") >= 0 or distro.find("CentOS") >= 0 and (version2install == "stable"): 
      f.write("baseurl=https://mirror.openshift.com/pub/origin-server/release/2/rhel-6/packages/x86_64/\n")
    elif distro.find("Fedora") >= 0 and (version2install == "nightly"):
      f.write("baseurl=https://mirror.openshift.com/pub/origin-server/nightly/fedora-latest/latest/x86_64/\n")
    elif distro.find("Red Hat") >= 0 or distro.find("CentOS") >= 0 and (version2install == "nightly"):
      f.write("baseurl=https://mirror.openshift.com/pub/origin-server/nightly/rhel-6/latest/x86_64/\n")
    f.write("enabled=1\n")
    f.write("gpgcheck=0\n")
  with open("/etc/yum.repos.d/openshift-deps.repo" ,"w") as f:
    f.write("[Openshift_Origin_Deps]\n")
    f.write("name=OSO Deps\n")
    if distro.find("Fedora") >= 0 and (version2install == "stable"):
      f.write("baseurl=https://mirror.openshift.com/pub/origin-server/release/2/fedora-19/dependencies/x86_64/\n")
    elif distro.find("Red Hat")  >= 0 or distro.find("CentOS") >= 0 and (version2install == "stable"):
      f.write("baseurl=https://mirror.openshift.com/pub/origin-server/release/2/rhel-6/dependencies/x86_64/\n")
    elif distro.find("Fedora") >= 0 and (version2install == "nightly"):
      f.write("baseurl=https://mirror.openshift.com/pub/origin-server/nightly/fedora-latest/dependencies/x86_64/\n")
    elif distro.find("Red Hat")  >= 0 or distro.find("CentOS") >= 0 and (version2install == "nightly"):
      f.write("baseurl=https://mirror.openshift.com/pub/origin-server/nightly/rhel-6/dependencies/x86_64/\n")
    f.write("enabled=1\n")
    f.write("gpgcheck=0\n")

setHostName()
oo_repos()
yumStuff()
puppetStuff()
buildEPELrepoIfNeeded()
doDNSstuff()
createPPM()

sys.exit(0)
