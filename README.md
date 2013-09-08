# ucs-domjoin

Simple script for making arbitrary Linux systems part of a UCS domain.  A lot of
the code was taken from the manufacturer's description at
http://wiki.univention.de/index.php?title=Ubuntu.

## Usage

* Prerequisite: Univention Corporate Server installation
  (http://www.univention.de/ |
  http://wiki.univention.de/index.php?title=UCS_Quickstart)
* Configure DNS on your client properly, e.g. point to your UCS Master as DNS
  server.  This command must print the domain name of your UCS master:

	host -t SRV _domaincontroller_master._tcp

* Download the ucs-domjoin script

	wget -O ucs-domjoin https://raw.github.com/jceb/ucs-domjoin/master/ucs-domjoin
	chmod a+x ucs-domjoin

* Run the script with root privileges

	sudo ./ucs-domjoin

## Features

* Automatic detection of the UCS Master / Domain Controller (requires a proper
  DNS configuration of the client)
* Dependency check of requirements
* Automatic creation of a LDAP computer object containing hostname, MAC
  addresses of all interfaces and operating system release details
* Automatic configuration of Debian-based systems
* Automatic Kerberos integration

## Known Issues

* Non-Debian-based systems can't be configured completely by this script.
  PAM and nsswitch.conf need manual configuration that can be quite tricky and
  requires lots of skill.
* SSH password for root needs to be entered multiple times
* No support for pam_ccreds and nss_ldap (sssd is used instead)
* No plug-in system for supporting arbitrary Linux distributions
* No error handling for LDAP errors, e.g. computer objects already exists
* IP addresses, DNS name and DHCP entries are not automatically created during
  domain join
* Only ntpdate is supported for setting the time
* Only wget is supported for downloading the UCS CA
