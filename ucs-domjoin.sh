#!/bin/sh
# ucs-domjoin.sh
#  Make Linux systems part of a UCS domain (inspired by http://wiki.univention.de/index.php?title=Ubuntu)
#
# Depends: dig, wget
#
# Copyright (C) 2012,2013 Jan Christoph Ebersbach
#
# http://www.e-jc.de/ | https://github.com/jceb/ucs-domjoin
#
# All rights reserved.
#
# The source code of this program is made available
# under the terms of the GNU Affero General Public License version 3
# (GNU AGPL V3) as published by the Free Software Foundation.
#
# Binary versions of this program provided by Univention to you as
# well as other copyrighted, protected or trademarked materials like
# Logos, graphics, fonts, specific documentations and configurations,
# cryptographic keys etc. are subject to a license agreement between
# you and Univention and not subject to the GNU AGPL V3.
#
# In the case you use this program under the terms of the GNU AGPL V3,
# the program is provided in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License with the Debian GNU/Linux or Univention distribution in file
# /usr/share/common-licenses/AGPL-3; if not, see
# <http://www.gnu.org/licenses/>.
#
# vi: ft=sh:tw=80:sw=4:ts=4:fdm=marker

set -u
set -e

query () { # Currently not in use {{{1
	local text allowempty result
	text="$1"           # text displayed to the user, e.g. a question/decision
	default="$2"        # default result in case the user didn't type anything
	forcenonempty="$3"  # if empty the user is queried again

	while true; do
		echo -n "${text} "
		# read result
		if [[ -n "${default}" ]] && [[ -z "${result}" ]]; then
			result="${default}"
		fi
		if [[ -n "${forcenonempty}" ]] && [[ -z "${result}" ]]; then
			echo "Please specify a non-empty value." 1>&2
			continue
		fi
		echo "$result"
		break
	done
	return 0
} # }}}1

log () { # {{{1
	echo -e "INFO: $@"
} # }}}1

warn () { # {{{1
	echo -e "WARNING: $@"
} # }}}1

error () { # {{{1
	echo -e "ERROR: $@" 1>&2
	exit 1
} # }}}1

testcmd () { # {{{1
	which "$1" &>/dev/null || error "Command or package is missing: $1"
} # }}}1

findmaster () { # {{{1
	local master
	set +e
	master=$(dig -t SRV _domaincontroller_master._tcp +short +search | awk '{print $4}')
	set -e
	if [ $? -ne 0 ]; then
		error "ERROR: Unable to find UCS Master"
	fi
	echo "${master}"
} # }}}1

# Test dependencies {{{1
testcmd ldapsearch
testcmd sssd
testcmd dig
testcmd wget
testcmd ssh
testcmd ntpdate
testcmd kinit
testcmd lsb_release
if lsb_release -is | grep -q 'buntu' ; then
	testcmd auth-client-config
	testcmd pam-auth-update
fi
# }}}1

# start domain join {{{1
echo
echo "Starting to join a UCS domain!"
echo

umask 022

if [ "$(whoami)" != 'root' ]; then
	error "root privileges are required to perform a domain join.  Use sudo or su to execute this script."
fi

log "Looking for UCS Master (DNS service record _domaincontroller_master._tcp)"
MASTER="$(findmaster)"
MASTER_IP="$(dig -t A "${MASTER}" +short)"
log "Found UCS Master: $MASTER ($MASTER_IP)"

# }}}1

log "Preparing configuration at /etc/univention" # {{{1
mkdir -p /etc/univention

log "Retrieving UCR configuration from root@${MASTER}" # {{{2
ssh root@${MASTER} ucr shell | grep -v ^hostname= >/etc/univention/ucr_master
. /etc/univention/ucr_master
# }}}2

log "Adding ${ldap_master} to /etc/hosts" # {{{2
grep -q "${ldap_master}" /etc/hosts || echo "${MASTER_IP} ${ldap_master}" >> /etc/hosts
# }}}2

log "Retrieving SSL CA, storing it at /etc/univention/ssl/ucsCA/CAcert.pem" {{{2
mkdir -p /etc/univention/ssl/ucsCA/
wget --quiet --no-check-certificate -O /etc/univention/ssl/ucsCA/CAcert.pem http://${ldap_master}/ucs-root-ca.crt
chmod a+r /etc/univention/ssl/ucsCA/CAcert.pem
# }}}2
# }}}1

log "Creating account for this computer" # {{{1
password="$(< /dev/urandom tr -dc A-Za-z0-9_ | head -c20)"
ldap_position="cn=computers,${ldap_base}"
hostname="$(hostname)"
dn="cn=${hostname},${ldap_position}"

mac_addresses=
for interface in /sys/class/net/*; do
	[ "$(basename ${interface})" == 'lo' ] && continue
	mac_addresses="${mac_addresses} --set mac=$(cat ${interface}/address)"
done

# TODO add IP addresses and register a DNS entry for this client as well
#ip_addresses=
if [ "$version_version" = 3.0 ] && [ "$version_patchlevel" -lt 2 ]; then
	type="computers/managedclient"
	ssh root@${ldap_master} udm "${type}" create --position "${ldap_position}" \
		--set name="${hostname}" --set password="${password}" $mac_addresses \
		--set description="$(lsb_release -d)"
else
	if lsb_release -is | grep -q 'buntu' ; then
		type="computers/ubuntu"
	else
		type="computers/linux"
	fi
	ssh root@${ldap_master} udm "${type}" create --position "${ldap_position}" \
		--set name="${hostname}" --set password="${password}" \
		--set description="$(lsb_release -d)" \
		--set operatingSystem="$(lsb_release -is)" \
		--set operatingSystemVersion="$(lsb_release -rs)" $mac_addresses
fi
touch /etc/ldap.secret
chmod 640 /etc/ldap.secret
echo "${password}" > /etc/ldap.secret
# }}}1

log "Creating LDAP configuration" # {{{1
# openldap_dir=/etc/ldap # TODO autodetect configuration directory
openldap_dir=/etc/openldap
mkdir -p "${openldap_dir}"

# Create ldap.conf
cat > ${openldap_dir}/ldap.conf <<__EOF__
TLS_CACERT /etc/univention/ssl/ucsCA/CAcert.pem
TLS_REQCERT hard
URI ldap://$ldap_master:7389
BASE $ldap_base
__EOF__
# }}}1

# log "Creating nss_ldap configuration" # {{{1
#cat >/etc/ldap.conf <<__EOF__
#uri ldap://$ldap_master:7389
#rootbinddn ${dn}
#
#base ${ldap_base}
#ldap_version 3
#scope sub
#ssl start_tls
#tls_checkpeer yes
#nss_initgroups_ignoreusers root
#__EOF__

# Activate ldap in nsswitch
#auth-client-config -t nss -p lac_ldap
# }}}1

log "Creating sssd configuration" # {{{1
mkdir -p /etc/sssd
touch /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
cat > /etc/sssd/sssd.conf <<__EOF__
[sssd]
config_file_version = 2
reconnection_retries = 3
sbus_timeout = 30
services = nss, pam, sudo
domains = $kerberos_realm

[nss]
reconnection_retries = 3

[pam]
reconnection_retries = 3

[domain/$kerberos_realm]
auth_provider = krb5
krb5_kdcip = ${MASTER_IP}
krb5_realm = ${kerberos_realm}
krb5_server = ${ldap_master}
krb5_kpasswd = ${ldap_master}
id_provider = ldap
ldap_uri = ldap://${ldap_master}:7389
ldap_search_base = ${ldap_base}
ldap_tls_reqcert = never
ldap_tls_cacert = /etc/univention/ssl/ucsCA/CAcert.pem
cache_credentials = true
enumerate = true
ldap_default_bind_dn = ${dn}
ldap_default_authtok_type = password
ldap_default_authtok = $(cat /etc/ldap.secret)
__EOF__
# }}}1

log "Configuring nsswitch.conf and pam" {{{1
if [ -d /etc/auth-client-config/profile.d ]; then
	log "Creating sss auth-client-config profile" # {{{2
	cat > /etc/auth-client-config/profile.d/sss <<__EOF__
[sss]
nss_passwd=     passwd:         compat sss
nss_group=      group:          compat sss
nss_shadow=     shadow:         compat
nss_netgroup=   netgroup:       nis

pam_auth=       auth    [success=3 default=ignore]      pam_unix.so nullok_secure try_first_pass
                auth    requisite                       pam_succeed_if.so uid >= 500 quiet
                auth    [success=1 default=ignore]      pam_sss.so use_first_pass
                auth    requisite                       pam_deny.so
                auth    required                        pam_permit.so

pam_account=    account required                                        pam_unix.so
                account sufficient                                      pam_localuser.so
                account sufficient                                      pam_succeed_if.so uid < 500 quiet
                account [default=bad success=ok user_unknown=ignore]    pam_sss.so
                account required                                        pam_permit.so

pam_password=   password        sufficient      pam_unix.so obscure sha512
                password        sufficient      pam_sss.so use_authtok
                password        required        pam_deny.so

pam_session=    session required                        pam_mkhomedir.so skel=/etc/skel/ umask=0077
                session optional                        pam_keyinit.so revoke
                session required                        pam_limits.so
                session [success=1 default=ignore]      pam_sss.so
                session required                        pam_unix.so
__EOF__
	auth-client-config -n -a -p sss
	service sssd start
	# }}}2

	log "Creating mkhomedir configuration" # {{{2
	cat >/usr/share/pam-configs/ucs_mkhomedir <<__EOF__
Name: activate mkhomedir
Default: yes
Priority: 900
Session-Type: Additional
Session:
        required                        pam_mkhomedir.so umask=0022 skel=/etc/skel
__EOF__

	DEBIAN_FRONTEND=noninteractive pam-auth-update
	# }}}2

	log "Creating security group configuration" # {{{2
	echo '*;*;*;Al0000-2400;audio,cdrom,dialout,floppy,plugdev,adm,games' >>/etc/security/group.conf

	cat >>/usr/share/pam-configs/local_groups <<__EOF__
Name: activate /etc/security/group.conf
Default: yes
Priority: 900
Auth-Type: Primary
Auth:
        required                        pam_group.so use_first_pass
__EOF__
	DEBIAN_FRONTEND=noninteractive pam-auth-update
	# }}}2
else
	warn "Autoconfiguration not supported.  Please configure /etc/nsswitch.conf and /etc/pam.d/ manually!  Examples are provided in this script."
fi
# }}}1

log "Creating kerberos configuration" # {{{1
cat >/etc/krb5.conf <<__EOF__
[libdefaults]
    default_realm = $kerberos_realm
    kdc_timesync = 1
    ccache_type = 4
    forwardable = true
    proxiable = true

[realms]
$kerberos_realm = {
   kdc = $ldap_master
   admin_server = $ldap_master
}
__EOF__
# }}}1

log "Disabling avahi-daemon" # {{{1
if type service; then
	service avahi-daemon stop
	sed -i 's|start on (|start on (never and |' /etc/init/avahi-daemon.conf
else
	warn "Please disable avahi-daemon for compatibility reasons manually."
fi
# }}}1

log "Synchronize time with the UCS master" # {{{1
ntpdate $ldap_master
# }}}1

# TODO es können sowohl ccreds als auch sssd verwendet werden, in beiden fällen müssen pakete aus aur installiert werden
# sssd ist vermutlich die bessere variante
# # Install packages
# DEBIAN_FRONTEND=noninteractive apt-get install nss-updatedb libnss-db libpam-ccreds
# 
# # Dump the LDAP data
# nss_updatedb ldap
# 
# # Call it every day
# cat >/etc/cron.daily/upd-local-nss-db <<__EOF__
# #!/bin/sh
# `which nss_updatedb` ldap
# __EOF__
# chmod +x /etc/cron.daily/upd-local-nss-db
# 
# # Added NOTFOUND case for ldap in nsswitch.conf
# sed -i 's|^passwd: .*|passwd: files ldap [NOTFOUND=return] db|; s|^group: .*|group: files ldap [NOTFOUND=return] db|' /etc/nsswitch.conf
# 
# # Skip pam_ldap if user_unknown or authinfo_unavail as well
# sed -i 's/^\(account.*\[success=\)\(.\)\(.*pam_ldap.so\)/\1\2 user_unknown=\2 authinfo_unavail=\2 \3/' /etc/pam.d/common-account

