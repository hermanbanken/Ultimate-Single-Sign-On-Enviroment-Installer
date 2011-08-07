#!/usr/bin/env python

import sys, os, re, socket, shutil, base64
import getpass, tempfile, uuid

sys.path.append(os.path.join(sys.path[0], "lib"))
import pexpect

from subprocess import Popen, PIPE, STDOUT

class PasswordMismatch(Exception):pass
class InvalidDN(Exception):pass
class SubprocessError(Exception):pass
class LDAPAuthError(Exception):pass

def execute_and_wait(cmd, showcmd=True):
    process = Popen(cmd, stdout=PIPE, stderr=STDOUT, shell=True)
    stdout , _ = process.communicate()

    if process.returncode:
        if showcmd:
            raise SubprocessError("There was an error executing '%s'   Output: \n\n %s" % (cmd, stdout))
        else:
            raise SubprocessError("There was an error executing the command.   Output: \n\n %s" % stdout)
    return stdout.strip()

database = """
dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib/ldap
olcModuleLoad: {0}back_hdb

# Create directory database
dn: olcDatabase={1}hdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcHdbConfig
olcDatabase: {1}hdb
olcDbDirectory: /var/lib/ldap
olcSuffix: %(dn)s
olcRootDN: cn=%(user)s,%(dn)s
olcRootPW: %(slappasswd)s
olcAccess: {0}to attrs=userPassword,shadowLastChange by dn="cn=%(user)s,%(dn)s" write by dn="%(rootdn)s" write by anonymous auth by self write by * none
olcAccess: {1}to dn.base="" by * read
olcLastMod: TRUE
olcDbCheckpoint: 512 30
olcDbConfig: {0}set_cachesize 0 2097152 0
olcDbConfig: {1}set_lk_max_objects 1500
olcDbConfig: {2}set_lk_max_locks 1500
olcDbConfig: {3}set_lk_max_lockers 1500
olcDbIndex: uid,gidNumber,sambasid,uidNumber pres,eq
olcDbIndex: cn,sn,mail,givenName,memberUid pres,eq,approx,sub
olcDbIndex: objectClass eq
olcDbIndex: apple-group-realname,apple-realname pres,eq,approx,sub
olcDbIndex: apple-generateduid,apple-group-memberguid,apple-ownerguid pres,eq

dn: cn=config
changetype: modify

dn: olcDatabase={-1}frontend,cn=config
changetype: modify
delete: olcAccess

dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootDN
olcRootDN: cn=%(user)s,cn=config

dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootPW
olcRootPW: %(slappasswd)s

"""

dit = """
dn: %(dn)s
objectClass: dcObject
objectclass: organization
o: %(hostname)s
dc: %(shorthostname)s
description: Tree root

dn: cn=%(user)s,%(dn)s
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: %(user)s
userPassword: %(slappasswd)s
description: LDAP administrator

# Populating
dn: ou=users,%(dn)s
ou: users
objectClass: organizationalUnit
objectClass: top

dn: ou=groups,%(dn)s
ou: groups
objectClass: organizationalUnit
objectClass: top

dn: ou=mounts,%(dn)s
ou: mounts
objectClass: organizationalUnit
objectClass: top


#Adding user
dn: %(rootdn)s
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
objectClass: organizationalPerson
uid: %(user)s
sn: Administrator
givenName: Directory
cn: Directory Administrator
uidNumber: 1000
gidNumber: 80
userPassword: %(slappasswd)s
loginShell: /bin/bash
homeDirectory: /home/%(user)s
title: System Administrator

#Adding Admin group
dn: cn=admin,ou=groups,%(dn)s
cn: admin
gidNumber: 80
objectClass: top
objectClass: posixGroup
memberUid: %(user)s
"""

mac = """# mac osx adjustments to group
dn: cn=admin,ou=groups,%(dn)s
changetype: modify
add: objectClass
objectClass: apple-group
objectClass: extensibleObject

dn: cn=admin,ou=groups,%(dn)s
changetype: modify
add: apple-group-realname
apple-group-realname: Open Directory Administrators

dn: cn=admin,ou=groups,%(dn)s
changetype: modify
add: apple-generateduid
apple-generateduid: %(uuid1)s

dn: cn=admin,ou=groups,%(dn)s
changetype: modify
add: apple-group-memberguid
apple-group-memberguid: %(uuid2)s

# mac osx adjustments to root user
dn: %(rootdn)s
changetype: modify
add: objectClass
objectClass: apple-user
objectClass: extensibleObject
objectClass: person
objectClass: top

# ADD ROOT USER TO admin group?

dn: %(rootdn)s
changetype: modify
add: apple-generateduid
apple-generateduid: %(uuid2)s

dn: %(rootdn)s
changetype: modify
add: authAuthority
authAuthority: ;basic;

# mac osx placeholders
dn: ou=macosx,%(dn)s
ou: macosx
objectClass: organizationalUnit
description: Holds metadata for OSX server

dn: cn=accesscontrols,ou=macosx,%(dn)s
cn: accesscontrols
objectClass: container

dn: cn=certificateauthorities,ou=macosx,%(dn)s
cn: certificateauthorities
objectClass: container

dn: cn=computers,ou=macosx,%(dn)s
cn: computers
objectClass: container

dn: cn=computer_groups,ou=macosx,%(dn)s
cn: computer_groups
objectClass: container

dn: cn=computer_lists,ou=macosx,%(dn)s
cn: computer_lists
objectClass: container

dn: cn=config,ou=macosx,%(dn)s
cn: config
objectClass: container

dn: cn=locations,ou=macosx,%(dn)s
cn: locations
objectClass: container

dn: cn=machines,ou=macosx,%(dn)s
cn: machines
objectClass: container

dn: cn=neighborhoods,ou=macosx,%(dn)s
cn: neighborhoods
objectClass: container

dn: cn=people,ou=macosx,%(dn)s
cn: people
objectClass: container

dn: cn=presets_computer_lists,ou=macosx,%(dn)s
cn: presets_computer_lists
objectClass: container

dn: cn=presets_groups,ou=macosx,%(dn)s
cn: presets_groups
objectClass: container

dn: cn=preset_users,ou=macosx,%(dn)s
cn: preset_users
objectClass: container

dn: cn=printers,ou=macosx,%(dn)s
cn: printers
objectClass: container

dn: cn=augments,ou=macosx,%(dn)s
cn: augments
objectClass: container

dn: cn=autoserversetup,ou=macosx,%(dn)s
cn: autoserversetup
objectClass: container

dn: cn=filemakerservers,ou=macosx,%(dn)s
cn: filemakerservers
objectClass: container

dn: cn=resources,ou=macosx,%(dn)s
cn: resources
objectClass: container

dn: cn=places,ou=macosx,%(dn)s
cn: places
objectClass: container

dn: cn=maps,ou=macosx,%(dn)s
cn: mapsts_computers,ou=macosx,%(dn)s
cn: presets_computers
objectClass: container

dn: cn=presets_computer_groups,ou=macosx,%(dn)s
cn: presets_computer_groups
objectClass: container

dn: cn=automountMap,ou=macosx,%(dn)s
cn: automountMap
objectClass: container

dn: ou=macosxodconfig,cn=config,ou=macosx,%(dn)s
ou: macosxodconfig
objectClass: organizationalUnit
description:: %(macod_config)s

dn: cn=presets_computers,ou=macosx,%(dn)s
cn: presets_computers
objectClass: container

dn: cn=CIFSServer,cn=config,ou=macosx,%(dn)s
cn: CIFSServer
objectClass: apple-configuration
objectClass: top

dn: cn=mcx_cache,cn=config,ou=macosx,%(dn)s
cn: mcx_cache
objectClass: apple-configuration
objectClass: top

dn: cn=ldapreplicas,cn=config,ou=macosx,%(dn)s
cn: ldapreplicas
objectClass: apple-configuration
objectClass: top

dn: cn=passwordserver,cn=config,ou=macosx,%(dn)s
cn: passwordserver
objectClass: apple-configuration
objectClass: top

dn: cn=macosxodpolicy,cn=config,ou=macosx,%(dn)s
cn: macosxodpolicy
objectClass: apple-configuration
objectClass: top

dn: cn=CollabServices,cn=config,ou=macosx,%(dn)s
cn: CollabServices
objectClass: apple-configuration
objectClass: top
"""



if __name__ == "__main__":
    user = raw_input("LDAP Admin Username:")
    passwd = getpass.getpass("LDAP Admin Password:")
    passwd2 = getpass.getpass("Confirm:")
    if passwd != passwd2:
        raise PasswordMismatch("Your passwords do not match!")

    dn = raw_input("Please enter your directory's root (e.g. dc=example,dc=com):\n\ndn: ")
    dn_regex = re.compile(r'^(dc=[a-zA-Z]+,)+(dc=[a-zA-Z]+)$')
    if not re.match(dn_regex, dn):
        raise InvalidDN("That doesn't follow the correct syntax!")

    workgroup = raw_input("Please enter the Windows workgroup name (alphanumeric, 15 chars max): ")
    workgroup_regex = re.compile(r'^[a-zA-Z0-9]+$')
    if not re.match(workgroup_regex, workgroup) or len(workgroup) > 15:
        raise InvalidWorkgroupName("'%s' is an invalid name.  It must be at most 15 chars and only use alphanumeric characters.")
    workgroup = workgroup.upper()

    print """
*************************
*** Base DN: %s ***
*** Root DN: cn=%s,%s ***
*** Root PW: @@@@@@@@@@@@ ***
*** Workgroup: %s ***
*************************
""" % (dn, user, dn, workgroup)

    ok = raw_input("Are you sure? ")
    if not ok[0] in ('Y', 'y'):
        print "Exiting"
        sys.exit(0)

    tempdir = tempfile.mkdtemp(prefix="LDAPTEMP_", dir=sys.path[0])

    rootdn = "uid=%s,ou=users,%s"% (user, dn)
    uuid1 = uuid.uuid1()
    uuid2 = uuid.uuid1()
    macod_path = os.path.abspath(os.path.join(sys.path[0], "etc", "macodconfig.xml"))


    dn_split = re.compile(r'dc=([a-zA-Z]+)+,?')
    dn_parts = dn_split.findall(dn)

    # variables in this section are not named properly
    fqdn = socket.getfqdn()
    ip = socket.gethostbyname(fqdn)
    hostname = fqdn.split(".")[0]

    print "\nSetting up /etc/hosts",
    fh = open("/etc/hosts", 'r+')
    data = ""
    for line in fh:
        line = line.strip()
        if ip in line:
            data += "%s\t%s\t%s\n" % (ip, hostname + "." + ".".join(dn_parts), hostname)
        else:
            data += line + "\n"
    fh.seek(0)
    fh.write(data)
    fh.close()

    hostname = socket.getfqdn()
    shorthostname = hostname.split(".")[1]
    print "Done"

    print "Getting updates...",
    output = execute_and_wait("/usr/bin/apt-get update")
    print "Done"

    print "Installing LDAP...",
    output = execute_and_wait("apt-get install -y --force-yes slapd ldap-utils")
    print "Done"

    print "Getting slapppasswd...",
    slappasswd = execute_and_wait("slappasswd -s %s" % passwd, showcmd=False)
    print "Done"

    print "Adding schemas..."

    for schema in ("cosine.ldif", "inetorgperson.ldif", "nis.ldif", "misc.ldif", "samba.ldif", "apple.ldif"):
        print "%s..." % schema,
        try:
            output = execute_and_wait("ldapadd -Y EXTERNAL -H ldapi:/// -f \"%s\"" % os.path.abspath(os.path.join(sys.path[0], "schema", schema)))
        except SubprocessError, e:
            if "Duplicate attribute" in str(e):
                print "Schema %s has already been added" % schema,
            else:
                raise
        print "Done"

    print "Writing configuration to temp directory...",
    database_path = os.path.join(tempdir, "database.ldif")
    fi = open(database_path, 'w')
    fi.write(database % locals())
    fi.close()
    print "wrote %s.  Done" % database_path
    print "Adding configuration to LDAP...",
    output = execute_and_wait("ldapadd -Y EXTERNAL -H ldapi:/// -f \"%s\"" % database_path)
    print "Done"

    print "Writing basic structure to temp directory...",
    dit_path = os.path.join(tempdir, "dit.ldif")
    fi = open(dit_path, 'w')
    fi.write(dit % locals())
    fi.close()
    print "wrote %s. Done" % dit_path

    print "Adding basic structure to LDAP tree...",
    output = execute_and_wait("ldapadd -x -D \"cn=%s,%s\" -H ldapi:/// -f \"%s\" -w \"%s\"" % (user, dn, dit_path, passwd), showcmd=False)
    print "Done"

    print "Base64 encoding macodconfig.xml...",
    fh = open(os.path.abspath(os.path.join(sys.path[0], "etc", "macodconfig.xml")), 'r')
    macod_config = base64.b64encode(fh.read() % locals())
    fh.close()
    print "Done"

    print "Writing Mac OSX config to temp directory...",
    mac_path = os.path.join(tempdir, "mac.ldif")
    fi = open(mac_path, 'w')
    fi.write(mac % locals())
    fi.close()
    print "wrote %s. Done" % mac_path

    print "Adding Mac OSX config to LDAP tree...",
    output = execute_and_wait("ldapadd -x -D \"cn=%s,%s\" -H ldapi:/// -f \"%s\" -w \"%s\"" % (user, dn, mac_path, passwd), showcmd=False)
    print "Done"

    print "Installing phpldapadmin...",
    output = execute_and_wait("apt-get install -y --force-yes phpldapadmin")
    print "Done"

    print "Configuring phpldapadmin..."
    fh = open("/etc/phpldapadmin/config.php", 'r+')
    data = fh.read()

    config_replace = (("$servers->setValue('server','base',array('dc=example,dc=com'));", "$servers->setValue('server','base',array('%s'));" % dn),
            ("$servers->setValue('login','bind_id','cn=admin,dc=example,dc=com');", "$servers->setValue('login','bind_id','cn=%s,%s');" % (user, dn))
            )

    for replace in config_replace:
        data = data.replace(*replace)
    fh.seek(0)
    fh.write(data)
    fh.close()
    print "Done.\tYou can access phpldapadmin from: http://%s/phpldapadmin" % hostname

    etc_dir = os.path.abspath(os.path.join(sys.path[0], "etc"))
    bin_dir = os.path.abspath(os.path.join(sys.path[0], "bin"))

    print "Setting up Samba...\n"
    output = execute_and_wait("apt-get install -y --force-yes samba libpam-smbpass smbldap-tools")
    shutil.move("/etc/samba/smb.conf", "/etc/samba/smb.conf.bak")
    shutil.copy(os.path.join(etc_dir, "smb.conf"), "/etc/samba/smb.conf")

    fh = open("/etc/samba/smb.conf", 'r+')
    data = fh.read()

    config_replace = (
            ("workgroup = EXAMPLE", "workgroup = %s" % workgroup),
            ("netbios name = LDAPTEST", "netbios name = %s" % hostname.upper()),
            ("ldap suffix = dc=example,dc=com", "ldap suffix = %s" % dn),
            ("ldap admin dn = cn=diradmin,dc=example,dc=com", "ldap admin dn = cn=%s,%s" % (user, dn)),
            )
    for replace in config_replace:
        data = data.replace(*replace)
    fh.seek(0)
    fh.write(data)
    fh.close()
    os.chmod("/etc/samba/smb.conf", 0755)

    child = pexpect.spawn("smbpasswd -W")
    child.expect("New SMB password:")
    child.sendline(passwd)
    child.expect("Retype new SMB password:")
    child.sendline(passwd)

    execute_and_wait("service smbd restart")

    print "Setting up smbldap-tools...\n"
    shutil.copy(os.path.join(etc_dir, "smbldap_bind.conf"), "/etc/smbldap-tools/smbldap_bind.conf")
    shutil.copy(os.path.join(etc_dir, "smbldap.conf"), "/etc/smbldap-tools/smbldap.conf")
    for f in [g for g in os.listdir(bin_dir) if g.startswith("smbldap")]:
        p = os.path.join(bin_dir, f)
        shutil.move(os.path.join("/usr/sbin", f), os.path.join("/usr/sbin", os.path.splitext(f)[0] + ".bak"))
        shutil.copy(p, os.path.join("/usr/sbin", f))

    sid = execute_and_wait("/usr/bin/net getlocalsid").split(":")[-1].strip()

    fh = open("/etc/smbldap-tools/smbldap.conf", 'r+')
    data = fh.read()

    config_replace = (
            ('SID="S-1-5-21-2252255531-4061614174-2474224977"', 'SID="%s"' % sid),
            ('sambaDomain="DOMSMB"', 'sambaDomain="%s"' % workgroup),
            ('suffix="dc=iallanis,dc=info"', 'suffix="%s"' % dn),
            ('usersdn="ou=Users,${suffix}"', 'usersdn="ou=users,${suffix}"'),
            ('groupsdn="ou=Groups,${suffix}"','groupsdn="ou=groups,${suffix}"'),
            )
    for replace in config_replace:
        data = data.replace(*replace)

    fh.seek(0)
    fh.write(data)
    fh.close()
    os.chmod("/etc/smbldap-tools/smbldap.conf", 0644)

    fh = open("/etc/smbldap-tools/smbldap_bind.conf", 'r+')
    data = fh.read()

    config_replace = (
            ('slaveDN="cn=Manager,dc=iallanis,dc=info"', 'slaveDN="cn=%s,%s"' % (user, dn)),
            ('slavePw="secret"', 'slavePw="%s"' % passwd),
            ('masterDN="cn=Manager,dc=iallanis,dc=info"', 'masterDN="cn=%s,%s"' % (user,dn)),
            ('masterPw="secret"', 'masterPw="%s"' % passwd),
            )
    for replace in config_replace:
        data = data.replace(*replace)

    fh.seek(0)
    fh.write(data)
    fh.close()
    os.chmod("/etc/smbldap-tools/smbldap_bind.conf", 0600)

    child = pexpect.spawn("/usr/sbin/smbldap-populate")
    child.expect('New password:')
    child.sendline(passwd)
    child.expect('Retype new password:')
    child.sendline(passwd)

    print "Setting up local LDAP authentication...\n\n"

    print "Installing LDAP auth client",
    output = execute_and_wait("DEBIAN_FRONTEND='noninteractive' apt-get install -y --force-yes ldap-auth-client")
    print "Done"

    print "Writing ldap.secret file...",
    secret_file = "/etc/ldap.secret"
    fh = open(secret_file, 'w')
    fh.write(passwd)
    fh.close()
    os.chmod(secret_file, 0600)
    print "Done"

    ldap_conf = "/etc/ldap.conf"
    print "Modifying %s..." % ldap_conf,
    fh = open(ldap_conf, 'r+')
    data = fh.read()

    config_replace = (("base dc=example,dc=net", "base %s" % dn),
                      ("uri ldapi:///","uri ldap://127.0.0.1/"),
                      ("rootbinddn cn=manager,dc=example,dc=net","rootbinddn cn=%s,%s" % (user, dn)),
                      ("#bind_policy hard","bind_policy soft")
                      )
    for replace in config_replace:
        data = data.replace(*replace)

    fh.seek(0)
    fh.write(data)
    fh.close()
    print "Done"

    print "Copying pam profile into place...",
    profile_path = "/etc/auth-client-config/profile.d/open_ldap"
    shutil.copy(os.path.abspath(os.path.join(sys.path[0],"etc", "open_ldap")), profile_path)
    os.chmod(profile_path, 0600)
    print "Done"

    print "Activating the open_ldap pam profile",
    output = execute_and_wait("auth-client-config -a -p open_ldap")
    try:
        assert user in execute_and_wait("getent passwd")
    except AssertionError:
        raise LDAPAuthError("Couldn't find the root user: '%s'" % user)
    print "Done"
    print
    print "LDAP authentication installed. Done"

    



