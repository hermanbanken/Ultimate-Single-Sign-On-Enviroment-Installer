#!/usr/bin/env python

import sys, os, re, socket
import getpass, tempfile
import uuid, base64

from subprocess import Popen, PIPE, STDOUT

class PasswordMismatch(Exception):pass
class InvalidDN(Exception):pass
class SubprocessError(Exception):pass

def execute_and_wait(cmd, showcmd=True):
    process = Popen(cmd, stdout=PIPE, stderr=STDOUT, shell=True)
    stdout, _ = process.communicate()

    if process.returncode:
        if showcmd:
            raise SubprocessError("There was an error executing '%s'   Output: \n\n %s" % (cmd, stdout))
        else:
            raise SubprocessError("There was an error executing the command.   Output: \n\n %s" % (cmd, stdout))
    return stdout

database = """dn: cn=module{0},cn=config
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
olcAccess: {2}to * by dn="cn=%(user)s,%(dn)s" write by dn="%(rootdn)s" write by * read
olcAccess: {3}to * by dn="%(rootdn)s" write by * read
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

dit = """dn: %(dn)s
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

#Adding Admin group
dn: cn=admin,ou=groups,%(dn)s
cn: admin
gidNumber: 80
objectClass: top
objectClass: posixGroup
memberUid: %(user)s


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
userPassword: $passwd
loginShell: /bin/bash
homeDirectory: /home/%(user)s
title: System Administrator
"""

mac = """ 
# mac osx adjustments to group
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
apple-generateduid: %(admingrp)s

dn: cn=admin,ou=groups,%(dn)s
changetype: modify
add: apple-group-memberguid
apple-group-memberguid: %(rootuuid)s

# mac osx adjustments to root user
dn: %(rootdn)s
changetype: modify
add: objectClass
objectClass: apple-user
objectClass: extensibleObject
objectClass: person
objectClass: top

dn: %(rootdn)s
changetype: modify
add: apple-generateduid
apple-generateduid: %(rootuuid)s

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
cn: maps
objectClass: container

dn: cn=automountMap,ou=macosx,%(dn)s
cn: automountMap
objectClass: container

dn: ou=macosxodconfig,cn=config,ou=macosx,%(dn)s
ou: macosxodconfig
objectClass: organizationalUnit
description:: %(encoded_template)s

dn: cn=presets_computers,ou=macosx,%(dn)s
cn: presets_computers
objectClass: container

dn: cn=presets_computer_groups,ou=macosx,%(dn)s
cn: presets_computer_groups
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
        raise PasswordMismatch("Your passwords do notmatch!")

    dn = raw_input("Please enter your directory's root (e.g. dc=example,dc=com):\n\ndn: ")
    dn_regex = re.compile(r'^(dc=[a-z]+,)+(dc=[a-z]+)$')
    if not re.match(dn_regex, dn):
        raise InvalidDN("That doesn't follow the correct syntax!")

    print """
*************************
*** Base DN: %s ***
*** Root DN: cn=%s,%s ***
*** Root PW: @@@@@@@@@@@@ ***
*************************
""" % (dn, user, dn )

    ok = raw_input("Are you sure? ")
    if not ok[0] in ('Y', 'y'):
        print "Exiting"
        sys.exit(0)

    tempdir = tempfile.mkdtemp(prefix="LDAPTEMP", dir=sys.path[0])

    rootdn = "uid=%s,ou=users,%s"% (user, dn)

    hostname = socket.getfqdn()
    shorthostname = hostname.split(".")[0]

    rootuuid = uuid.uuid1() # UUID for apple root user
    admingrp = uuid.uuid1() # UUID for apple admin group

    print "Getting updates...",
    output = execute_and_wait("apt-get update")
    print "Done"

    print "Installing LDAP...",
    output = execute_and_wait("apt-get install -y --force-yes slapd ldap-utils")
    print "Done"

    print "Running slapppasswd.",
    slappasswd = execute_and_wait("slappasswd -s %s" % passwd, showcmd=False)
    print "Done"

    print "Adding schemas..."

    for schema in ("cosine.ldif", "inetorgperson.ldif", "nis.ldif", "misc.ldif", "samba.ldif", "apple.ldif"):
        print "%s..." % schema,
        output = execute_and_wait("ldapadd -Y EXTERNAL -H ldapi:/// -f \"%s\"" % os.path.abspath(os.path.join(sys.path[0], "schema", schema)))
        print "Done"

    print "Writing configuration to temp directory...",
    database_path = os.path.join(tempdir, "database.ldif")
    fi = open(database_path, 'w')
    fi.write(database % locals())
    fi.close()
    print "wrote %s.  Done" % database_path
    print "Adding configuration to LDAP tree...",
    output = execute_and_wait("ldapadd -Y EXTERNAL -H ldapi:/// -f '%s'" % database_path)

    print "Writing basic structure to temp directory...",
    dit_path = os.path.join(tempdir, "dit.ldif")
    fi = open(dit_path, 'w')
    fi.write(dit % locals())
    fi.close()
    print "wrote %s. Done" % dit_path
    print "Adding basic structure to LDAP tree...",
    output = execute_and_wait("ldapadd -x -D 'cn=%(user)s,%(dn)s' -w '%(passwd)s' -f '%(dit_path)s'" % locals())

    print "Generating Mac OSX bindings template for Open Directory..."
    mac_template_path = os.path.abspath(os.path.join(sys.path[0], "etc/macodconfig.xml")
    fi = open(mac_template_path, 'r')
    mac_template = fi.read() % locals()
    fi.close()
    encoded_template = base64.b64encode(mac_template) # We place this var in mac.ldif, base64 format required
    
    print "Writing Mac OSX structure to temp directory...",
    mac_path = os.path.join(tempdir, "mac.ldif")
    fi = open(mac_path, 'w')
    fi.write(mac % locals())
    fi.close()
    print "write %s. Done" % mac_path
    print "Adding Mac OSX structure to LDAP tree...",
    output = execute_and_wait("ldapadd -x -D 'cn=%(user)s,%(dn)s' -w '%(passwd)s' -f '%(mac_path)s'" % locals())
