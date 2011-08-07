all:	configure
	@println
	@echo "Installing the Ultimate Single Sign On Enviroment"

slapd:
	@echo "======= INSTALLING PREREQUISITES ======="
	@apt-get update -y -qq
	@apt-get install -y slapd ldap-utils

configure: slapd configure.py
	@echo "=========== CONFIGURATION ==============" 
	./configure.py

install: install.py
	@echo "============ INSTALLING ================" 
	./install.py > install.log
