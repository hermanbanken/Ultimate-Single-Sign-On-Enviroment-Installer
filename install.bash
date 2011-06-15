#!/bin/bash
#--------------------------------------------------------------#
# Welkom
#--------------------------------------------------------------#
clear
echo "#-------------------------------------#"
echo "#------- EASY LDAP SETUP v1 ----------#"
echo "#-- brought to you by Herman Banken --#"
echo "#-- see my blog at hermanbanken.nl  --#"
echo "#-------------------------------------#"
sleep .2

#--------------------------------------------------------------#
# Get Variables
#--------------------------------------------------------------#
directory_regex="^(dc=[a-z]+,)*(dc=[a-z]+)$"

while :
do
	echo "Before you can sit back you'll have to fill in some basic details like your LDAP directory root user's name and password."
	echo -ne "\nUsername: "
	read root_name
	
	echo -ne "Password: "
	while :
	do
		read -s root_passplain
#		root_passhash=`slappasswd -s $root_passplain`
		
		echo -ne "\nConfirm:  "
		read -s root_passdup
		if [ "$root_passplain" == "$root_passdup" ]
		then
			break
		fi	
		
		echo -ne "\nThe password's didn't match. Please retry.\nPassword: "
	done
	echo -e "\n";

	echo "Next we'll need some details about the directory tree."
	while :
	do
		echo -ne "Please enter your directory's root (e.g. dc=example,dc=com):\n\ndn: "
		read directory_base
		if [[ $directory_base =~ $directory_regex ]]; then
			break
		fi
		echo "The root that you entered doesn't match the regex $directory_regex.";
	done
	
	echo -e "\nDo you want to support Open Directory binds? (e.g. Mac OSX)";
	echo -ne "\nSupport OD [y/n]: ";
	read confirmod
		
	if [[ $confirmod == "y" ]]; then
		directory_osx=1
	else
		directory_osx=0
	fi
	
	echo -e "\nSo far you have this configuration:"
	echo " BASEDN = $directory_base"
	echo " ROOTDN = cn=$root_name,$directory_base"
	echo " ROOTPW = secret"
	echo " OD Support = $directory_osx"
	
	echo -e "\nDo you want to continue the installation with these settings?";
	echo -n "Continue [y/n]: ";
	read confirmconf
	
	if [[ $confirmconf == "y" ]]; then
		break
	else 
		continue
	fi
done

echo -e "\n\n#-------------------------------------#"
echo "#----- Continuing installation -------#"
echo "#-------------------------------------#"

cd install_scripts
./install_ldap.sh $directory_base $root_name $root_passplain $directory_osx

##apt-get -y --force-yes install libnss-ldap
