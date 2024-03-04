#!/bin/bash

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;35m'
NC='\033[0m'

mkdir $PWD/audit > /dev/null 2>&1

pass=0
fail=0

clear
# Banner Introduction
echo -e "${RED}==================================================================${NONE}"
echo "******************************************************************"
echo -e "******************** ${BOLD}${YELLOW} Welcome ${NONE} *************************"
echo -e "*************** ${CYAN}Red-Hat 9 OS CIS Auditing ${NONE} ***********************"
echo -e "${RED}******************************************************************"
echo -e "${RED}==================================================================${NONE}"
echo
echo -e "${BOLD}${YELLOW}WARNING:${NONE} ${WHITE} Please refrain from entering any commands or interfering with the execution of the audit script to ensure accurate results.${NONE}"
sleep 2

# Check if system packages are up-to-date
echo
echo -e "${BLUE}Check system packages are up-to-date or not${NC}"
if dnf check-update > /dev/null 2>&1; then
    echo -e "${GREEN}PASS:${NC} System packages are up-to-date."
    pass=$((pass + 1))
else
    echo -e "${RED}FAIL:${NC} System packages are not up-to-date."
    fail=$((fail + 1))
fi
sleep 2

###########################################################################################################################

##Category 1.1 Initial Setup - Filesystem Configuration
echo
echo -e "${BLUE}1.1 Initial Setup - Filesystem Configuration${NC}"

# Check if cramfs module is configured to be disabled
if modprobe -n -v cramfs > /dev/null 2>&1 | grep -q "^install /bin/true$"; then
  echo -e "${RED}FAIL:${NC} cramfs module is configured to be installed. Ensure mounting of cramfs filesystems is not disabled."
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} cramfs module is not configured to be installed. Mounting of cramfs filesystems is disabled."
  pass=$((pass + 1))
fi
sleep 2

# Ensure mounting of freevxfs filesystems is disabled
if lsmod | grep -q "^freevxfs\s" > /dev/null 2>&1; then
    echo -e "${RED}FAIL:${NC} Freevxfs module is loaded. Ensure mounting of freevxfs filesystems is not disabled."
    fail=$((fail + 1))
else
    echo -e "${GREEN}PASS:${NC} Freevxfs module is not loaded. Mounting of freevxfs filesystems is disabled."
    pass=$((pass + 1))
fi
sleep 2

# Check if JFFS2 module is configured to be loaded at boot time
if modprobe -n -v jffs2 > /dev/null 2>&1 | grep -q "^install /bin/true$"; then
    echo -e "${RED}FAIL:${NC} JFFS2 filesystem module is configured to be loaded at boot time."
    fail=$((fail + 1))
else
    echo -e "${GREEN}PASS:${NC} JFFS2 filesystem module is not configured to be loaded at boot time."
    pass=$((pass + 1))
fi
sleep 2

# Check if HFS module is configured to be loaded at boot time
if modprobe -n -v hfs > /dev/null 2>&1 | grep -q "^install /bin/true$"; then
    echo -e "${RED}FAIL:${NC} HFS filesystem module is configured to be loaded at boot time."
    fail=$((fail + 1))
else
    echo -e "${GREEN}PASS:${NC} HFS filesystem module is not configured to be loaded at boot time."
    pass=$((pass + 1))
fi
sleep 2

# Check if SquashFS module is configured to be loaded at boot time
if modprobe -n -v squashfs > /dev/null 2>&1 | grep -q "^install /bin/true$"; then
    echo -e "${RED}FAIL:${NC} SquashFS filesystem module is configured to be loaded at boot time."
    fail=$((fail + 1))
else
    echo -e "${GREEN}PASS:${NC} SquashFS filesystem module is not configured to be loaded at boot time."
    pass=$((pass + 1))
fi
sleep 2

# Check if UDF module is configured to be loaded at boot time
if modprobe -n -v udf > /dev/null 2>&1 | grep -q "^install /bin/true$"; then
    echo -e "${RED}FAIL:${NC} UDF filesystem module is configured to be loaded at boot time."
    fail=$((fail + 1))
else
    echo -e "${GREEN}PASS:${NC} UDF filesystem module is not configured to be loaded at boot time."
    pass=$((pass + 1))
fi
sleep 2

# Check if VFAT module is configured to be loaded at boot time
if modprobe -n -v vfat > /dev/null 2>&1 | grep -q "^install /bin/true$"; then
    echo -e "${RED}FAIL:${NC} VFAT filesystem module is configured to be loaded at boot time."
    fail=$((fail + 1))
else
    echo -e "${GREEN}PASS:${NC} VFAT filesystem module is not configured to be loaded at boot time."
    pass=$((pass + 1))
fi
sleep 2

# Check if the sticky bit is set on all world-writable directories
world_writable_directories=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null)
if [[ -z "$world_writable_directories" ]]; then
    echo -e "${GREEN}PASS:${NC} Sticky bit is set on all world-writable directories."
    pass=$((pass + 1))
else
    echo -e "${RED}FAIL:${NC} Some world-writable directories do not have the sticky bit set, please check $PWD/audit/world_writable_directories"
    echo "$world_writable_directories" > "$PWD/audit/world_writable_directories"
    fail=$((fail + 1))
fi
sleep 2

# Check if automounting is disabled
systemctl is-enabled autofs.service > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
    echo -e "${GREEN}PASS:${NC} Automounting is disabled."
    pass=$((pass + 1))
else
    echo -e "${RED}FAIL:${NC} Automounting is enabled."
    fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 1.2 Initial Setup - Configure Software Updates
echo
echo -e "${BLUE}1.2 Initial Setup - Configure Software Updates${NC}"
# Check if gpgcheck is globally activated in /etc/dnf/dnf.conf
if egrep -q "^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$" /etc/dnf/dnf.conf; then
    echo -e "${GREEN}PASS:${NC} gpgcheck is globally activated in /etc/dnf/dnf.conf."
    pass=$((pass + 1))
else
    echo -e "${RED}FAIL:${NC} gpgcheck is not globally activated in /etc/dnf/dnf.conf."
    fail=$((fail + 1))
fi
# Check if gpgcheck is globally activated in individual repo files
rhel_1_2_2_temp=0
for file in /etc/yum.repos.d/*; do
    if egrep -q "^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$" "$file"; then
        echo -e "${GREEN}PASS:${NC} gpgcheck is globally activated in $file."
        ((rhel_1_2_2_temp++))
    else
        echo -e "${RED}FAIL:${NC} gpgcheck is not globally activated in $file."
        fail=$((fail + 1))
    fi
done
# Check if all repo files have been audited
rhel_1_2_2_temp_2=$(ls -1q /etc/yum.repos.d/* | wc -l)
if [[ "$rhel_1_2_2_temp" -eq "$rhel_1_2_2_temp_2" ]]; then
    echo -e "${GREEN}PASS:${NC} All repository files have been audited."
    pass=$((pass + 1))
else
    echo -e "${RED}FAIL:${NC} Not all repository files have been audited."
    fail=$((fail + 1))
fi
sleep 2

##################################################################################################################################

## Category 1.3 Initial Setup - Filesystem Integrity Checking
echo
echo -e "${BLUE}1.3 Initial Setup - Filesystem Integrity Checking${NC}"
# Check if AIDE is installed
if rpm -q aide > /dev/null 2>&1; then
    echo -e "${GREEN}PASS:${NC} AIDE is installed."
    pass=$((pass + 1))
else
    echo -e "${RED}FAIL:${NC} AIDE is not installed."
    fail=$((fail + 1))
fi
sleep 2
# Check if the cron job for filesystem integrity checking is set up
if crontab -u root -l > /dev/null 2>&1 | grep -q "^0 5 \* \* \* /usr/sbin/aide --check$"; then
    echo -e "${GREEN}PASS:${NC} Filesystem integrity is regularly checked."
    pass=$((pass + 1))
else
    echo -e "${RED}FAIL:${NC} Filesystem integrity check cron job is not set up."
    fail=$((fail + 1))
fi
sleep 2

# Ensure cryptographic mechanisms are used to protect the integrity of audit tools
# Audit Procedure - Check AIDE configuration
audit_selection=$(grep -Ps -- '(\/sbin\/(audit|au)\H*\b)' /etc/aide.conf.d/*.conf /etc/aide.conf)
# Display the result of the audit
if [[ -n "$audit_selection" ]]; then
  echo -e "${GREEN}PASS:${NC} AIDE is configured to use cryptographic mechanisms for audit tools."
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} AIDE is not configured to use cryptographic mechanisms for audit tools."
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

echo
echo -e "${BLUE}1.4 Initial Setup - Secure Boot Settings${NC}"
# Check permissions on bootloader config are configured
bootloader_config="/boot/grub2/grub.cfg"
bootloader_permissions=$(stat -c "%a %U %G" "$bootloader_config")
# Check if permissions are configured properly
if [[ "$bootloader_permissions" == "400 root root" ]]; then
  echo -e "${GREEN}PASS:${NC} Permissions on bootloader config are configured properly"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on bootloader config are not configured properly"
  fail=$((fail + 1))
fi
sleep 2

# Check if authentication is required for single-user mode
rescue_service="/usr/lib/systemd/system/rescue.service"
emergency_service="/usr/lib/systemd/system/emergency.service"
# Check if authentication is required for rescue service
if grep -q "^\s*ExecStart" "$rescue_service" && grep -q "/sbin/sulogin" "$rescue_service" && grep -q "/usr/bin/systemctl --fail --no-block default" "$rescue_service"; then
  rescue_service_audit="PASS"
else
  rescue_service_audit="FAIL"
fi
# Check if authentication is required for emergency service
if grep -q "^\s*ExecStart" "$emergency_service" && grep -q "/sbin/sulogin" "$emergency_service" && grep -q "/usr/bin/systemctl --fail --no-block default" "$emergency_service"; then
  emergency_service_audit="PASS"
else
  emergency_service_audit="FAIL"
fi
# Display the audit result
if [[ "$rescue_service_audit" == "PASS" && "$emergency_service_audit" == "PASS" ]]; then
  echo -e "${GREEN}PASS:${NC} Authentication required for single user mode"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Authentication not properly configured for single user mode"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

echo
echo -e "${BLUE}1.5${NC} Check core dumps are restricted"

# Check if core dumps are restricted
limits_conf="/etc/security/limits.conf > /dev/null 2>&1;"
limits_d_dir="/etc/security/limits.d > /dev/null 2>&1;"
sysctl_conf="/etc/sysctl.conf > /dev/null 2>&1;"
sysctl_d_dir="/etc/sysctl.d > /dev/null 2>&1;"
# Check if core dumps are restricted in limits.conf
if grep -q "^(\s*)\*\s+hard\s+core\s+0(\s*#.*)?\s*$" "$limits_conf" > /dev/null 2>&1; then
  limits_conf_audit="PASS"
else
  limits_conf_audit="FAIL"
fi
# Check if core dumps are restricted in limits.d
if grep -q "^(\s*)\*\s+hard\s+core\s+0(\s*#.*)?\s*$" "$limits_d_dir"/* > /dev/null 2>&1; then
  limits_d_audit="PASS"
else
  limits_d_audit="FAIL"
fi
# Check if core dumps are restricted in sysctl.conf
if grep -q "^(\s*)fs.suid_dumpable\s*=\s*0(\s*#.*)?\s*$" "$sysctl_conf"> /dev/null 2>&1; then
  sysctl_conf_audit="PASS"
else
  sysctl_conf_audit="FAIL"
fi
# Check if core dumps are restricted in sysctl.d
if grep -q "^(\s*)fs.suid_dumpable\s*=\s*0(\s*#.*)?\s*$" "$sysctl_d_dir"/* > /dev/null 2>&1; then
  sysctl_d_audit="PASS"
else
  sysctl_d_audit="FAIL"
fi
# Check if core dumps are restricted using kernel parameter
if sysctl fs.suid_dumpable | grep -q "fs.suid_dumpable = 0"; then
  kernel_param_audit="PASS"
else
  kernel_param_audit="FAIL"
fi
# Display the audit result
if [[ "$limits_conf_audit" == "PASS" && "$limits_d_audit" == "PASS" && "$sysctl_conf_audit" == "PASS" && "$sysctl_d_audit" == "PASS" && "$kernel_param_audit" == "PASS" ]]; then
  echo -e "${GREEN}PASS:${NC} Core dumps are restricted"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Core dumps are not properly restricted"
  fail=$((fail + 1))
fi
sleep 2

# Check if ASLR is enabled in sysctl.conf
if grep -q "^(\s*)kernel.randomize_va_space\s*=\s*2(\s*#.*)?\s*$" /etc/sysctl.conf; then
  sysctl_conf_audit="PASS"
else
  sysctl_conf_audit="FAIL"
fi
# Check if ASLR is enabled in sysctl.d
if grep -q "^(\s*)kernel.randomize_va_space\s*=\s*2(\s*#.*)?\s*$" /etc/sysctl.d/*; then
  sysctl_d_audit="PASS"
else
  sysctl_d_audit="FAIL"
fi
# Check if ASLR is enabled using kernel parameter
if sysctl kernel.randomize_va_space | grep -q "kernel.randomize_va_space = 2"; then
  kernel_param_audit="PASS"
else
  kernel_param_audit="FAIL"
fi
# Display the audit result
if [[ "$sysctl_conf_audit" == "PASS" && "$sysctl_d_audit" == "PASS" && "$kernel_param_audit" == "PASS" ]]; then
  echo -e "${GREEN}PASS:${NC} Address space layout randomization (ASLR) is enabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Address space layout randomization (ASLR) is not properly enabled"
  fail=$((fail + 1))
fi
sleep 2

# Check if prelink is installed
if rpm -q prelink >/dev/null 2>&1; then
  echo -e "${RED}FAIL:${NC} Prelink is installed. It should be removed."
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Prelink is not installed. No action required."
  pass=$((pass + 1))
fi
sleep 2

############################################################################################################################

##Category 1.6 Initial Setup - Mandatory Access Control
echo
echo -e "${BLUE}1.6 Initial Setup - Mandatory Access Control${NC}"

# Ensure SELinux is installed
if rpm -q libselinux >/dev/null 2>&1; then
  echo -e "${GREEN}PASS:${NC} SELinux is installed."
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SELinux is not installed."
  fail=$((fail + 1))
fi
sleep 2

# Check if SELinux is disabled in bootloader configuration
if grep -E '^\s*linux' /boot/loader/entries/*.conf | grep -q '\s*selinux=0'; then
  echo -e "${RED}FAIL:${NC} SELinux is disabled in bootloader configuration"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} SELinux is not disabled in bootloader configuration"
  pass=$((pass + 1))
fi
sleep 2

# Check if SELinux is configured in targeted or mls mode
if grep -E '^\s*SELINUXTYPE=(targeted|mls)\b' /etc/selinux/config > /dev/null 2>&1; then
  echo -e "${GREEN}PASS:${NC} SELinux is configured in targeted mode, No action required."
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SELinux is not configured in mls mode"
  fail=$((fail + 1))
fi
sleep 2

# Check if SELinux is currently enforcing
if sestatus | grep -q "Current mode:.*enforcing"; then
  echo -e "${GREEN}PASS:${NC} SELinux is currently Enforcing Mode"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SELinux is not currently Enforcing Mode"
  fail=$((fail + 1))
fi
sleep 2

# Check for unconfined processes
unconfined_processes=$(ps -eZ | grep unconfined)
# Display the unconfined processes, if any
if [ -n "$unconfined_processes" ]; then
  echo -e "${RED}FAIL:${NC} Unconfined processes found, please check $PWD/audit/unconfined_processes.txt"
  fail=$((fail + 1))
  echo "$unconfined_processes" > "$PWD/audit/unconfined_processes.txt"
else
  echo -e "${GREEN}PASS:${NC} No unconfined processes found"
  pass=$((pass + 1))
fi
sleep 2

# Audit Procedure
legacy_policy_check=$(grep -E -i '^\s*LEGACY\s*(\s+#.*)?$' /etc/crypto-policies/config)
# Display the result of the audit
if [ -n "$legacy_policy_check" ]; then
  echo -e "${RED}FAIL:${NC} Legacy crypto policy found in /etc/crypto-policies/config"
  fail=$((fail + 1))
  echo -e "${RED}Details:${NC}"
  echo "$legacy_policy_check" >> $PWD/audit/legacy_policy_check.txt
else
  echo -e "${GREEN}PASS:${NC} No legacy crypto policy found in /etc/crypto-policies/config"
  pass=$((pass + 1))
fi
sleep 2

# Check if setroubleshoot is installed
if rpm -q setroubleshoot >/dev/null 2>&1; then
    echo -e "${RED}FAIL:${NC} setroubleshoot is installed"
    fail=$((fail + 1))
else
    echo -e "${GREEN}PASS:${NC} setroubleshoot is not installed"
    pass=$((pass + 1))
fi
sleep 2

# Check if mcstrans is installed
if rpm -q mcstrans >/dev/null 2>&1; then
    echo -e "${RED}FAIL:${NC} mcstrans is installed"
    fail=$((fail + 1))
else
    echo -e "${GREEN}PASS:${NC} mcstrans is not installed"
    pass=$((pass + 1))
fi
sleep 2

############################################################################################################################

##Category 1.7 Initial Setup - Warning Banners
echo
echo -e "${BLUE}1.7 Initial Setup - Warning Banners${NC}"
# Check if message of the day is configured properly
if grep -qE '(\\v|\\r|\\m|\\s)' /etc/motd; then
  echo -e "${RED}FAIL:${NC} Message of the day is not configured properly"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Message of the day is configured properly"
  pass=$((pass + 1))
fi
sleep 2

# Check if the warning banner is set to the correct message
if grep -q "Authorized uses only. All activity may be monitored and reported." /etc/issue; then
  echo -e "${GREEN}PASS:${NC} Local login warning banner is configured properly"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Local login warning banner is not configured properly"
  fail=$((fail + 1))
fi
sleep 2

# Check remote login warning banner is configured properly
if grep -q "Authorized uses only. All activity may be monitored and reported." /etc/issue.net; then
  echo -e "${GREEN}PASS:${NC} Remote login warning banner is configured properly"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Remote login warning banner is not configured properly"
  fail=$((fail + 1))
fi
sleep 2

# Check if the permissions on /etc/motd are configured properly
if [[ "$(stat -c '%a' /etc/motd)" == "644" ]]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/motd are configured properly"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/motd are not configured properly"
  fail=$((fail + 1))
fi
sleep 2

# Check if the permissions on /etc/issue are configured properly
if [[ "$(stat -c '%a' /etc/issue)" == "644" ]]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/issue are configured properly"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/issue are not configured properly"
  fail=$((fail + 1))
fi
sleep 2

# Check if the permissions on /etc/issue.net are configured properly
if [[ "$(stat -c '%a' /etc/issue.net)" == "644" ]]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/issue.net are configured properly"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/issue.net are not configured properly"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 2.1 Services - inetd Services
echo
echo -e "${BLUE}2.1 Services - inetd Services${NC}"

# Check if chargen services are enabled
if systemctl list-units --type=service | grep -q chargen; then
  echo -e "${RED}FAIL:${NC} chargen services are enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} chargen services are not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Check if daytime services are enabled
if systemctl list-units --type=service | grep -q daytime; then
  echo -e "${RED}FAIL:${NC} daytime services are enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} daytime services are not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Check if discard services are enabled
if systemctl list-units --type=service | grep -q discard; then
  echo -e "${RED}FAIL:${NC} discard services are enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} discard services are not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Check if echo services are enabled
if systemctl list-units --type=service | grep -q echo; then
  echo -e "${RED}FAIL:${NC} echo services are enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} echo services are not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Check if time services are enabled
if systemctl list-units --type=service | grep -q time; then
  echo -e "${RED}FAIL:${NC} time services are enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} time services are not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Check if TFTP server is enabled
if systemctl list-units --type=socket | grep -q tftp; then
  echo -e "${RED}FAIL:${NC} TFTP server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} TFTP server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Check if xinetd is enabled
if systemctl list-unit-files --type=service | grep -q xinetd.service; then
  echo -e "${RED}FAIL:${NC} xinetd is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} xinetd is not enabled"
  pass=$((pass + 1))
fi
sleep 2

############################################################################################################################

##Category 2.2 Services - Special Purpose Services
echo
echo -e "${BLUE}2.2 Services - Special Purpose Services${NC}"

# Check if either NTP or Chrony is installed
if rpm -q ntp >/dev/null 2>&1 || rpm -q chrony >/dev/null 2>&1; then
  echo -e "${GREEN}PASS:${NC} Time synchronization is in use"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Time synchronization is not in use"
  fail=$((fail + 1))
fi
sleep 2

# Check if ntp is installed
if rpm -q ntp >/dev/null; then
  echo -e "${GREEN}PASS:${NC} ntp is configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} ntp is not configured"
  fail=$((fail + 1))
fi
sleep 2

# Check if chrony is installed
if rpm -q chrony >/dev/null; then
  echo -e "${GREEN}PASS:${NC} chrony is configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} chrony is not configured"
  fail=$((fail + 1))
fi
sleep 2

# Check if X Window System is installed
if rpm -q xorg-x11* >/dev/null; then
  echo -e "${RED}FAIL:${NC} X Window System is installed"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} X Window System is not installed"
  pass=$((pass + 1))
fi
sleep 2

# Ensure Avahi Server is not enabled
rhel_2_2_3="$(systemctl is-enabled avahi-daemon.service)"
rhel_2_2_3=$?
if [[ "$rhel_2_2_3" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} Avahi Server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Avahi Server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure CUPS is not enabled
rhel_2_2_4="$(systemctl is-enabled cups.service)"
rhel_2_2_4=$?
if [[ "$rhel_2_2_4" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} CUPS is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} CUPS is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure DHCP Server is not enabled
rhel_2_2_5="$(systemctl is-enabled dhcpd.service 2>/dev/null)"
rhel_2_2_5=$?
if [[ "$rhel_2_2_5" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} DHCP Server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} DHCP Server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure LDAP server is not enabled
rhel_2_2_6="$(systemctl is-enabled slapd.service 2>/dev/null)"
rhel_2_2_6=$?
if [[ "$rhel_2_2_6" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} LDAP server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} LDAP server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure RPC-BIND are not enabled
rpcbind_check=$(rpm -q rpcbind)
rpcbind_enabled_status=$(systemctl is-enabled rpcbind)
rpcbind_socket_enabled_status=$(systemctl is-enabled rpcbind.socket)
# Display the result of the audit
if [ "$rpcbind_check" == "package rpcbind is not installed" ] && [ "$rpcbind_enabled_status" == "masked" ] && [ "$rpcbind_socket_enabled_status" == "masked" ]; then
  echo -e "${GREEN}PASS:${NC} rpcbind is not installed and rpcbind services are masked"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} rpcbind is installed or rpcbind services are not masked"
  fail=$((fail + 1))
fi
sleep 2

# Ensure rsync-daemon is not installed or the rsyncd service is masked
rsync_daemon_check=$(rpm -q rsync-daemon 2>/dev/null)
rsyncd_enabled_status=$(systemctl is-enabled rsyncd 2>/dev/null)
# Display the result of the audit
if [ "$rsync_daemon_check" == "package rsync-daemon is not installed" ] && [ "$rsyncd_enabled_status" == "masked" ]; then
  echo -e "${GREEN}PASS:${NC} rsync-daemon is not installed and rsyncd service is masked"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} rsync-daemon is installed or rsyncd service is not masked"
  fail=$((fail + 1))
fi
sleep 2

# Ensure DNS Server is not enabled
rhel_2_2_8="$(systemctl is-enabled named.service)"
rhel_2_2_8=$?
if [[ "$rhel_2_2_8" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} DNS Server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} DNS Server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure FTP Server is not enabled
rhel_2_2_9="$(systemctl is-enabled vsftpd.service 2>/dev/null)"
rhel_2_2_9=$?
if [[ "$rhel_2_2_9" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} FTP Server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} FTP Server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure HTTP server is not enabled
rhel_2_2_10="$(systemctl is-enabled httpd.service)"
rhel_2_2_10=$?
if [[ "$rhel_2_2_10" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} HTTP server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} HTTP server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure IMAP and POP3 server is not enabled
rhel_2_2_11="$(systemctl is-enabled dovecot.service 2>/dev/null)"
rhel_2_2_11=$?
if [[ "$rhel_2_2_11" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} IMAP and POP3 server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} IMAP and POP3 server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure Samba is not enabled
rhel_2_2_12="$(systemctl is-enabled smb.service)"
rhel_2_2_12=$?
if [[ "$rhel_2_2_12" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} Samba is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Samba is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure HTTP Proxy Server is not enabled
rhel_2_2_13="$(systemctl is-enabled squid.service 2>/dev/null)"
rhel_2_2_13=$?
if [[ "$rhel_2_2_13" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} HTTP Proxy Server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} HTTP Proxy Server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure SNMP Server is not enabled
rhel_2_2_14="$(systemctl is-enabled snmpd.service 2>/dev/null)"
rhel_2_2_14=$?
if [[ "$rhel_2_2_14" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} SNMP Server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} SNMP Server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure NIS Server is not enabled
rhel_2_2_16="$(systemctl is-enabled ypserv.service 2>/dev/null)"
rhel_2_2_16=$?
if [[ "$rhel_2_2_16" -eq 0 ]]; then
  echo -e "${RED}FAIL:${NC} NIS Server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} NIS Server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Check if rsh service is enabled
rsh_enabled=$(systemctl is-enabled rsh.socket.service 2>/dev/null)
rlogin_enabled=$(systemctl is-enabled rlogin.socket.service 2>/dev/null)
rexec_enabled=$(systemctl is-enabled rexec.socket.service 2>/dev/null)
# Display audit results
if [[ "$rsh_enabled" == "enabled" || "$rlogin_enabled" == "enabled" || "$rexec_enabled" == "enabled" ]]; then
  echo -e "${RED}FAIL:${NC} rsh server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} rsh server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Check if talk service is enabled
talk_enabled=$(systemctl is-enabled ntalk.service 2>/dev/null)
# Display audit results
if [[ "$talk_enabled" == "enabled" ]]; then
  echo -e "${RED}FAIL:${NC} talk server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} talk server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Check if telnet service is enabled
telnet_enabled=$(systemctl is-enabled telnet.socket.service 2>/dev/null)
# Display audit results
if [[ "$telnet_enabled" == "enabled" ]]; then
  echo -e "${RED}FAIL:${NC} telnet server is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} telnet server is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Check dnsmasq is not installed or not.
dnsmasq_check=$(rpm -q dnsmasq 2>/dev/null)
# Display the result of the audit
if [ "$dnsmasq_check" == "package dnsmasq is not installed" ]; then
  echo -e "${GREEN}PASS:${NC} dnsmasq is not installed"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} dnsmasq is installed"
  fail=$((fail + 1))
fi
sleep 2

# Check mail transfer agent is not installed
mta_check=$(rpm -q postfix sendmail exim 2>/dev/null)
# Display the result of the audit
if [[ "$mta_check" == "package postfix is not installed" && \
      "$mta_check" == "package sendmail is not installed" && \
      "$mta_check" == "package exim is not installed" ]]; then
  echo -e "${GREEN}PASS:${NC} No Mail Transfer Agent (MTA) is installed"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Mail Transfer Agent (MTA) is installed"
  fail=$((fail + 1))
fi
sleep 2

# Ensure nfs-utils is not installed or the nfs-server service is masked
nfs_utils_check=$(rpm -q nfs-utils 2>/dev/null)
nfs_server_status=$(systemctl is-active nfs-server 2>/dev/null)
# Display the result of the audit
if [ "$nfs_utils_check" == "package nfs-utils is not installed" ] && [ "$nfs_server_status" == "inactive" ]; then
  echo -e "${GREEN}PASS:${NC} nfs-utils is not installed and nfs-server service is inactive"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} nfs-utils is installed or nfs-server service is active"
  fail=$((fail + 1))
fi
sleep 2

# Ensure rsync service is not enabled
rsync_enabled=$(systemctl is-enabled rsyncd.service 2>/dev/null)
# Display the result of the audit
if [ "$rsync_enabled" == "disabled" ]; then
  echo -e "${GREEN}PASS:${NC} rsync service is not enabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} rsync service is enabled"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 2.3 Services - Service Clients
echo
echo -e "${BLUE}2.3 Services - Service Clients${NC}"

# Check if NIS Client (ypbind) is installed
if rpm -q ypbind >/dev/null 2>&1; then
  echo -e "${RED}FAIL:${NC} NIS Client is installed"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} NIS Client is not installed"
  pass=$((pass + 1))
fi
sleep 2

# Check if rsh client is installed
if rpm -q rsh >/dev/null 2>&1; then
  echo -e "${RED}FAIL:${NC} rsh client is installed"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} rsh client is not installed"
  pass=$((pass + 1))
fi
sleep 2

# Check if talk client is installed
if rpm -q talk >/dev/null 2>&1; then
  echo -e "${RED}FAIL:${NC} talk client is installed"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} talk client is not installed"
  pass=$((pass + 1))
fi
sleep 2

# Check if telnet client is installed
if rpm -q telnet >/dev/null 2>&1; then
  echo -e "${RED}FAIL:${NC} telnet client is installed"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} telnet client is not installed"
  pass=$((pass + 1))
fi
sleep 2

# Check if LDAP client is installed
if rpm -q openldap-clients >/dev/null 2>&1; then
  echo -e "${RED}FAIL:${NC} LDAP client is installed"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} LDAP client is not installed"
  pass=$((pass + 1))
fi
sleep 2

# Ensure TFTP client is not installed:
tftp_client_check=$(rpm -q tftp 2>/dev/null)
if [ "$tftp_client_check" == "package tftp is not installed" ]; then
  echo -e "${GREEN}PASS:${NC} TFTP client is not installed"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} TFTP client is installed"
  fail=$((fail + 1))
fi
sleep 2

# Ensure FTP client is not installed
ftp_client_check=$(rpm -q ftp 2>/dev/null)
if [ "$ftp_client_check" == "package ftp is not installed" ]; then
  echo -e "${GREEN}PASS:${NC} FTP client is not installed"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} FTP client is installed"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 3.1 Network Configuration - Network Parameters (Host Only)
echo
echo -e "${BLUE}3.1 Network Configuration - Network Parameters (Host Only)${NC}"


# Check if IPv6 is enabled
ipv6_status=$(grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && echo -e "\n - IPv6 is enabled\n" || echo -e "\n - IPv6 is not enabled\n")
# Update counters based on IPv6 status
if [[ "${ipv6_status}" == *"- IPv6 is enabled"* ]]; then
  echo -e "${RED}FAIL:${NC} IPv6 is enabled"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} IPv6 is not enabled"
  pass=$((pass + 1))
fi
sleep 2

# Ensure wireless interfaces are disabled:
wireless_interfaces_check=$(find /sys/class/net/*/ -type d -name wireless 2>/dev/null)
if [ -n "$wireless_interfaces_check" ]; then
  echo -e "${RED}FAIL:${NC} Wireless interfaces are active"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} No wireless interfaces are active"
  pass=$((pass + 1))
fi
sleep 2

# Check if IP forwarding is disabled
ip_forwarding=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
if [ "$ip_forwarding" -eq 0 ]; then
  echo -e "${GREEN}PASS:${NC} IP forwarding is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} IP forwarding is enabled"
  fail=$((fail + 1))
fi
sleep 2

# Check if packet redirect sending is disabled
send_redirects_all=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null)
send_redirects_default=$(sysctl -n net.ipv4.conf.default.send_redirects 2>/dev/null)
if [ "$send_redirects_all" -eq 0 ] && [ "$send_redirects_default" -eq 0 ]; then
  echo -e "${GREEN}PASS:${NC} Packet redirect sending is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Packet redirect sending is enabled"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 3.2 Network Configuration - Network Parameters (Host and Router)
echo
echo -e "${BLUE}3.2 Network Configuration - Network Parameters (Host and Router)${NC}"

# Check if source routed packets are not accepted
accept_source_route_all=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null)
accept_source_route_default=$(sysctl -n net.ipv4.conf.default.accept_source_route 2>/dev/null)
if [ "$accept_source_route_all" -eq 0 ] && [ "$accept_source_route_default" -eq 0 ]; then
  echo -e "${GREEN}PASS:${NC} Source routed packets are not accepted"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Source routed packets are accepted"
  fail=$((fail + 1))
fi
sleep 2

# Check if ICMP redirects are not accepted
accept_redirects_all=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
accept_redirects_default=$(sysctl -n net.ipv4.conf.default.accept_redirects 2>/dev/null)
if [ "$accept_redirects_all" -eq 0 ] && [ "$accept_redirects_default" -eq 0 ]; then
  echo -e "${GREEN}PASS:${NC} ICMP redirects are not accepted"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} ICMP redirects are accepted"
  fail=$((fail + 1))
fi
sleep 2

# Check if secure ICMP redirects are not accepted
secure_redirects_all=$(sysctl -n net.ipv4.conf.all.secure_redirects 2>/dev/null)
secure_redirects_default=$(sysctl -n net.ipv4.conf.default.secure_redirects 2>/dev/null)
if [ "$secure_redirects_all" -eq 0 ] && [ "$secure_redirects_default" -eq 0 ]; then
  echo -e "${GREEN}PASS:${NC} Secure ICMP redirects are not accepted"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Secure ICMP redirects are accepted"
  fail=$((fail + 1))
fi
sleep 2

# Check if suspicious packets are logged
log_martians_all=$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null)
log_martians_default=$(sysctl -n net.ipv4.conf.default.log_martians 2>/dev/null)
if [ "$log_martians_all" -eq 1 ] && [ "$log_martians_default" -eq 1 ]; then
  echo -e "${GREEN}PASS:${NC} Suspicious packets are logged"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Suspicious packets are not logged"
  fail=$((fail + 1))
fi
sleep 2

# Check if broadcast ICMP requests are ignored
icmp_echo_ignore_broadcasts=$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null)
if [ "$icmp_echo_ignore_broadcasts" -eq 1 ]; then
  echo -e "${GREEN}PASS:${NC} Broadcast ICMP requests are ignored"
  pass=$((pass + 1))
else
  echo -e "${RED}PASS:${NC} Broadcast ICMP requests are not ignored"
  fail=$((fail + 1))
fi

# Check if bogus ICMP responses are ignored
icmp_ignore_bogus_error_responses=$(sysctl -n net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null)
if [ "$icmp_ignore_bogus_error_responses" -eq 1 ]; then
  echo -e "${GREEN}PASS:${NC} Bogus ICMP responses are ignored"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Bogus ICMP responses are not ignored"
  fail=$((fail + 1))
fi
sleep 2

# Check if Reverse Path Filtering is enabled
rp_filter_all=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)
rp_filter_default=$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null)
if [ "$rp_filter_all" -eq 1 ] && [ "$rp_filter_default" -eq 1 ]; then
  echo -e "${GREEN}PASS:${NC} Reverse Path Filtering is enabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Reverse Path Filtering is not enabled"
  fail=$((fail + 1))
fi
sleep 2

# Check if TCP SYN Cookies is enabled
tcp_syn_cookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
if [ "$tcp_syn_cookies" -eq 1 ]; then
  echo -e "${GREEN}PASS:${NC} TCP SYN Cookies is enabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} TCP SYN Cookies is not enabled"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 3.3 Network Configuration - IPv6
echo
echo -e "${BLUE}3.3 Network Configuration - IPv6${NC}"
# Check if IPv6 router advertisements are not accepted
ipv6_accept_ra=$(sysctl -n net.ipv6.conf.all.accept_ra 2>/dev/null)
if [ "$ipv6_accept_ra" -eq 0 ]; then
  echo -e "${GREEN}PASS:${NC} IPv6 router advertisements are not accepted"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} IPv6 router advertisements are accepted"
  fail=$((fail + 1))
fi
sleep 2

# Check if IPv6 redirects are not accepted
ipv6_accept_redirects=$(sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null)
if [ "$ipv6_accept_redirects" -eq 0 ]; then
  echo -e "${GREEN}PASS:${NC} IPv6 redirects are not accepted"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} IPv6 redirects are accepted"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 3.4 Network Configuration - TCP Wrappers
echo
echo -e "${BLUE}3.4 Network Configuration - TCP Wrappers${NC}"

# Check if TCP Wrappers is installed
if rpm -q tcp_wrappers >/dev/null 2>&1; then
  echo -e "${GREEN}PASS:${NC} TCP Wrappers is installed"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} TCP Wrappers is not installed"
  fail=$((fail + 1))
fi
sleep 2

# Check if /etc/hosts.allow is configured
if [[ -e "/etc/hosts.allow" ]]; then
  echo -e "${GREEN}PASS:${NC} /etc/hosts.allow is configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} /etc/hosts.allow is not configured"
  fail=$((fail + 1))
fi
sleep 2

# Check if /etc/hosts.deny is configured
if [[ -e "/etc/hosts.deny" ]]; then
  echo -e "${GREEN}PASS:${NC} /etc/hosts.deny is configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} /etc/hosts.deny is not configured"
  fail=$((fail + 1))
fi
sleep 2

# Check permissions on /etc/hosts.allow
hosts_allow_perms=$(stat -c "%a" /etc/hosts.allow 2>/dev/null)
if [[ -n "$hosts_allow_perms" && "$hosts_allow_perms" == "644" ]]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/hosts.allow are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/hosts.allow are not properly configured"
  fail=$((fail + 1))
fi
sleep 2

# Check permissions on /etc/hosts.deny
hosts_deny_perms=$(stat -c "%a" /etc/hosts.deny 2>/dev/null)
if [[ -n "$hosts_deny_perms" && "$hosts_deny_perms" == "644" ]]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/hosts.deny are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/hosts.deny are not properly configured"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 3.5 Network Configuration - Uncommon Network Protocols
echo
echo -e "${BLUE}3.5 Network Configuration - Uncommon Network Protocols${NC}"

# Check if DCCP is disabled
dccp_status=$(lsmod | grep "^dccp\s")
if [[ -z "$dccp_status" ]]; then
  echo -e "${GREEN}PASS:${NC} DCCP is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} DCCP is not disabled"
  fail=$((fail + 1))
fi
sleep 2

# Check if SCTP is disabled
sctp_status=$(lsmod | grep "^sctp\s")
if [[ -z "$sctp_status" ]]; then
  echo -e "${GREEN}PASS:${NC} SCTP is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SCTP is not disabled"
  fail=$((fail + 1))
fi
sleep 2

# Check if RDS is disabled
rds_status=$(lsmod | grep "^rds\s")
if [[ -z "$rds_status" ]]; then
  echo -e "${GREEN}PASS:${NC} RDS is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} RDS is not disabled"
  fail=$((fail + 1))
fi
sleep 2

# Check if TIPC is disabled
tipc_status=$(lsmod | grep "^tipc\s")
if [[ -z "$tipc_status" ]]; then
  echo -e "${GREEN}PASS:${NC} TIPC is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} TIPC is not disabled"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 3.6 Network Configuration - Firewall Configuration
echo
echo -e "${BLUE}3.6 Network Configuration - Firewall Configuration${NC}"
# Check if nftables is installed
nftables_check=$(rpm -q nftables 2>/dev/null)
if [ "$nftables_check" == "package nftables is not installed" ]; then
  echo -e "${RED}FAIL:${NC} nftables is not installed"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} nftables is installed"
  pass=$((pass + 1))
fi
sleep 2

# Check if firewalld default zone is set
default_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
if [ "$default_zone" != "public" ]; then
  echo -e "${RED}FAIL:${NC} Firewalld default zone is not set to 'public'"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Firewalld default zone is set to 'public'"
  pass=$((pass + 1))
fi
sleep 2

# Check if at least one nftables table exists
nft_tables=$(nft list tables 2>/dev/null)
if [ -z "$nft_tables" ]; then
  echo -e "${RED}FAIL:${NC} No nftables tables found"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} At least one nftables table exists"
  pass=$((pass + 1))
fi
sleep 2

# Check if iptables is installed
iptables_check=$(rpm -q iptables 2>/dev/null)
if [ -z "$iptables_check" ]; then
  echo -e "${RED}FAIL:${NC} iptables is not installed"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} iptables is installed"
  pass=$((pass + 1))
fi
sleep 2

############################################################################################################################

##Category 4.1 Logging and Auditing - Configure System Accounting (auditd)
echo
echo -e "${BLUE}4.1 Logging and Auditing - Configure System Accounting (auditd)${NC}"
# Check if auditd is installed
auditd_check=$(rpm -q audit 2>/dev/null)
if [ -z "$auditd_check" ]; then
  echo -e "${RED}FAIL:${NC} auditd is not installed"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} auditd is installed"
  pass=$((pass + 1))
fi
sleep 2

# Check if system is configured to be disabled when audit logs are full
space_left_action=$(grep -E "^\s*space_left_action\s*=" /etc/audit/auditd.conf | awk -F "=" '{print $2}' | tr -d ' ')
action_mail_acct=$(grep -E "^\s*action_mail_acct\s*=" /etc/audit/auditd.conf | awk -F "=" '{print $2}' | tr -d ' ')
admin_space_left_action=$(grep -E "^\s*admin_space_left_action\s*=" /etc/audit/auditd.conf | awk -F "=" '{print $2}' | tr -d ' ')
if [[ "$space_left_action" == "email" ]] && [[ "$action_mail_acct" == "root" ]] && [[ "$admin_space_left_action" == "halt" ]]; then
  echo -e "${GREEN}PASS:${NC} System is configured to be disabled when audit logs are full"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} System is not configured to be disabled when audit logs are full"
  fail=$((fail + 1))
fi
sleep 2

# Check if audit logs are configured to be automatically deleted
max_log_file_action=$(grep -E "^\s*max_log_file_action\s*=" /etc/audit/auditd.conf | awk -F "=" '{print $2}' | tr -d ' ')
if [[ "$max_log_file_action" == "keep_logs" ]]; then
  echo -e "${GREEN}PASS:${NC} Audit logs are not automatically deleted"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Audit logs are configured to be automatically deleted"
  fail=$((fail + 1))
fi
sleep 2

# Check if auditd service is enabled
auditd_enabled=$(systemctl is-enabled auditd.service 2>/dev/null)
if [[ "$auditd_enabled" == "enabled" ]]; then
  echo -e "${GREEN}PASS:${NC} auditd service is enabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} auditd service is not enabled"
  fail=$((fail + 1))
fi
sleep 2

# Check if auditing for processes that start prior to auditd is enabled
grub_cmdline=$(grep -E "^\s*GRUB_CMDLINE_LINUX=" /etc/default/grub | sed 's/.*GRUB_CMDLINE_LINUX="//;s/"$//')
if [[ "$grub_cmdline" =~ (^| )audit=1($| ) ]]; then
  echo -e "${GREEN}PASS:${NC} Auditing for processes that start prior to auditd is enabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Auditing for processes that start prior to auditd is not enabled"
  fail=$((fail + 1))
fi
sleep 2

# Check if audit_backlog_limit is set to an appropriate size
audit_backlog_limit=$(grubby --info=ALL | grep -Po "\baudit_backlog_limit=\d+\b" | awk -F'=' '{print $2}')
if [ -n "$audit_backlog_limit" ]; then
  echo -e "${GREEN}PASS:${NC} audit_backlog_limit is set to $audit_backlog_limit"
  pass=$((pass + 1))
  # Check if the value is sufficient (8192 or larger)
  if [ "$audit_backlog_limit" -ge "8192" ]; then
    echo -e "${GREEN}Sufficient Value:${NC} audit_backlog_limit is set to a sufficient value"
    pass=$((pass + 1))
  else
    echo -e "${RED}Insufficient Value:${NC} audit_backlog_limit is set to a value less than 8192"
    fail=$((fail + 1))
  fi
else
  echo -e "${RED}FAIL:${NC} audit_backlog_limit is not set"
  fail=$((fail + 1))
fi
sleep 2

# Check if audit log files are mode 0640 or less permissive
audit_log_dir=$(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs dirname)
insecure_log_files=$(find "$audit_log_dir" -type f \( ! -perm 600 -a ! -perm 0400 -a ! -perm 0200 -a ! -perm 0000 -a ! -perm 0640 -a ! -perm 0440 -a ! -perm 0040 \) -exec stat -Lc "%n %#a" {} +)
if [ -n "$insecure_log_files" ]; then
  echo -e "${RED}FAIL:${NC} Some audit log files are more permissive than mode 0640"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} All audit log files are mode 0640 or less permissive"
  pass=$((pass + 1))
fi
sleep 2

# Check if only authorized users own audit log files
audit_log_dir=$(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs dirname)
unauthorized_owners=$(find "$audit_log_dir" -type f ! -user root -exec stat -Lc "%n %U" {} +)
if [ -n "$unauthorized_owners" ]; then
  echo -e "${RED}FAIL:${NC} Some audit log files are not owned by the root user"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} All audit log files are owned by the root user"
  pass=$((pass + 1))
fi
sleep 2

# Check if only authorized groups are assigned ownership of audit log files
log_group_check=$(grep -Piw -- '^\h*log_group\h*=\h*(adm|root)\b' /etc/audit/auditd.conf)
audit_log_dir=$(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs dirname)
unauthorized_group_owners=$(stat -c "%n %G" "$audit_log_dir"/* | grep -Pv '^\h*\H+\h+(adm|root)\b')
if [ -n "$log_group_check" ] && [ -z "$unauthorized_group_owners" ]; then
  echo -e "${GREEN}PASS:${NC} Log group is set to either 'adm' or 'root', and all audit log files are owned by authorized groups"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Log group is not set to 'adm' or 'root', or some audit log files are not owned by authorized groups"
  fail=$((fail + 1))
fi

# Check if the audit log directory is 0750 or more restrictive
audit_log_dir=$(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs dirname)
audit_log_dir_permissions=$(stat -Lc "%a" "$audit_log_dir")
if ! echo "$audit_log_dir_permissions" | grep -Pq -- '^\h*\H+\h+([0,5,7][0,5]0)'; then
  echo -e "${RED}FAIL:${NC} Audit log directory does not have a mode of 0750 or more restrictive"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Audit log directory has a mode of 0750 or more restrictive"
  pass=$((pass + 1))
fi
sleep 2

# Check if audit configuration files are 640 or more restrictive
audit_conf_files=$(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \))
audit_conf_permissions=$(stat -Lc "%n %a" $audit_conf_files)
if ! echo "$audit_conf_permissions" | grep -Pq -- '^\h*\H+\h*([0,2,4,6][0,4]0)\h*$'; then
  echo -e "${RED}FAIL:${NC} Audit configuration files are not 640 or more restrictive"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Audit configuration files are 640 or more restrictive"
  pass=$((pass + 1))
fi
sleep 2

# Check if audit configuration files are owned by root
audit_conf_files=$(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \))
audit_conf_ownership=$(find $audit_conf_files ! -user root)
if [ -n "$audit_conf_ownership" ]; then
  echo -e "${RED}FAIL:${NC} Audit configuration files are not owned by root"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Audit configuration files are owned by root"
  pass=$((pass + 1))
fi

# Check if audit configuration files belong to group root
audit_conf_files=$(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \))
audit_conf_group=$(find $audit_conf_files ! -group root)
if [ -n "$audit_conf_group" ]; then
  echo -e "${RED}FAIL:${NC} Audit configuration files do not belong to group root"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Audit configuration files belong to group root"
  pass=$((pass + 1))
fi
sleep 2

# Check if audit tools are 755 or more restrictive
audit_tools=("auditctl" "aureport" "ausearch" "autrace" "auditd" "augenrules")
audit_tools_permissions=$(stat -c "%n %a" $(which "${audit_tools[@]}") | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h*$')
if [ -n "$audit_tools_permissions" ]; then
  echo -e "${RED}FAIL:${NC} Audit tools are not 755 or more restrictive"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Audit tools are 755 or more restrictive"
  pass=$((pass + 1))
fi
sleep 2

# Check if audit tools are owned by root
audit_tools=("auditctl" "aureport" "ausearch" "autrace" "auditd" "augenrules")
audit_tools_ownership=$(stat -c "%n %U" $(which "${audit_tools[@]}") | grep -Pv -- '^\h*\H+\h+root\h*$')
if [ -n "$audit_tools_ownership" ]; then
  echo -e "${RED}FAIL:${NC} Audit tools are not owned by root"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Audit tools are owned by root"
  pass=$((pass + 1))
fi
sleep 2


# Check if audit tools belong to group root
audit_tools=("auditctl" "aureport" "ausearch" "autrace" "auditd" "augenrules")
audit_tools_ownership_group=$(stat -c "%n %G" $(which "${audit_tools[@]}") | grep -Pv -- '^\h*\H+\h+root\h*$')
if [ -n "$audit_tools_ownership_group" ]; then
  echo -e "${RED}FAIL:${NC} Audit tools do not belong to group root"
  fail=$((fail + 1))
else
  echo -e "${GREEN}PASS:${NC} Audit tools belong to group root"
  pass=$((pass + 1))
fi
sleep 2

# Ensure events that modify date and time information are collected
audit_rules=(
    "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change"
    "-a always,exit -F arch=b32 -S clock_settime -k time-change"
    "-w /etc/localtime -p wa -k time-change"
)
for rule in "${audit_rules[@]}"; do
    if ! grep -q -- "$rule" /etc/audit/rules.d/audit.rules; then
        echo -e "${RED}FAIL:${NC} Audit rule is missing: $rule"
        fail=$((fail + 1))
    else
        echo -e "${GREEN}PASS:${NC} Audit rule already exists: $rule"
        pass=$((pass + 1))
    fi
done
sleep 2

# Ensure events that modify user/group information are collected
audit_rules=(
    "-w /etc/group -p wa -k identity"
    "-w /etc/passwd -p wa -k identity"
    "-w /etc/gshadow -p wa -k identity"
    "-w /etc/shadow -p wa -k identity"
    "-w /etc/security/opasswd -p wa -k identity"
)
for rule in "${audit_rules[@]}"; do
    if ! grep -q -- "$rule" /etc/audit/rules.d/audit.rules; then
        echo -e "${RED}FAIL:${NC} Audit rule is missing: $rule"
        fail=$((fail + 1))
    else
        echo -e "${GREEN}PASS:${NC} Audit rule already exists: $rule"
        pass=$((pass + 1))
    fi
done
sleep 2


# Ensure events that modify system locale information are collected
audit_rules=(
    "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale"
    "-w /etc/issue -p wa -k system-locale"
    "-w /etc/issue.net -p wa -k system-locale"
    "-w /etc/hosts -p wa -k system-locale"
    "-w /etc/sysconfig/network -p wa -k system-locale"
)
for rule in "${audit_rules[@]}"; do
    if ! grep -q -- "$rule" /etc/audit/rules.d/audit.rules; then
        echo -e "${RED}FAIL:${NC} Audit rule is missing: $rule"
        fail=$((fail + 1))
    else
        echo -e "${GREEN}PASS:${NC} Audit rule already exists: $rule"
        pass=$((pass + 1))
    fi
done
sleep 2

# Ensure events that modify the system's Mandatory Access Controls are collected
audit_rule="-w /etc/selinux/ -p wa -k MAC-policy"
if ! grep -q -- "$audit_rule" /etc/audit/rules.d/audit.rules; then
    echo -e "${RED}FAIL:${NC} Audit rule is missing: $audit_rule"
    fail=$((fail + 1))
else
    echo -e "${GREEN}PASS:${NC} Audit rule already exists: $audit_rule"
    pass=$((pass + 1))
fi
sleep 2

# Ensure login and logout events are collected
audit_rule1="-w /var/run/faillock/ -p wa -k logins"
audit_rule2="-w /var/log/lastlog -p wa -k logins"
if ! grep -q -- "$audit_rule1" /etc/audit/rules.d/audit.rules && ! grep -q -- "$audit_rule2" /etc/audit/rules.d/audit.rules; then
    echo -e "${GREEN}PASS:${NC} Audit rules for login and logout events are already present"
    pass=$((pass + 1))
else
    echo -e "${RED}FAIL:${NC} Audit rules for login and logout events are missing"
    fail=$((fail + 1))
fi
sleep 2

# Ensure session initiation information is collected
audit_rule1="-w /var/run/utmp -p wa -k session"
audit_rule2="-w /var/log/wtmp -p wa -k session"
audit_rule3="-w /var/log/btmp -p wa -k session"
if ! grep -q -- "$audit_rule1" /etc/audit/rules.d/audit.rules && ! grep -q -- "$audit_rule2" /etc/audit/rules.d/audit.rules && ! grep -q -- "$audit_rule3" /etc/audit/rules.d/audit.rules; then
    echo -e "${GREEN}PASS:${NC} Audit rules for session initiation information are already present"
    pass=$((pass + 1))
else
    echo -e "${RED}FAIL:${NC} Audit rules for session initiation information are missing"
    fail=$((fail + 1))
fi
sleep 2

# Ensure discretionary access control permission modification events are collected
audit_rule1="-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
audit_rule2="-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
audit_rule3="-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
if ! grep -q -- "$audit_rule1" /etc/audit/rules.d/audit.rules && ! grep -q -- "$audit_rule2" /etc/audit/rules.d/audit.rules && ! grep -q -- "$audit_rule3" /etc/audit/rules.d/audit.rules; then
    echo -e "${GREEN}PASS:${NC} Audit rules for discretionary access control permission modification events are already present"
    pass=$((pass + 1))
else
    echo -e "${RED}FAIL:${NC} Audit rules for discretionary access control permission modification events are missing"
    fail=$((fail + 1))
fi
sleep 2

# Ensure unsuccessful unauthorized file access attempts are collected
audit_rule1="-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
audit_rule2="-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
audit_rule3="-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
audit_rule4="-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
if ! grep -q -- "$audit_rule1" /etc/audit/rules.d/audit.rules && ! grep -q -- "$audit_rule2" /etc/audit/rules.d/audit.rules && ! grep -q -- "$audit_rule3" /etc/audit/rules.d/audit.rules && ! grep -q -- "$audit_rule4" /etc/audit/rules.d/audit.rules; then
    echo -e "${GREEN}PASS:${NC} Audit rules for unsuccessful unauthorized file access attempts are already present"
    pass=$((pass + 1))
else
    echo -e "${RED}FAIL:${NC} Audit rules for unsuccessful unauthorized file access attempts are missing"
    fail=$((fail + 1))
fi
sleep 2

# Ensure use of privileged commands is collected
rhel_4_1_12_temp=0
for file in $(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f); do
    audit_rule="-a always,exit -F path=$file -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"
    if ! grep -- "$audit_rule" /etc/audit/rules.d/audit.rules; then
        ((rhel_4_1_12_temp=rhel_4_1_12_temp+1))
    fi
done
rhel_4_1_12_temp_2="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | wc -l)"
if [[ "$rhel_4_1_12_temp" -ge "$rhel_4_1_12_temp_2" ]]; then
  echo -e "${GREEN}PASS:${NC} Use of privileged commands is collected"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Ensure use of privileged commands is collected"
  fail=$((fail + 1))
fi
sleep 2

# Ensure successful file system mounts are collected
rhel_4_1_13_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_13_temp_1=$?
rhel_4_1_13_temp_2="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_13_temp_2=$?
if [[ "$rhel_4_1_13_temp_1" -eq 0 ]] && [[ "$rhel_4_1_13_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}PASS:${NC} Successful file system mounts are collected"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Ensure successful file system mounts are collected"
  fail=$((fail + 1))
fi
sleep 2

# Ensure file deletion events by users are collected
rhel_4_1_14_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_14_temp_1=$?
rhel_4_1_14_temp_2="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_14_temp_2=$?
if [[ "$rhel_4_1_14_temp_1" -eq 0 ]] && [[ "$rhel_4_1_14_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}PASS:${NC} File deletion events by users are collected"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Ensure file deletion events by users are collected"
  fail=$((fail + 1))
fi
sleep 2

# Ensure changes to system administration scope (sudoers) is collected
rhel_4_1_15_temp_1="$(egrep "^-w\s+/etc/sudoers\s+-p\s+wa\s+-k\s+scope\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_15_temp_1=$?
rhel_4_1_15_temp_2="$(egrep "^-w\s+/etc/sudoers.d\s+-p\s+wa\s+-k\s+scope\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_15_temp_2=$?
if [[ "$rhel_4_1_15_temp_1" -eq 0 ]] && [[ "$rhel_4_1_15_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}PASS:${NC} Changes to system administration scope (sudoers) is collected"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Ensure changes to system administration scope (sudoers) is collected"
  fail=$((fail + 1))
fi
sleep 2

# Ensure system administrator actions (sudolog) are collected
rhel_4_1_16="$(egrep "^-w\s+/var/log/sudo.log\s+-p\s+wa\s+-k\s+actions\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_16=$?
if [[ "$rhel_4_1_16" -eq 0 ]]; then
  echo -e "${GREEN}PASS:${NC} System administrator actions (sudolog) are collected"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Ensure system administrator actions (sudolog) are collected"
  fail=$((fail + 1))
fi
sleep 2

# Ensure kernel module loading and unloading is collected
rhel_4_1_17_temp_1="$(egrep "^-w\s+/sbin/insmod\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_1=$?
rhel_4_1_17_temp_2="$(egrep "^-w\s+/sbin/rmmod\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_2=$?
rhel_4_1_17_temp_3="$(egrep "^-w\s+/sbin/modprobe\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_3=$?
rhel_4_1_17_temp_4="$(uname -p | grep -q 'x86_64' || egrep "^-a\s+(always,exit|exit,always)\s+arch=b32\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_4=$?
rhel_4_1_17_temp_5="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+arch=b64\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_5=$?
if [[ "$rhel_4_1_17_temp_1" -eq 0 ]] && [[ "$rhel_4_1_17_temp_2" -eq 0 ]] && [[ "$rhel_4_1_17_temp_3" -eq 0 ]] && [[ "$rhel_4_1_17_temp_4" -eq 0 ]] && [[ "$rhel_4_1_17_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}PASS:${NC} Kernel module loading and unloading is collected"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Ensure kernel module loading and unloading is collected"
  fail=$((fail + 1))
fi
sleep 2

# Ensure the audit configuration is immutable
rhel_4_1_18="$(egrep "^-e\s+2\s*$" /etc/audit/rules.d/audit.rules)"
rhel_4_1_18=$?
augenrules --load > /dev/null 2>&1
if [[ "$rhel_4_1_18" -eq 0 ]]; then
  echo -e "${GREEN}PASS:${NC} The audit configuration is immutable"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Ensure the audit configuration is immutable"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 4.2 Logging and Auditing - Configure rsyslog
echo
echo -e "${BLUE}4.2 Logging and Auditing - Configure rsyslog${NC}"

# Ensure rsyslog Service is enabled
if systemctl is-enabled rsyslog.service >/dev/null 2>&1; then
  echo -e "${GREEN}PASS:${NC} rsyslog Service is enabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} rsyslog Service is not enabled"
  fail=$((fail + 1))
fi
sleep 2

# Ensure rsyslog default file permissions are configured
rsyslog_permission_check=$(grep -Ps '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf)
if [ -n "$rsyslog_permission_check" ]; then
  echo -e "${GREEN}PASS:${NC} rsyslog default file permissions are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} rsyslog default file permissions are not configured"
  fail=$((fail + 1))
fi
sleep 2

# Ensure rsyslog is not configured to receive logs from a remote client
tcp_module_check=$(grep -Ps -- '^\h*module\(load="imtcp"\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf)
tcp_input_check=$(grep -Ps -- '^\h*input\(type="imtcp" port="514"\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf)
if [ -z "$tcp_module_check" ] && [ -z "$tcp_input_check" ]; then
  echo -e "${GREEN}PASS:${NC} rsyslog is not configured to receive logs from a remote client"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} rsyslog is configured to receive logs from a remote client"
  fail=$((fail + 1))
fi
sleep 2

# Ensure journald is not configured to receive logs from a remote client
remote_socket_status=$(systemctl is-enabled systemd-journal-remote.socket > /dev/null 2>&1)
if [ "$remote_socket_status" == "masked" ]; then
  echo -e "${GREEN}PASS:${NC} systemd-journal-remote.socket is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} systemd-journal-remote.socket is enabled"
  fail=$((fail + 1))
fi
sleep 2

# Ensure journald service is enabled
journald_status=$(systemctl is-enabled systemd-journald.service)
if [ "$journald_status" == "static" ]; then
  echo -e "${GREEN}PASS:${NC} systemd-journald.service is enabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} systemd-journald.service is not enabled"
  fail=$((fail + 1))
fi
sleep 2

# Check if syslog-ng package is installed
if rpm -q syslog-ng &> /dev/null; then
  echo -e "${GREEN}PASS:${NC} syslog-ng is installed."
  success=$((success + 1))
else
  echo -e "${RED}FAIL:${NC} syslog-ng is not installed."
  fail=$((fail + 1))
fi
sleep 2

# Check if rsyslog package is installed
if rpm -q rsyslog &> /dev/null; then
  echo -e "${GREEN}PASS:${NC} rsyslog is installed"
  success=$((success + 1))
else
  echo -e "${RED}FAIL:${NC} rsyslog is not installed"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on all logfiles are configured
log_permissions=$(find /var/log -type f -exec stat -c "%a %n" {} + | awk '$1 !~ /^(6|4)[0-7]{2}$/')
if [ -z "$log_permissions" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on all log files are properly configured"
  success=$((success + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on some log files are not properly configured"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 5.1 Access, Authentication and Authorization - Configure cron
echo
echo -e "${BLUE}5.1 Access, Authentication and Authorization - Configure cron${NC}"

# Ensure cron daemon is enabled
rhel_5_1_1_status=$(systemctl is-enabled crond.service)
if [ "$rhel_5_1_1_status" == "enabled" ]; then
  echo -e "${GREEN}PASS:${NC} Cron daemon is enabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Cron daemon is not enabled"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/crontab are configured
crontab_permissions=$(stat -c "%A" /etc/crontab)
if [ "$crontab_permissions" == "600" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/crontab are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/crontab are not configured properly"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/cron.hourly are configured
cron_hourly_permissions=$(stat -c "%A" /etc/cron.hourly)
if [ "$cron_hourly_permissions" == "700" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/cron.hourly are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/cron.hourly are not configured properly"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/cron.daily are configured
cron_daily_permissions=$(stat -c "%A" /etc/cron.daily)
if [ "$cron_daily_permissions" == "700" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/cron.daily are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/cron.daily are not configured properly"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/cron.weekly are configured
cron_weekly_permissions=$(stat -c "%A" /etc/cron.weekly)
if [ "$cron_weekly_permissions" == "700" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/cron.weekly are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/cron.weekly are not configured properly"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/cron.monthly are configured
cron_monthly_permissions=$(stat -c "%A" /etc/cron.monthly)
if [ "$cron_monthly_permissions" == "700" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/cron.monthly are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/cron.monthly are not configured properly"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/cron.d are configured
cron_d_permissions=$(stat -c "%A" /etc/cron.d)
if [ "$cron_d_permissions" == "700" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/cron.d are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/cron.d are not configured properly"
  fail=$((fail + 1))
fi
sleep 2

# Ensure at/cron is restricted to authorized users
if [ -e /etc/cron.allow ] && [ -e /etc/at.allow ]; then
  cron_allow_permissions=$(stat -c "%A" /etc/cron.allow)
  at_allow_permissions=$(stat -c "%A" /etc/at.allow)
  
  if [ "$cron_allow_permissions" == "600" ] && [ "$at_allow_permissions" == "600" ]; then
    echo -e "${GREEN}PASS:${NC} at/cron is restricted to authorized users"
	pass=$((pass + 1))
  else
    echo -e "${RED}FAIL:${NC} at/cron is not restricted to authorized users"
	fail=$((fail + 1))
  fi
else
  echo -e "${RED}FAIL:${NC} at/cron is not restricted to authorized users"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 5.2 Access, Authentication and Authorization - SSH Server Configuration
echo
echo -e "${BLUE}5.2 Access, Authentication and Authorization - SSH Server Configuration${NC}"

# Ensure permissions on /etc/ssh/sshd_config are configured
sshd_config_permissions=$(stat -c "%A" /etc/ssh/sshd_config)
if [ "$sshd_config_permissions" == "600" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on /etc/ssh/sshd_config are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on /etc/ssh/sshd_config are not configured correctly"
  fail=$((fail + 1))
fi
sleep 2

# Ensure SSH Protocol is set to 2
sshd_config_protocol=$(grep -E "^\s*Protocol\s+(?!2\s*$)" /etc/ssh/sshd_config)
if [ -z "$sshd_config_protocol" ]; then
  echo -e "${GREEN}PASS:${NC} SSH Protocol is set to 2"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH Protocol is not set to 2"
  fail=$((fail + 1))
fi
sleep 2

# Ensure SSH LogLevel is set to INFO
sshd_config_loglevel=$(grep -E "^\s*LogLevel\s+(?!INFO\s*$)" /etc/ssh/sshd_config)
if [ -z "$sshd_config_loglevel" ]; then
  echo -e "${GREEN}PASS:${NC} SSH LogLevel is set to INFO"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH LogLevel is not set to INFO"
  fail=$((fail + 1))
fi
sleep 2

# Ensure SSH X11 forwarding is disabled
x11_forwarding_disabled=$(grep -E "^\s*X11Forwarding\s+no(\s*#.*)?$" /etc/ssh/sshd_config)
if [ -n "$x11_forwarding_disabled" ]; then
  echo -e "${GREEN}PASS:${NC} SSH X11 forwarding is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH X11 forwarding is not disabled"
  fail=$((fail + 1))
fi
sleep 2

# Ensure SSH MaxAuthTries is set to 4 or less
max_auth_tries_config=$(grep -E "^\s*MaxAuthTries\s+[0-4](\s*#.*)?$" /etc/ssh/sshd_config)
if [ -n "$max_auth_tries_config" ]; then
  echo -e "${GREEN}PASS:${NC} SSH MaxAuthTries is set to 4 or less"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH MaxAuthTries is not set to 4 or less"
  fail=$((fail + 1))
fi
sleep 2

# Ensure SSH IgnoreRhosts is enabled
ignore_rhosts_config=$(grep -E "^\s*IgnoreRhosts\s+yes(\s*#.*)?$" /etc/ssh/sshd_config)
if [ -n "$ignore_rhosts_config" ]; then
  echo -e "${GREEN}PASS:${NC} SSH IgnoreRhosts is enabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH IgnoreRhosts is not enabled"
  fail=$((fail + 1))
fi
sleep 2

# Ensure SSH HostbasedAuthentication is disabled
hostbased_auth_config=$(grep -E "^\s*HostbasedAuthentication\s+no(\s*#.*)?$" /etc/ssh/sshd_config)
if [ -n "$hostbased_auth_config" ]; then
  echo -e "${GREEN}PASS:${NC} SSH HostbasedAuthentication is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH HostbasedAuthentication is not disabled"
  fail=$((fail + 1))
fi
sleep 2

# Ensure SSH root login is disabled
root_login_config=$(grep -E "^\s*PermitRootLogin\s+no(\s*#.*)?$" /etc/ssh/sshd_config)
if [ -n "$root_login_config" ]; then
  echo -e "${GREEN}PASS:${NC} SSH root login is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH root login is not disabled"
  fail=$((fail + 1))
fi
sleep 2

# Ensure SSH PermitEmptyPasswords is disabled
if grep -Eq "^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config; then
  echo -e "${GREEN}PASS:${NC} SSH PermitEmptyPasswords is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH PermitEmptyPasswords is not disabled"
  fail=$((fail + 1))
fi

# Ensure SSH PermitUserEnvironment is disabled
if grep -Eq "^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config; then
  echo -e "${GREEN}PASS:${NC} SSH PermitUserEnvironment is disabled"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH PermitUserEnvironment is not disabled"
  fail=$((fail + 1))
fi
sleep 2

# Ensure only approved MAC algorithms are used
if grep -Eq "^(\s*)MACs\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config; then
  echo -e "${GREEN}PASS:${NC} Only approved MAC algorithms are used"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Only approved MAC algorithms are not used"
  fail=$((fail + 1))
fi
sleep 2

# Ensure SSH Idle Timeout Interval is configured
if grep -Eq "^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && grep -Eq "^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config; then
  echo -e "${GREEN}PASS:${NC} SSH Idle Timeout Interval is configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH Idle Timeout Interval is not configured"
  fail=$((fail + 1))
fi
sleep 2

# Ensure SSH LoginGraceTime is set to one minute or less
if grep -Eq "^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config; then
  echo -e "${GREEN}PASS:${NC} SSH LoginGraceTime is properly configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH LoginGraceTime is not configured"
  fail=$((fail + 1))
fi
sleep 2

# Ensure SSH warning banner is configured
if grep -Eq "^(\s*)Banner\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config; then
  echo -e "${GREEN}PASS:${NC} SSH warning banner is properly configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} SSH warning banner is not configured"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 5.3 Access, Authentication and Authorization - Configure PAM
echo
echo -e "${BLUE}5.3 Access, Authentication and Authorization - Configure PAM${NC}"

# Ensure password creation requirements are configured
if grep -q "^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf &&
   grep -q "^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf &&
   grep -q "^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf &&
   grep -q "^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf &&
   grep -q "^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf &&
   grep -q "password requisite pam_pwquality.so try_first_pass retry=3" /etc/pam.d/system-auth &&
   grep -q "password requisite pam_pwquality.so try_first_pass retry=3" /etc/pam.d/password-auth; then
  echo -e "${GREEN}PASS:${NC} Password creation requirements are properly configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Password creation requirements are not configured"
  fail=$((fail + 1))
fi
sleep 2

# Ensure lockout for failed password attempts is configured
pam_tally2_check=$(grep -E "auth\s+required\s+pam_tally2\.so" /etc/pam.d/system-auth)
if [[ -n "$pam_tally2_check" ]]; then
  echo -e "${GREEN}PASS:${NC} Lockout for failed password attempts is properly configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Lockout for failed password attempts is not configured"
  fail=$((fail + 1))
fi
sleep 2


# Ensure password reuse is limited
# Audit Procedure for system-auth
pam_unix_system_auth=$(grep -E "^\s*password\s+sufficient\s+pam_unix\.so" /etc/pam.d/system-auth)
if [[ -n "$pam_unix_system_auth" ]]; then
  password_reuse_limit=$(grep -E "^\s*password\s+sufficient\s+pam_unix\.so\s+.*remember=[0-9]+" /etc/pam.d/system-auth)
  if [[ -n "$password_reuse_limit" ]]; then
    echo -e "${GREEN}PASS:${NC} Password reuse is limited in system-auth configuration"
	pass=$((pass + 1))
  else
    echo -e "${RED}FAIL:${NC} Password reuse is not limited in system-auth configuration"
	fail=$((fail + 1))
  fi
else
  echo -e "${RED}FAIL:${NC} System-auth configuration not found"
  fail=$((fail + 1))
fi
# Audit Procedure for password-auth
pam_unix_password_auth=$(grep -E "^\s*password\s+sufficient\s+pam_unix\.so" /etc/pam.d/password-auth)
if [[ -n "$pam_unix_password_auth" ]]; then
  password_reuse_limit=$(grep -E "^\s*password\s+sufficient\s+pam_unix\.so\s+.*remember=[0-9]+" /etc/pam.d/password-auth)
  if [[ -n "$password_reuse_limit" ]]; then
    echo -e "${GREEN}PASS:${NC} Password reuse is limited in password-auth configuration"
	pass=$((pass + 1))
  else
    echo -e "${RED}FAIL:${NC} Password reuse is not limited in password-auth configuration"
	fail=$((fail + 1))
  fi
else
  echo -e "${RED}FAIL:${NC} Password-auth configuration not found"
  fail=$((fail + 1))
fi
sleep 2

# Ensure password hashing algorithm is SHA-512
pam_unix_system_auth=$(grep -E "^\s*password\s+sufficient\s+pam_unix\.so" /etc/pam.d/system-auth)
if [[ -n "$pam_unix_system_auth" ]]; then
  password_hash_algorithm=$(grep -E "^\s*password\s+sufficient\s+pam_unix\.so\s+.*sha512" /etc/pam.d/system-auth)
  if [[ -n "$password_hash_algorithm" ]]; then
    echo -e "${GREEN}PASS:${NC} Password hashing algorithm is SHA-512 in system-auth configuration"
	pass=$((pass + 1))
  else
    echo -e "${RED}FAIL:${NC} Password hashing algorithm is not SHA-512 in system-auth configuration"
	fail=$((fail + 1))
  fi
else
  echo -e "${RED}FAIL:${NC} System-auth configuration not found"
  fail=$((fail + 1))
fi
# Audit Procedure for password-auth
pam_unix_password_auth=$(grep -E "^\s*password\s+sufficient\s+pam_unix\.so" /etc/pam.d/password-auth)
if [[ -n "$pam_unix_password_auth" ]]; then
  password_hash_algorithm=$(grep -E "^\s*password\s+sufficient\s+pam_unix\.so\s+.*sha512" /etc/pam.d/password-auth)
  if [[ -n "$password_hash_algorithm" ]]; then
    echo -e "${GREEN}PASS:${NC} Password hashing algorithm is SHA-512 in password-auth configuration"
	pass=$((pass + 1))
  else
    echo -e "${RED}FAIL:${NC} Password hashing algorithm is not SHA-512 in password-auth configuration"
	fail=$((fail + 1))
  fi
else
  echo -e "${RED}FAIL:${NC} Password-auth configuration not found"
  fail=$((fail + 1))
fi
sleep 2

# Ensure users must provide password for escalation
sudoers_check=$(grep -r "^[^#].*NOPASSWD" /etc/sudoers /etc/sudoers.d/* > /dev/null 2>&1;)
if [ -z "$sudoers_check" ]; then
  echo -e "${GREEN}PASS:${NC} Users must provide a password for escalation"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Users are allowed NOPASSWD escalation"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 5.4 Access, Authentication and Authorization - User Accounts and Environment
echo
echo -e "${BLUE}5.4 Access, Authentication and Authorization - User Accounts and Environment${NC}"

# Ensure password expiration is 90 days or less
rhel_5_4_1_1="$(egrep -q "^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs)"
if [[ "$rhel_5_4_1_1" -eq 0 ]]; then
  echo -e "${GREEN}PASS:${NC} Password expiration is set to 90 days or less"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Password expiration is not set to 90 days or less"
  fail=$((fail + 1))
fi
sleep 2

# Ensure minimum days between password changes is 7 or more
rhel_5_4_1_2="$(egrep -q "^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs)"
if [[ "$rhel_5_4_1_2" -eq 0 ]]; then
  echo -e "${GREEN}PASS:${NC} Minimum days between password changes is set to 7 or more"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Minimum days between password changes is not set to 7 or more"
  fail=$((fail + 1))
fi
sleep 2

# Ensure password expiration warning days is 7 or more
rhel_5_4_1_3="$(egrep -q "^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$" /etc/login.defs)"
if [[ "$rhel_5_4_1_3" -eq 0 ]]; then
  echo -e "${GREEN}PASS:${NC} Password expiration warning days is set to 7 or more"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Password expiration warning days is not set to 7 or more"
  fail=$((fail + 1))
fi
sleep 2

# Ensure inactive password lock is 30 days or less
rhel_5_4_1_4="$(useradd -D -f 30)"
if [[ "$rhel_5_4_1_4" -eq 0 ]]; then
  echo -e "${GREEN}PASS:${NC} Inactive password lock is set to 30 days or less"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Inactive password lock is not set to 30 days or less"
  fail=$((fail + 1))
fi
sleep 2

# Ensure system accounts are non-login
while IFS=: read -r username _ uid _; do
    # Check if UID is less than 1000 (system accounts)
    if [ "$uid" -lt 1000 ]; then
        # Check if the user is not root
        if [ "$username" != "root" ]; then
            # Get the shell of the user
            shell=$(getent passwd "$username" | cut -d: -f7)
            # Check if the shell is set to /sbin/nologin or /usr/sbin/nologin
            if [ "$shell" = "/sbin/nologin" ] || [ "$shell" = "/usr/sbin/nologin" ]; then
                echo -e "${GREEN}PASS:${NC} $username is a non-login account"
                success=$((success + 1))
            else
                echo -e "${RED}FAIL:${NC} $username is not configured as a non-login account"
                fail=$((fail + 1))
            fi
        fi
    fi
done < /etc/passwd

# Ensure default group for the root account is GID 0
root_gid=$(getent passwd root | cut -d: -f4)
if [ "$root_gid" = "0" ]; then
  echo -e "${GREEN}PASS:${NC} Default group for the root account is GID 0"
  success=$((success + 1))
else
  echo -e "${RED}FAIL:${NC} Default group for the root account is not GID 0"
  fail=$((fail + 1))
fi
sleep 2

# Ensure default user umask is 027 or more restrictive
umask_bashrc=$(grep -E "^\s*umask\s+[^027]" /etc/bashrc)
umask_profile=$(grep -E "^\s*umask\s+[^027]" /etc/profile)
if [ -z "$umask_bashrc" ] && [ -z "$umask_profile" ]; then
  echo -e "${GREEN}PASS:${NC} Default user umask is 027 or more restrictive"
  success=$((success + 1))
else
  echo -e "${RED}FAIL:${NC} Default user umask is not 027 or more restrictive"
  fail=$((fail + 1))
fi
sleep 2

# Ensure access to the su command is restricted
pam_su=$(grep -E "^\s*auth\s+required\s+pam_wheel.so(\s+use_uid)?(\s+.*)?$" /etc/pam.d/su)
if [ -n "$pam_su" ]; then
  echo -e "${GREEN}PASS:${NC} Access to the su command is restricted"
  success=$((success + 1))
else
  echo -e "${RED}FAIL:${NC} Access to the su command is not restricted"
  fail=$((fail + 1))
fi
sleep 2


# Ensure root password is set
root_password_status=$(passwd -S root | grep -o 'Password set')
if [[ "$root_password_status" == "Password set" ]]; then
  echo -e "${GREEN}PASS:${NC} Root password is set"
  success=$((success + 1))
else
  echo -e "${RED}FAIL:${NC} Root password is not set"
  fail=$((fail + 1))
fi
sleep 2

############################################################################################################################

##Category 6.1 System Maintenance - System File Permissions
echo
echo -e "${BLUE}6.1 System Maintenance - System File Permissions${NC}"

# Ensure permissions on /etc/passwd are configured
file="/etc/passwd"
permissions=$(stat -c "%a" "$file")
if [ "$permissions" = "644" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on $file are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on $file are not configured"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/shadow are configured
file="/etc/shadow"
permissions=$(stat -c "%a" "$file")
if [ "$permissions" = "640" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on $file are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on $file are not configured"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/group are configured
file="/etc/group"
permissions=$(stat -c "%a" "$file")
if [ "$permissions" = "644" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on $file are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on $file are not configured"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/gshadow are configured
file="/etc/gshadow"
permissions=$(stat -c "%a" "$file")
if [ "$permissions" = "640" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on $file are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on $file are not configured"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/passwd- are configured
file="/etc/passwd-"
permissions=$(stat -c "%a" "$file")
if [ "$permissions" = "600" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on $file are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on $file are not configured"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/shadow- are configured
file="/etc/shadow-"
permissions=$(stat -c "%a" "$file")
if [ "$permissions" = "600" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on $file are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on $file are not configured"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/group- are configured
file="/etc/group-"
permissions=$(stat -c "%a" "$file")
if [ "$permissions" = "600" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on $file are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on $file are not configured"
  fail=$((fail + 1))
fi
sleep 2

# Ensure permissions on /etc/gshadow- are configured
file="/etc/gshadow-"
permissions=$(stat -c "%a" "$file")
if [ "$permissions" = "600" ]; then
  echo -e "${GREEN}PASS:${NC} Permissions on $file are configured"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Permissions on $file are not configured"
  fail=$((fail + 1))
fi
sleep 2

##Category 6.2 System Maintenance - User and Group Settings
echo
echo -e "${BLUE}6.2 System Maintenance - User and Group Settings${NC}"


# Ensure accounts in /etc/passwd use shadowed passwords
audit_log="$PWD/audit/accounts_with_shadowed_passwords.txt"
non_shadowed_accounts=$(awk -F: '($2 != "x") { print $1 }' /etc/passwd)
if [[ -z "$non_shadowed_accounts" ]]; then
  echo -e "${GREEN}PASS:${NC} All accounts in /etc/passwd use shadowed passwords"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} The following accounts in /etc/passwd do not use shadowed passwords: $non_shadowed_accounts"
  fail=$((fail + 1))
fi
sleep 2

# Ensure /etc/shadow password fields are not empty
audit_log="$PWD/audit/empty_password_fields.txt"
empty_password_accounts=$(awk -F: '($2 == "") { print $1 }' /etc/shadow)
empty_password_accounts=$(awk -F: '($2 == "") { print $1 }' /etc/shadow)
if [[ -z "$empty_password_accounts" ]]; then
  echo -e "${GREEN}PASS:${NC} No accounts in /etc/shadow have empty password fields"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} The following accounts in /etc/shadow have empty password fields: $empty_password_accounts"
  fail=$((fail + 1))
fi
sleep 2

# Ensure no legacy "+" entries exist in /etc/passwd
audit_log="$PWD/audit/legacy_plus_entries.txt"
legacy_plus_entries=$(grep '^\+:' /etc/passwd)
if [[ -z "$legacy_plus_entries" ]]; then
  echo -e "${GREEN}PASS:${NC} No legacy + entries exist in /etc/passwd"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Legacy + entries exist in /etc/passwd"
  fail=$((fail + 1))
  echo "$legacy_plus_entries" > "$audit_log"
fi
sleep 2

# Ensure no legacy "+" entries exist in /etc/shadow
audit_log="$PWD/audit/legacy_plus_entries_shadow.txt"
legacy_plus_entries=$(grep '^\+:' /etc/shadow)
if [[ -z "$legacy_plus_entries" ]]; then
  echo -e "${GREEN}PASS:${NC} No legacy + entries exist in /etc/shadow"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Legacy + entries exist in /etc/shadow"
  fail=$((fail + 1))
  echo "$legacy_plus_entries" > "$audit_log"
fi
sleep 2

# Ensure no legacy "+" entries exist in /etc/group
audit_log="$PWD/audit/legacy_plus_entries_group.txt"
legacy_plus_entries=$(grep '^\+:' /etc/group)
if [[ -z "$legacy_plus_entries" ]]; then
  echo -e "${GREEN}PASS:${NC} No legacy + entries exist in /etc/group"
  pass=$((pass + 1))
else
  echo -e "${RED}FAIL:${NC} Legacy + entries exist in /etc/group"
  fail=$((fail + 1))
  echo "$legacy_plus_entries" > "$audit_log"
fi
sleep 2

###########################################################################################################################

echo -e "-----------------------------------------------------------------------------------"
echo 
echo -e "${BLUE}AUDIT SCRIPT FOR **Red Hat Enterprise Linux 9** EXECUTED SUCCESSULLY!!${NC}"
echo
echo -e "-----------------------------------------------------------------------------------"
echo 
echo -e "${YELLOW}SUMMARY:${NC}"
echo -e "${GREEN}AUDIT PASSED:${NC} $pass"
echo -e "${RED}AUDIT FAILED:${NC} $fail"
echo
echo -e "-----------------------------------------------------------------------------------"

###########################################################################################################################
