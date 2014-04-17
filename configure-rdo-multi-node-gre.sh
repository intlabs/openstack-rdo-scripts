#!/bin/bash


#To make this work requires a few nodes:
#All should be running CentOS 6.5 minimal install with 1st nic set to dhcp no configuration of nodes post anaconda should be required. (This is an obvious lie - there is no cake)

#compute: 1 nic - to management net
#dashboard: 1 nic - to management net
#network: 3 nic - management, data, external
#compute-kvm: 2 nic - mangement, data
#storage: 1 nic - mangement, must have mounted volume at /var/cinder_storage for cinder and raw disks sitting at /dev/sdd for swift and /dev/sde for glance"



set -e

if [ $# -lt 2 ] || [ $(($# % 2)) = 1 ]; then
    echo "Usage: $0 <openstack_release> <ssh_key_file> [<qemu_compute_host_name> <qemu_compute_host_ip>]+"
    exit 1
fi

OPENSTACK_RELEASE=$1

SSH_KEY_FILE=$2

CONTROLLER_VM_NAME=rdo-controller
CONTROLLER_VM_IP=172.16.73.132
NETWORK_VM_NAME=rdo-network
NETWORK_VM_IP=172.16.73.134
DASHBOARD_VM_NAME=rdo-dashboard
DASHBOARD_VM_IP=172.16.73.137
STORAGE_VM_NAME=rdo-storage
STORAGE_VM_IP=172.16.73.142

i=0
QEMU_COMPUTE_VM_NAMES=()
QEMU_COMPUTE_VM_IPS=()
for val in ${@:3}
do
   if [ $(($i % 2)) = 0 ]; then
       QEMU_COMPUTE_VM_NAMES+=($val)
   else
       QEMU_COMPUTE_VM_IPS+=($val)
   fi
   ((i++))
done

RDO_ADMIN=root
RDO_ADMIN_PASSWORD=acoman

ANSWERS_FILE=packstack_answers.conf
NOVA_CONF_FILE=/etc/nova/nova.conf
CEILOMETER_CONF_FILE=/etc/ceilometer/ceilometer.conf

DOMAIN=localdomain

MAX_WAIT_SECONDS=600

BASEDIR=$(dirname $0)

. $BASEDIR/utils.sh

if [ ! -f "$SSH_KEY_FILE" ]; then
    ssh-keygen -q -t rsa -f $SSH_KEY_FILE -N "" -b 4096
fi
SSH_KEY_FILE_PUB=$SSH_KEY_FILE.pub

echo "Configuring SSH public key authentication on the RDO hosts"
configure_ssh_pubkey_auth $RDO_ADMIN $CONTROLLER_VM_IP $SSH_KEY_FILE_PUB $RDO_ADMIN_PASSWORD
configure_ssh_pubkey_auth $RDO_ADMIN $NETWORK_VM_IP $SSH_KEY_FILE_PUB $RDO_ADMIN_PASSWORD
configure_ssh_pubkey_auth $RDO_ADMIN $DASHBOARD_VM_IP $SSH_KEY_FILE_PUB $RDO_ADMIN_PASSWORD
configure_ssh_pubkey_auth $RDO_ADMIN $STORAGE_VM_IP $SSH_KEY_FILE_PUB $RDO_ADMIN_PASSWORD

for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    configure_ssh_pubkey_auth $RDO_ADMIN $QEMU_COMPUTE_VM_IP $SSH_KEY_FILE_PUB $RDO_ADMIN_PASSWORD
done

echo "Sync hosts date and time"
update_host_date $RDO_ADMIN@$CONTROLLER_VM_IP
update_host_date $RDO_ADMIN@$NETWORK_VM_IP
update_host_date $RDO_ADMIN@$DASHBOARD_VM_IP
update_host_date $RDO_ADMIN@$STORAGE_VM_IP

for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    update_host_date $RDO_ADMIN@$QEMU_COMPUTE_VM_IP
done

config_openstack_network_adapter () {
    SSHUSER_HOST=$1
    ADAPTER=$2
    IPADDR=$3
    NETMASK=$4

    run_ssh_cmd_with_retry $SSHUSER_HOST "cat << EOF > /etc/sysconfig/network-scripts/ifcfg-$ADAPTER
DEVICE="$ADAPTER"
BOOTPROTO="none"
MTU="1500"
ONBOOT="yes"
IPADDR="$IPADDR"
NETMASK="$NETMASK"
EOF"

    run_ssh_cmd_with_retry $SSHUSER_HOST "ifup $ADAPTER"
}

set_fake_iface_for_rdo_neutron_bug () {
    local SSHUSER_HOST=$1
    local IFACE=$2

    run_ssh_cmd_with_retry $SSHUSER_HOST "ip link set name $IFACE dev dummy0 && ip addr add 10.8.100.2/24 dev $IFACE && ifconfig $IFACE up"
}

echo "Configuring networking"

DATA_IP_BASE=10.13.8
DATA_IP_NETMASK=255.255.255.0
NETWORK_VM_DATA_IP=$DATA_IP_BASE.1

set_interface_static_ip_from_dhcp_centos $RDO_ADMIN@$CONTROLLER_VM_IP eth0
set_hostname $RDO_ADMIN@$CONTROLLER_VM_IP $CONTROLLER_VM_NAME.$DOMAIN $CONTROLLER_VM_IP
# See https://bugs.launchpad.net/packstack/+bug/1307018
set_fake_iface_for_rdo_neutron_bug $RDO_ADMIN@$CONTROLLER_VM_IP eth1

config_openstack_network_adapter $RDO_ADMIN@$NETWORK_VM_IP eth1 $NETWORK_VM_DATA_IP $DATA_IP_NETMASK
config_openstack_network_adapter $RDO_ADMIN@$NETWORK_VM_IP eth2
set_interface_static_ip_from_dhcp_centos $RDO_ADMIN@$NETWORK_VM_IP eth0
set_hostname $RDO_ADMIN@$NETWORK_VM_IP $NETWORK_VM_NAME.$DOMAIN $NETWORK_VM_IP

set_interface_static_ip_from_dhcp_centos $RDO_ADMIN@$DASHBOARD_VM_IP eth0
set_hostname $RDO_ADMIN@$DASHBOARD_VM_IP $DASHBOARD_VM_NAME.$DOMAIN $DASHBOARD_VM_IP

set_interface_static_ip_from_dhcp_centos $RDO_ADMIN@$STORAGE_VM_IP eth0
set_hostname $RDO_ADMIN@$STORAGE_VM_IP $STORAGE_VM_NAME.$DOMAIN $STORAGE_VM_IP

i=0
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    QEMU_COMPUTE_VM_NAME=${QEMU_COMPUTE_VM_NAMES[$i]}
    QEMU_COMPUTE_VM_DATA_IP=$DATA_IP_BASE.$(($i+2))

    config_openstack_network_adapter $RDO_ADMIN@$QEMU_COMPUTE_VM_IP eth1 $QEMU_COMPUTE_VM_DATA_IP $DATA_IP_NETMASK
    set_interface_static_ip_from_dhcp_centos $RDO_ADMIN@$QEMU_COMPUTE_VM_IP eth0
    set_hostname $RDO_ADMIN@$QEMU_COMPUTE_VM_IP $QEMU_COMPUTE_VM_NAME.$DOMAIN $QEMU_COMPUTE_VM_IP

    ((i++))
done

echo "Validating network configuration"

set_test_network_config () {
    SSHUSER_HOST=$1
    IFADDR=$2
    ACTION=$3

    if check_interface_exists $SSHUSER_HOST br-eth1; then
        IFACE=br-eth1
    else
        IFACE=eth1
    fi

    set_interface_ip $SSHUSER_HOST $IFACE $IFADDR $ACTION
}

i=0
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    QEMU_COMPUTE_VM_DATA_IP=$DATA_IP_BASE.$(($i+2))

    ping_ip $RDO_ADMIN@$NETWORK_VM_IP $QEMU_COMPUTE_VM_DATA_IP
    ping_ip $RDO_ADMIN@$QEMU_COMPUTE_VM_IP $NETWORK_VM_DATA_IP

    ((i++))
done

# TODO: Check external network

echo "Installing NFS packages on storage node"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "yum install nfs* -y"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "service rpcbind start"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "chkconfig rpcbind on"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "service nfs start"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "chkconfig nfs on"

echo "Setting up NFS Server for cinder"
#run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "mkdir /var/cinder_storage"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "chmod 755 /var/cinder_storage/"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "printf '/var/cinder_storage/         $CONTROLLER_VM_IP/24(rw,sync,no_root_squash,no_all_squash)' > /etc/exports"
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "sed -i '$ a\/var/cinder_storage/         $QEMU_COMPUTE_VM_IP/24(rw,sync,no_root_squash,no_all_squash)' /etc/exports"
done
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "sed -i '$ a\/var/cinder_storage/         $NETWORK_VM_IP/24(rw,sync,no_root_squash,no_all_squash)' /etc/exports"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "sed -i '$ a\/var/cinder_storage/         $DASHBOARD_VM_IP/24(rw,sync,no_root_squash,no_all_squash)' /etc/exports"


echo "NFS EXPORT firewall rules"
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $QEMU_COMPUTE_VM_IP/32 -p tcp --dport 2049 -j ACCEPT"
    run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $QEMU_COMPUTE_VM_IP/32 -p tcp --dport 111 -j ACCEPT"
    run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $QEMU_COMPUTE_VM_IP/32 -p tcp --dport 32803 -j ACCEPT"
    run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $QEMU_COMPUTE_VM_IP/32 -p tcp --dport 892 -j ACCEPT"
    run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $QEMU_COMPUTE_VM_IP/32 -p tcp --dport 875 -j ACCEPT"
    run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $QEMU_COMPUTE_VM_IP/32 -p tcp --dport 662 -j ACCEPT"
done

run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $CONTROLLER_VM_IP/32 -p tcp --dport 2049 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $CONTROLLER_VM_IP/32 -p tcp --dport 111 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $CONTROLLER_VM_IP/32 -p tcp --dport 32803 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $CONTROLLER_VM_IP/32 -p tcp --dport 892 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $CONTROLLER_VM_IP/32 -p tcp --dport 875 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $CONTROLLER_VM_IP/32 -p tcp --dport 662 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $NETWORK_VM_IP/32 -p tcp --dport 2049 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $NETWORK_VM_IP/32 -p tcp --dport 111 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $NETWORK_VM_IP/32 -p tcp --dport 32803 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $NETWORK_VM_IP/32 -p tcp --dport 892 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $NETWORK_VM_IP/32 -p tcp --dport 875 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $NETWORK_VM_IP/32 -p tcp --dport 662 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 2049 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 111 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 32803 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 892 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 875 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 662 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "service iptables save"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "service iptables restart && iptables --list"


echo "Setting up NFS Client for cinder"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "yum install nfs* -y"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "service rpcbind start"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "chkconfig rpcbind on"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "service nfs start"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "chkconfig nfs on"


echo "Installing iSCSI target on Storage Node"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "yum install scsi-target-utils -y"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "service tgtd start && chkconfig tgtd on && service tgtd restart"

echo "Installing iSCSI target on Storage Node - for swift"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode target --op new --tid 1 --targetname iqn.2014-16.lan.cannycomputing.rdo-storage:disk1"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode target --op show"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode logicalunit --op new --tid 1 --lun 1 --backing-store /dev/sdd"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode target --op show"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode target --op bind --tid 1 --initiator-address $CONTROLLER_VM_IP "
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode account --op new --user cinderiscsi_user --password cinderiscsi_user_password"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode account --op bind --tid 1 --user cinderiscsi_user"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode account --op show"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode target --op show"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgt-admin --dump"

echo "Installing iSCSI target on Storage Node - for glance"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode target --op new --tid 2 --targetname iqn.2014-16.lan.cannycomputing.rdo-storage:disk2"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode target --op show"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode logicalunit --op new --tid 2 --lun 1 --backing-store /dev/sde"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode target --op show"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode target --op bind --tid 2 --initiator-address $CONTROLLER_VM_IP "
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode account --op new --user glanceiscsi_user --password glanceiscsi_user_password"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode account --op bind --tid 2 --user glanceiscsi_user"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode account --op show"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgtadm --lld iscsi --mode target --op show"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgt-admin --dump"

echo "Manually writing iSCSI target settings on Storage Node"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "cat << EOF > /etc/tgt/targets.conf
default-driver iscsi
<target iqn.2014-16.lan.cannycomputing.rdo-storage:disk1>
    backing-store /dev/sdd
    incominguser cinderiscsi_user cinderiscsi_user_password
    initiator-address $CONTROLLER_VM_IP
</target>
<target iqn.2014-16.lan.cannycomputing.rdo-storage:disk2>
    backing-store /dev/sde
    incominguser glanceiscsi_user glanceiscsi_user_password
    initiator-address $CONTROLLER_VM_IP
</target>
EOF"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "/etc/init.d/tgtd restart"
echo "checking our targets are still running on storage node"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "tgt-admin --dump"

echo "Setting up firewall on Storage Node for iscsi"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "iptables -I INPUT -s $CONTROLLER_VM_IP -p tcp --dport 3260 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "service iptables save"
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP "service iptables restart && iptables --list"

echo "Installing iSCSI initiator on Controller Node"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "yum install iscsi-initiator-utils -y"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "service iscsi start && chkconfig iscsi on"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "service iscsid start && chkconfig iscsid on"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iscsiadm --mode discoverydb --type sendtargets --portal $STORAGE_VM_IP  --discover"

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "sed -i -e 's/node.session.auth.authmethod = None/node.session.auth.authmethod = CHAP\\n node.session.auth.username = cinderiscsi_user\\n node.session.auth.password = cinderiscsi_user_password /g' /var/lib/iscsi/nodes/iqn.2014-16.lan.cannycomputing.$STORAGE_VM_NAME\:disk1/$STORAGE_VM_IP\,3260\,1/default"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iscsiadm --mode node --targetname iqn.2014-16.lan.cannycomputing.$STORAGE_VM_NAME:disk1 --portal $STORAGE_VM_IP -l "

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "sed -i -e 's/node.session.auth.authmethod = None/node.session.auth.authmethod = CHAP\\n node.session.auth.username = glanceiscsi_user\\n node.session.auth.password = glanceiscsi_user_password /g' /var/lib/iscsi/nodes/iqn.2014-16.lan.cannycomputing.$STORAGE_VM_NAME\:disk2/$STORAGE_VM_IP\,3260\,1/default"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iscsiadm --mode node --targetname iqn.2014-16.lan.cannycomputing.$STORAGE_VM_NAME:disk2 --portal $STORAGE_VM_IP -l "

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "service iscsid start && chkconfig iscsid on && service iscsid restart"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "service iscsi start && chkconfig iscsi on && service iscsi restart"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "fdisk -l | grep Disk"
echo "SERIOUSLY: I'm just about to format a disk with NO sanity checking, mad or what. I'll give myself 30 seconds to think about how bad an idea this is (along with how much the above sucks)"
echo "run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "mkfs.ext4 -F /dev/sdb""
echo "run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "mkfs.ext4 -F /dev/sdc""
sleep 1
echo "formatting swift volume!!!"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "mkfs.ext4 -F /dev/sdb"
echo "formatting glance volume!!!"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "mkfs.ext4 -F /dev/sdc"

echo "mount glance iscsi target on controller node and add entry to fstab"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "mkdir -p /var/lib/glance"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "mount /dev/sdc /var/lib/glance"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "sed -i '$ a\/dev/sdc /var/lib/glance   ext4 _netdev 0 0' /etc/fstab"




echo "Installing RDO RPMs on controller"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "yum install -y http://rdo.fedorapeople.org/openstack/openstack-$OPENSTACK_RELEASE/rdo-release-$OPENSTACK_RELEASE.rpm || true"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "yum install -y openstack-packstack"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "yum -y install http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm || true"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "yum install -y crudini"

echo "Generating Packstack answer file"

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "packstack --gen-answer-file=$ANSWERS_FILE"

echo "Configuring Packstack answer file"

QEMU_COMPUTE_VM_IP_LIST=""
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    if [ "$QEMU_COMPUTE_VM_IP_LIST" ]; then
        QEMU_COMPUTE_VM_IP_LIST+=","
    fi
    QEMU_COMPUTE_VM_IP_LIST+=$QEMU_COMPUTE_VM_IP
done

echo "Configuring Packstack answer file services"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "\
crudini --set packstack_answers.conf general CONFIG_HEAT_INSTALL y && \
crudini --set packstack_answers.conf general CONFIG_HORIZON_HOST $DASHBOARD_VM_IP && \
crudini --set packstack_answers.conf general CONFIG_HORIZON_SSL y && \
crudini --set packstack_answers.conf general CONFIG_SWIFT_INSTALL y && \
crudini --set packstack_answers.conf general CONFIG_SWIFT_STORAGE_HOSTS $CONTROLLER_VM_IP/sdb && \
crudini --set packstack_answers.conf general CONFIG_CINDER_BACKEND nfs && \
crudini --set packstack_answers.conf general CONFIG_CINDER_VOLUMES_CREATE n && \
crudini --set packstack_answers.conf general CONFIG_CINDER_NFS_MOUNTS $STORAGE_VM_IP:/var/cinder_storage && \
crudini --set packstack_answers.conf general CONFIG_NAGIOS_INSTALL y"

echo "Configuring Swift on compute nodes with packstack"

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "\
crudini --set $ANSWERS_FILE general CONFIG_SSH_KEY /root/.ssh/id_rsa.pub && \
crudini --set $ANSWERS_FILE general CONFIG_NTP_SERVERS 0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org && \
crudini --set $ANSWERS_FILE general CONFIG_CINDER_VOLUMES_SIZE 20G && \
crudini --set $ANSWERS_FILE general CONFIG_NOVA_COMPUTE_HOSTS $QEMU_COMPUTE_VM_IP_LIST && \
crudini --del $ANSWERS_FILE general CONFIG_NOVA_NETWORK_HOST"

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "\
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_L3_HOSTS $NETWORK_VM_IP && \
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_DHCP_HOSTS $NETWORK_VM_IP && \
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_METADATA_HOSTS $NETWORK_VM_IP && \
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_OVS_TENANT_NETWORK_TYPE gre && \
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_OVS_TUNNEL_RANGES 1:1000 && \
crudini --set $ANSWERS_FILE general CONFIG_NEUTRON_OVS_TUNNEL_IF eth1"

echo "Deploying SSH private key on $CONTROLLER_VM_IP"
scp -i $SSH_KEY_FILE -o 'PasswordAuthentication no' $SSH_KEY_FILE $RDO_ADMIN@$CONTROLLER_VM_IP:.ssh/id_rsa
scp -i $SSH_KEY_FILE -o 'PasswordAuthentication no' $SSH_KEY_FILE_PUB $RDO_ADMIN@$CONTROLLER_VM_IP:.ssh/id_rsa.pub

echo "Running Packstack"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "packstack --answer-file=$ANSWERS_FILE"


echo "Workaround for horizon tennant vs packstck mismatch"
run_ssh_cmd_with_retry $RDO_ADMIN@$DASHBOARD_VM_IP "sed -i -e 's/OPENSTACK_KEYSTONE_DEFAULT_ROLE = \"Member\"/OPENSTACK_KEYSTONE_DEFAULT_ROLE = \"_member_\"/g' /etc/openstack-dashboard/local_settings"
run_ssh_cmd_with_retry $RDO_ADMIN@$DASHBOARD_VM_IP "service httpd restart"

echo "Workaround for Neutron OVS agent bug on controller"

disable_neutron_ovs_agent () {
    local SSHUSER_HOST=$1
    local AGENTHOSTNAME=$2
    run_ssh_cmd_with_retry $SSHUSER_HOST "service neutron-openvswitch-agent stop"
    run_ssh_cmd_with_retry $SSHUSER_HOST "chkconfig neutron-openvswitch-agent off"
    local AGENTID=`run_ssh_cmd_with_retry $SSHUSER_HOST "source ./keystonerc_admin && neutron agent-list | grep 'Open vSwitch agent' | grep $AGENTHOSTNAME" | awk '{print $2}'`
    run_ssh_cmd_with_retry $SSHUSER_HOST "source ./keystonerc_admin && neutron agent-delete $AGENTID"
}

# See: https://bugs.launchpad.net/packstack/+bug/1307018
disable_neutron_ovs_agent $RDO_ADMIN@$CONTROLLER_VM_IP $CONTROLLER_VM_NAME.$DOMAIN

echo "Additional firewall rules"
# See https://github.com/stackforge/packstack/commit/ca46227119fd6a6e5b0f1ef19e8967d92a3b1f6c
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $QEMU_COMPUTE_VM_IP/32 -p tcp --dport 9696 -j ACCEPT"
done

run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $NETWORK_VM_IP/32 -p tcp --dport 9696 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $NETWORK_VM_IP/32 -p tcp --dport 35357 -j ACCEPT"

echo "Additional firewall rules - for horizon"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 5000 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 8000 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 8004 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 8773 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 8774 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 8776 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 8777 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 9292 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 9696 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "iptables -I INPUT -s $DASHBOARD_VM_IP/32 -p tcp --dport 35357 -j ACCEPT"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "service iptables save"

echo "Disabling Nova API rate limits"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "crudini --set $NOVA_CONF_FILE DEFAULT api_rate_limit False"

echo "Enabling Neutron firewall driver on controller"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "sed -i 's/^#\ firewall_driver/firewall_driver/g' /etc/neutron/plugins/openvswitch/ovs_neutron_plugin.ini && service neutron-server restart"

echo "Set libvirt_type on QEMU/KVM compute node"
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    run_ssh_cmd_with_retry $RDO_ADMIN@$QEMU_COMPUTE_VM_IP "grep vmx /proc/cpuinfo > /dev/null && crudini --set $NOVA_CONF_FILE DEFAULT libvirt_type kvm || true"
done

echo "Applying additional OVS configuration on $NETWORK_VM_IP"

run_ssh_cmd_with_retry $RDO_ADMIN@$NETWORK_VM_IP "ovs-vsctl list-ports br-ex | grep eth2 || ovs-vsctl add-port br-ex eth2"

echo "Rebooting Linux nodes to load the new kernel"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP reboot
run_ssh_cmd_with_retry $RDO_ADMIN@$NETWORK_VM_IP reboot
run_ssh_cmd_with_retry $RDO_ADMIN@$DASHBOARD_VM_IP reboot
run_ssh_cmd_with_retry $RDO_ADMIN@$STORAGE_VM_IP reboot
for QEMU_COMPUTE_VM_IP in ${QEMU_COMPUTE_VM_IPS[@]}
do
    run_ssh_cmd_with_retry $RDO_ADMIN@$QEMU_COMPUTE_VM_IP reboot
done
echo "Wait for reboot"
sleep 120

echo "Waiting for SSH to be available on $CONTROLLER_VM_IP"
wait_for_listening_port $CONTROLLER_VM_IP 22 $MAX_WAIT_SECONDS

echo "Validating Nova configuration"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && nova service-list | sed -e '$d' | awk '(NR > 3) {print $10}' | sed -rn '/down/q1'" 10

echo "Validating Neutron configuration"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && neutron agent-list -f csv | sed -e '1d' | sed -rn 's/\".*\",\".*\",\".*\",\"(.*)\",.*/\1/p' | sed -rn '/xxx/q1'" 10

echo "Setting up demo user"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && keystone user-create --name=demo --pass=demo --email=demo@example.com"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && keystone tenant-create --name=demo --description=Demo_Tenant"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && keystone user-role-add --user=demo --role=_member_ --tenant=demo"

echo "Setting up demo user keystone source file"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "printf 'export OS_USERNAME=demo' > keystonerc_demo"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "sed -i '$ a\export OS_USERNAME=demo' keystonerc_demo"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "sed -i '$ a\export OS_TENANT_NAME=demo' keystonerc_demo"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "sed -i '$ a\export OS_PASSWORD=demo' keystonerc_demo"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "sed -i '$ a\export OS_AUTH_URL=http://172.16.73.132:35357/v2.0/' keystonerc_demo"
#run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "sed -i "$ a\export export PS1='[\u@\h \W(keystone_demo)]\$ '" keystonerc_demo"

echo "Create External network"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && neutron net-create ext-net --shared --router:external=True"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && neutron subnet-create ext-net --name ext-subnet  --allocation-pool start=172.16.73.220,end=172.16.73.240 --disable-dhcp --gateway 172.16.73.2 172.16.73.0/24"

echo "Create Guest Network"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && neutron net-create demo-net"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && neutron subnet-create demo-net --name demo-subnet --gateway 192.168.1.1 192.168.1.0/24 --dns_nameservers list=true 8.8.4.4 8.8.8.8"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && neutron router-create demo-router"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && neutron router-interface-add demo-router demo-subnet"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && neutron router-gateway-set demo-router ext-net"

echo "Create Network security rules - admin domain"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && nova secgroup-add-rule default icmp -1 -1 0.0.0.0/0"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && nova secgroup-add-rule default tcp 1 65535 0.0.0.0/0"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && nova secgroup-add-rule default udp 1 65535 0.0.0.0/0"

echo "Create Network security rules - demo domain"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && nova secgroup-add-rule default icmp -1 -1 0.0.0.0/0"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && nova secgroup-add-rule default tcp 1 65535 0.0.0.0/0"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && nova secgroup-add-rule default udp 1 65535 0.0.0.0/0"

echo "Test network"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "ping -c 4 172.16.73.220"

echo "Get cirros image for testing"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_admin && glance image-create --name="CirrOS-0.3.2" --disk-format=qcow2 --container-format=bare --is-public=true --copy-from http://cdn.download.cirros-cloud.net/0.3.2/cirros-0.3.2-x86_64-disk.img"

echo "Check the demo user is happy"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && nova keypair-list"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && nova flavor-list"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && nova image-list"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && neutron net-list"
run_ssh_cmd_with_retry $RDO_ADMIN@$CONTROLLER_VM_IP "source ./keystonerc_demo && nova secgroup-list"

echo "RDO installed!"
echo "SSH access:"
echo "ssh -i $SSH_KEY_FILE $RDO_ADMIN@$CONTROLLER_VM_IP"
