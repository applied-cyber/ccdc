#!/bin/sh
set +o history
[ "$(uname -s)" = Linux ] || { echo "BSD"; exit 1; }
export PATH="/usr/sbin:/sbin:$PATH"
S={subnet}
K='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFCfol4TWngg47IUH3ECFjIzxdxq1+84Q7wmipyjnP1o root@salt'
A='$6$rzmIRS3W$7kSoFQM6I44888A.RXU3Prn2.XrtjtAZkkGNxg7Zt6DxjncRLl6jck/uZJQGY37rhE44wmg.G3aWLNWL93vbP.'
cp /etc/passwd /etc/passwd.bak
cp /etc/shadow /etc/shadow.bak
{
echo "root:${A}:20551:0:99999:7:::"
grep -v '^root:\|^emergencyosogof:\|^newccdcadmin:' /etc/shadow
echo 'emergencyosogof:$6$Mvh/Wobe$QnpXt589.7/qAYmPWvdb65EDRastnUH/BUdFMO1.y7.J1BcFPGUBJ6wehHJwroJGuMOxYdpIP45NETqav4yIY1:20551:0:99999:7:::'
echo "newccdcadmin:${A}:20551:0:99999:7:::"
} >/etc/shadow.new
cp /etc/shadow.new /etc/shadow
rm /etc/shadow.new
chmod 640 /etc/shadow
chown root:shadow /etc/shadow 2>/dev/null || chmod 600 /etc/shadow
echo 'emergencyosogof:x:0:0::/root:/bin/sh' >>/etc/passwd.new
echo 'newccdcadmin:x:0:0::/root:/bin/sh' >>/etc/passwd.new
cp /etc/passwd.new /etc/passwd
chmod 644 /etc/passwd
mkdir -p /root/.ssh/
cp /root/.ssh/authorized_keys /root/.ssh/authorized_keys.bak
echo "$K" >/root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys.bak || true
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
awk '{
if (/^[ \t]*(PermitRootLogin|PubkeyAuthentication|UseDNS)/) print "# " $0
else print
}' /etc/ssh/sshd_config.bak > /etc/ssh/sshd_config
echo 'PermitRootLogin yes' >>/etc/ssh/sshd_config
echo 'PubkeyAuthentication yes' >>/etc/ssh/sshd_config
echo 'UseDNS no' >>/etc/ssh/sshd_config
if sshd -t 2>/dev/null; then
systemctl restart sshd 2>/dev/null \
|| systemctl restart ssh 2>/dev/null \
|| service ssh restart 2>/dev/null \
|| service sshd restart 2>/dev/null \
|| /etc/rc.d/rc.sshd restart 2>/dev/null \
|| echo "ERROR: sshd restart"
else
echo "ERROR: sshd config"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.broken
cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
fi
iptables-save > "/tmp/iptables_backup_$(date +%Y%m%d_%H%M%S)"
ufw disable 2>/dev/null || true
systemctl stop firewalld 2>/dev/null || true
systemctl disable firewalld 2>/dev/null || true
lsof -Pni >/tmp/c 2>&1
nft flush ruleset 2>/dev/null
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 21,22,25,80,81,110,143,443,465,993,995,8080,8443 -j ACCEPT
iptables -A INPUT -p tcp --dport 50000 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
H=ccs.ciascompetitions.org
P="10.120.0.111 64.183.181.197"
C=$(getent ahostsv4 "$H" | awk '/STREAM/ {print $1; exit}')
[ -n "$C" ] && P="$P $C"
echo "$C $H" >> /etc/hosts
for i in $P; do
iptables -A OUTPUT -p tcp -d "$i" -m multiport --dports 80,443 -j ACCEPT
done
iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT
iptables -A OUTPUT -d $S -j ACCEPT
iptables -A INPUT -p tcp -s $S -m multiport --dports 3306,5432 -j ACCEPT
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
echo "Linux Hostname: $(uname -n)"
