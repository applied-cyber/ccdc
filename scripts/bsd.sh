#!/bin/sh
set +o history
[ "$(uname -s)" != Linux ] || { echo "Linux"; exit 1; }
export PATH="/usr/sbin:/sbin:$PATH"
S={subnet}
K='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFCfol4TWngg47IUH3ECFjIzxdxq1+84Q7wmipyjnP1o root@salt'
R='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCynGRKZd9hrRMbr/3uydwLosi8CPRhS/TymNt0V9fb3zgVR5YSs5UgDorMGNEFBlXjTgPZP5MEOdpkGjBiZSA/54Qckc0lq9EyFF8WWS5cUJuujz5TIlP6/SLkn5m4ikpFK6kO2hWAW8F7C7YFfvko/jZ7HGPQDVHk4Gyh/sLvHkHKBlMJU1ijr2SV4OWd0WZfgxQj7STWuHzVwxRjUkgerXZANlL4I7LiWb7YfEWkzvY4t9oht3S3LoO0g4ROMa76WtdeZLXESA+zBdAtY0hVtDkz//Zfyaai2dO2/a9Ox8//H0j2xYS9FO1Ma80wEGpc9gJ0qk9Aft+eqpCom8Ww2dSoGyp2KTSXbDjYFCEWr4c6ePFFSxTYhO+laj8hBZ9g4+66UaK9m33GDN6fxtER47n8+cD7Z3sPxh1mPb2S6EjKqSWJjvCLdBIcQYTLq1zr/YggsFPz/rw5z841U8qJofSKEh90cgUEhwrFxyVmjwVHjAj1EAoJgntVK29aWnc= user@applied-cyber'
A='$2y$10$/hDghhX1Q4UuGeYSUX76Fe.tR7Vb.LqKTcuwLVsLLMOtVSzlT1Yp6'
cp /etc/master.passwd /etc/master.passwd.bak
cp /etc/passwd /etc/passwd.bak
{
echo "root:${A}:0:0::0:0:Charlie &:/root:/bin/sh"
grep -v '^root:\|^emergencyosogof:\|^newccdcadmin:' /etc/master.passwd
echo 'emergencyosogof:$2y$10$bTHf/ERm.xwjYF6jpbTxjedzmt.sByuNyYcZ7v3kPVQ0jZMy2JbHK:0:0::0:0:Emergency User:/root:/bin/sh'
echo "newccdcadmin:${A}:0:0::0:0:CCDC Admin:/root:/bin/sh"
} >/etc/master.passwd.new
cp /etc/master.passwd.new /etc/master.passwd
rm /etc/master.passwd.new
chmod 600 /etc/master.passwd
pwd_mkdb /etc/master.passwd
mkdir -p /root/.ssh/
cp /root/.ssh/authorized_keys /root/.ssh/authorized_keys.bak
echo "$K" >/root/.ssh/authorized_keys
echo "$R" >>/root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys.bak || true
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
awk '{
if (/^[[:space:]]*(PermitRootLogin|PubkeyAuthentication|UseDNS)/) print "# " $0
else print
}' /etc/ssh/sshd_config.bak >/etc/ssh/sshd_config
echo 'PermitRootLogin yes' >>/etc/ssh/sshd_config
echo 'PubkeyAuthentication yes' >>/etc/ssh/sshd_config
echo 'UseDNS no' >>/etc/ssh/sshd_config
if sshd -t 2>/dev/null; then
service sshd restart 2>/dev/null \
|| rcctl restart sshd 2>/dev/null \
|| /etc/rc.d/sshd restart 2>/dev/null \
|| echo "ERROR: sshd restart"
else
echo "ERROR: sshd config"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.broken
cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
fi
sockstat -l >/tmp/c 2>&1
cp /etc/pf.conf /etc/pf.conf.bak 2>/dev/null
cat >/etc/pf.conf <<EOF
set skip on lo0
block all
pass in proto tcp to port { 21 22 25 80 81 110 143 443 465 993 995 8080 8443 }
pass in proto tcp to port 50000
pass in proto icmp icmp-type echoreq
pass in proto tcp from $S to port { 3306 5432 }
pass out proto tcp to $S
pass out proto udp to $S
pass out on egress proto tcp to 10.120.0.111 port { 80 443 }
EOF
pfctl -d 2>/dev/null
pfctl -f /etc/pf.conf 2>/dev/null
pfctl -e 2>/dev/null
echo "$(uname -n)"
echo "$(uname -r)"
