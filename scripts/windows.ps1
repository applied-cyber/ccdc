$PK="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFCfol4TWngg47IUH3ECFjIzxdxq1+84Q7wmipyjnP1o root@salt"
$PW=""
$USERS=@('newccdcadmin','domino','emergencyosogof')
net user Administrator $PW
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 0
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force
Stop-Service Spooler
Set-Service Spooler -StartupType Disabled
Stop-Service CertSvc
Set-Service CertSvc -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
$isDC = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2
if ($isDC) {
    net user krbtgt p
    net user krbtgt p
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "FullSecureChannelProtection" 1 -Type DWORD -Force
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" "TcpReceivePacketSize" 0xFF00 -Type DWORD -Force
    Restart-Service DNS
}
foreach ($u in $USERS) {
    net user $u $PW /add /y
    if ($isDC) {
        net group "Domain Admins" $u /add
    } else {
        net localgroup "Administrators" $u /add
    }
}
if (-not (Get-Service sshd)) {
    iwr https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip -OutFile ssh.zip
    Expand-Archive ssh.zip -DestinationPath "C:\Program Files\OpenSSH"
    & "C:\Program Files\OpenSSH\OpenSSH-Win64\install-sshd.ps1"
    & "C:\Program Files\OpenSSH\OpenSSH-Win64\ssh-keygen.exe" -A
}
$sshdConfig = "$env:ProgramData\ssh\sshd_config"
Copy-Item $sshdConfig "$sshdConfig.bak" -Force
@(
    'PubkeyAuthentication yes'
    'PasswordAuthentication yes'
    'UseDNS no'
    'AllowUsers newccdcadmin domino emergencyosogof'
    'Match Group administrators'
    'AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys'
) | Set-Content $sshdConfig -Encoding ascii
Set-Content "$env:ProgramData\ssh\administrators_authorized_keys" $PK -Encoding ascii
icacls.exe "$env:ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F'
Set-Service sshd -StartupType Automatic
Restart-Service sshd
$ccsIP = (Resolve-DnsName ccs.ciascompetitions.org -Type A).IPAddress
Add-Content "C:\Windows\System32\drivers\etc\hosts" "$ccsIP`tccs.ciascompetitions.org"
if ($isDC) {
    netsh advfirewall firewall add rule name="22in" dir=in action=allow protocol=TCP localport=22
    netsh advfirewall firewall add rule name="135block" dir=in action=block protocol=TCP localport=135
    exit 0
}
netsh advfirewall set allprofiles state off
netsh advfirewall export "C:\o"
netsh advfirewall firewall set rule name=all new enable=no
netsh advfirewall firewall add rule name="stdportsin" dir=in action=allow protocol=TCP localport=21,25,53,80,81,110,143,443,465,993,995,8080,8443
netsh advfirewall firewall add rule name="22,3389in" dir=in action=allow protocol=TCP localport=22,3389
netsh advfirewall firewall add rule name="localnetin" dir=out action=allow remoteip=localsubnet
netsh advfirewall firewall add rule name="CCSout" dir=out action=allow protocol=TCP remoteip=10.120.0.111,64.183.181.197,$ccsIP remoteport=80,443
netsh advfirewall firewall add rule name="Pingin" dir=in action=allow protocol=icmpv4:8,any
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall set allprofiles state on
