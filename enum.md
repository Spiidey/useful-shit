# Target Enumeration Copypastas

## Setup environment variables for EZ-copypasta

```shell
export URL="http://192.168.x.x:80"
```

```shell
export IP="192.168.x.x"
```

## Target Discovery
### Nmap
```shell
 sudo nmap -p- -v -oN nmap-tcp-all
```

```shell
sudo nmap -p- -sV -sS -Pn -A -oN nmap-tcp-aggro $IP
```

## Fuzzing

### Directory/Endpoint discovery
```shell
wfuzz -c -z file,/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt --hc 404,301 "$URL/FUZZ/"
```

### Authenticated directory discovery
```shell
wfuzz -c -z file,/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt --hc 404 -b "PARAM=value" "$URL/FUZZ/"
```

### File discovery
```shell
wfuzz -c -z file,/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt --hc 301,404 "$URL/FUZZ"
```

### Authenticated file fuzzing
```shell
wfuzz -c -z file,/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt --hc 301,404,403 -b "PARAM=value" "$URL/FUZZ"
```

### Parameter discovery
```shell
wfuzz -c -z file,/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt --hc 404,301 "$URL/FUZZ=data"
```

### GET parameter values
```shell
wfuzz -c -z file,/usr/share/wordlists/seclists/Usernames/cirt-default-usernames.txt --hc 404,301 "$URL/index.php?parameter=FUZZ"
```

### XSS Fuzz
```shell
wfuzz -c -z file,/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt --hh 0 "$URL/index.php?id=FUZZ"
```
### SQLi Fuzz (copy params from Burp)
```shell
wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt -d "db=mysql&id=FUZZ" -u $URL
```

## Gobuster

### Endpoint discovery
```shell
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -u $URL
```

### Subdomain discovery
```shell
gobuster dns -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -d $URL
```

## Hakrawler
#### Crawling 
```shell
echo "$URL" > urls.txt
cat urls.txt | hakrawler
```
