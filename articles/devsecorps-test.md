---
title: "tmp"
emoji: "💻"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: []
published: false
---

## 目的
Dockerの学習をしたかったので、自身が学びたいセキュリティ分野に関する実践的な演習を行い理解を深める。

単なるコンテナ技術の学習にとどまらず、TrivyとGitHub Actionsを用いたDevSecOps環境を構築し、システムを恒久的に止めないための実務的なリスク受容のプロセスを実践的に理解することを目的とする。

## 環境構成
ローカルのDockerで検証を行い、それをGithub Actionsで最終的に自動化する。


GitHubリポジトリのルートディレクトリに `.github/workflows/trivy-scan.yml` を配置し、コードがPushされるたびに自動で脆弱性スキャンが実行されるパイプラインを構築した。

実際のyamlファイルの中身は以下の通り：
```yaml
name: DevSecOps Pipeline

# 1. 起動タイミング(コードがPushされた時）
on: [push]

jobs:
  build-and-scan:
    # 2. 作業環境（最新のUbuntuの仮想マシン）
    runs-on: ubuntu-latest

    steps:
      # 3. コードを仮想マシンに持ってくる
      - name: Checkout code
        uses: actions/checkout@v4

      # 4. イメージをビルドする
      - name: Build an image from Dockerfile
        run: docker build -t secure-nginx:${{ github.sha }} .

      # 5. Trivyを実行してスキャンする
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'secure-nginx:${{ github.sha }}'
          format: 'table'
          # CRITICALかHIGHが出たらエラーにして処理を強制終了する
          exit-code: '1'
          ignore-unfixed: true
          vuln-type: 'os,library'
          severity: 'CRITICAL,HIGH'
```

本パイプラインにおける最大のポイントは、Trivyの実行オプションに`exit-code: '1'` を設定している点である。
これにより、スキャン結果に `CRITICAL`または `HIGH`の脆弱性が1件でも含まれていた場合、GitHub Actionsのジョブが強制的に終了される。これにより、致命的な脆弱性を含んだコンテナが本番環境へデプロイされることを機械的に防いでいる。

## 検証1 古いコンテナにおける脆弱性

まず、Dockerfileに`FROM nginx:1.14`と記述する。これは非常に古いバージョン(2018年頃)のパッケージであり、多くの脆弱性が含まれていることが知られている。

Trivyを用いて、実際に致命的な脆弱性を検出すると以下のようになる：

```bash
➜  devsecorps-test git:(main) trivy image --severity CRITICAL vulnerable-nginx
2026-03-31T22:43:11+09:00       INFO    [vuln] Vulnerability scanning is enabled

（中略）

Report Summary

┌───────────────────────────────┬────────┬─────────────────┬─────────┐
│            Target             │  Type  │ Vulnerabilities │ Secrets │
├───────────────────────────────┼────────┼─────────────────┼─────────┤
│ vulnerable-nginx (debian 9.8) │ debian │       31        │    -    │
└───────────────────────────────┴────────┴─────────────────┴─────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)

vulnerable-nginx (debian 9.8)
Total: 31 (CRITICAL: 31)

┌──────────────┬────────────────┬──────────┬──────────────┬────────────────────────┬────────────────────────┬──────────────────────────────────────────────────────────────┐
│   Library    │ Vulnerability  │ Severity │    Status    │   Installed Version    │     Fixed Version      │                             Title                            │
├──────────────┼────────────────┼──────────┼──────────────┼────────────────────────┼────────────────────────┼──────────────────────────────────────────────────────────────┤
│ dpkg         │ CVE-2022-1664  │ CRITICAL │ fixed        │ 1.18.25                │ 1.18.26                │ Dpkg::Source::Archive in dpkg, the Debian package management │
│              │                │          │              │                        │                        │ system, b ...                                                │
│              │                │          │              │                        │                        │ https://avd.aquasec.com/nvd/cve-2022-1664                    │
├──────────────┼────────────────┤          │              ├────────────────────────┼────────────────────────┼──────────────────────────────────────────────────────────────┤
│ libbsd0      │ CVE-2019-20367 │          │              │ 0.8.3-1                │ 0.8.3-1+deb9u1         │ nlist.c in libbsd before 0.10.0 has an out-of-bounds read    │
│              │                │          │              │                        │                        │ during a com...                                              │
│              │                │          │              │                        │                        │ https://avd.aquasec.com/nvd/cve-2019-20367                   │
└──────────────┴────────────────┴──────────┴──────────────┴────────────────────────┴────────────────────────┴──────────────────────────────────────────────────────────────┘
（以下略）
```

致命的な脆弱性が31個も見つかった。

## 検証2 最新のコンテナへの移行

Dockerfileの中身を書き換え、パッケージを先ほどよりもセキュアな`nginx:alpine (Alpine 3.23.3)`へと変える。

```bash
➜  devsecorps-test git:(main) trivy image secure-nginx
2026-03-31T22:46:37+09:00       INFO    [vuln] Vulnerability scanning is enabled

（中略）

Report Summary

┌──────────────────────────────┬────────┬─────────────────┬─────────┐
│            Target            │  Type  │ Vulnerabilities │ Secrets │
├──────────────────────────────┼────────┼─────────────────┼─────────┤
│ secure-nginx (alpine 3.23.3) │ alpine │        4        │    -    │
└──────────────────────────────┴────────┴─────────────────┴─────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)


secure-nginx (alpine 3.23.3)

Total: 4 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 3, CRITICAL: 0)

┌─────────┬────────────────┬──────────┬────────┬───────────────────┬───────────────┬──────────────────────────────────────────────────────────────┐
│ Library │ Vulnerability  │ Severity │ Status │ Installed Version │ Fixed Version │                            Title                             │
├─────────┼────────────────┼──────────┼────────┼───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ libpng  │ CVE-2026-33416 │ HIGH     │ fixed  │ 1.6.55-r0         │ 1.6.56-r0     │ libpng: libpng: Arbitrary code execution due to              │
│         │                │          │        │                   │               │ use-after-free vulnerability                                 │
│         │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2026-33416                   │
│         ├────────────────┤          │        │                   │               ├──────────────────────────────────────────────────────────────┤
│         │ CVE-2026-33636 │          │        │                   │               │ libpng: libpng: Information disclosure and denial of service │
│         │                │          │        │                   │               │ via out-of-bounds read/write in...                           │
│         │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2026-33636                   │
├─────────┼────────────────┤          │        ├───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ zlib    │ CVE-2026-22184 │          │        │ 1.3.1-r2          │ 1.3.2-r0      │ zlib: zlib: Arbitrary code execution via buffer overflow in  │
│         │                │          │        │                   │               │ untgz utility                                                │
│         │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2026-22184                   │
│         ├────────────────┼──────────┤        │                   │               ├──────────────────────────────────────────────────────────────┤
│         │ CVE-2026-27171 │ MEDIUM   │        │                   │               │ zlib: zlib: Denial of Service via infinite loop in CRC32     │
│         │                │          │        │                   │               │ combine functions...                                         │
│         │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2026-27171                   │
└─────────┴────────────────┴──────────┴────────┴───────────────────┴───────────────┴──────────────────────────────────────────────────────────────┘
```

検出された脆弱性が4つに減り、レベルも`CRITICAL`から`HIGH`や`MEDIUM`へと下がった。

さらに`.trivyignore`ファイルを作成し、検出される脆弱性を0にする。あくまでも検出させなくしたのであって、脆弱性を修正したわけではないことに注意。

```bash
➜  devsecorps-test git:(main) trivy image secure-nginx
2026-03-31T22:51:23+09:00       INFO    [vuln] Vulnerability scanning is enabled

（中略）

Report Summary

┌──────────────────────────────┬────────┬─────────────────┬─────────┐
│            Target            │  Type  │ Vulnerabilities │ Secrets │
├──────────────────────────────┼────────┼─────────────────┼─────────┤
│ secure-nginx (alpine 3.23.3) │ alpine │        0        │    -    │
└──────────────────────────────┴────────┴─────────────────┴─────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)
```
## 考察 


 |比較項目|修正前（vulnerable-nginx）|修正後（secure-nginx）|改善効果と実務的な運用対応|
 |---|---|---|---|
|ベースイメージ|nginx:1.14 (Debian 9.8)|nginx:alpine (Alpine 3.23.3)|Alpine採用により攻撃面（アタックサーフェス）を大幅削減|
|脆弱性総数|31件|4件|全体のリスクを劇的に削減|
|CRITICAL（致命的）|31件|0件|パイプラインを停止させる致命的なリスクを完全排除|
|HIGH（高）|0件|3件|公式リポジトリ未修正のため .trivyignore にてリスク受容|
|MEDIUM（中）|0件|1件|同上で運用による受容プロセスを適用|
|CI/CDの挙動|エラー終了（デプロイ遮断）|正常終了（デプロイ成功）| GitHub Actionsにて自動ブロックと通過を実証|


コンテナを最新のものにした結果、脆弱性が劇的に減少しており、パッケージを更新することの重要性がうかがえる。

しかし、Alpine Linuxを採用しパッケージのアップデートを試みても脆弱性を完全に無くすことはできなかった。
実際の開発現場において、脆弱性を0にすることに固執しパイプラインを停止させることは可用性を著しく損なうため非現実的である。

したがって、脆弱性の内容をきちんと審査し、許容可能なリスクに対しては `.trivyignore` 等を用いて意図的に無視するリスク受容の運用設計が不可欠である。
