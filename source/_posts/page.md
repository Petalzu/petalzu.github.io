---
title: Face the fear, create the future.
date: 2024-01-19 00:00:00
updated: 2024-07-24 14:30:05
categories: [笔记]
tags: [hello world,hexo,cloudflare,GitHub Pages,hexo-theme-redefine]
sticky: 999
cover: /images/page0.svg
thumbnail: /images/page0.svg
toc: true
---
直面恐惧，创造未来。

探究摄影、写作和技术。欢迎访问Petalzu的个人网站。

<!-- more -->
关于本站主题：[Icarus](https://ppoffice.github.io/hexo-theme-icarus/)

关于本站框架：[Hexo](https://hexo.io/zh-cn/)

## 在GitHub Pages 上部署 Icarus
### 本地部署
在本地建立hexo文件夹，安装以下应用程序：  

Node.js (Node.js 版本需不低于 10.13，建议使用 Node.js 12.0 及以上版本)  
Git  

执行如下命令：
```bash
npm install hexo
```
添加Hexo 所在的目录下的 node_modules 添加到环境变量之中  

在想要建立hexo的 <folder>下执行如下命令：
```bash
hexo init <folder>
cd <folder>
npm install
```

在 Hexo 根目录执行以下命令安装主题，有两种方式：
```bash
npm npm install -S hexo-theme-icarus hexo-renderer-inferno
```

在 Hexo 根目录的 _config.yml 文件中，将 theme 值修改为 Icarus：
```bash
theme: icarus
```
或执行命令：
```bash
hexo config theme icarus
```

添加新页：
```bash
hexo new page
```

启动hexo服务器，访问 localhost:4000 查看效果：
```bash
hexo server
```

### 推送
建立存储库，名为 <你的 GitHub 用户名>.github.io

将 main 分支 push 到 GitHub仓库：
```bash
git push -u origin main
```
或者使用GitHub Desktop等工具进行推送。

使用 node --version 指令检查你电脑上的 Node.js 版本，并记下该版本 (例如：v18.16.0)  
在储存库中前往 Settings > Pages > Source，并将 Source 改为 GitHub Actions。  
在储存库中建立 .github/workflows/pages.yml，并填入以下内容：  
```yml
name: Pages

on:
  push:
    branches:
      - master # default branch

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          # If your repository depends on submodule, please see: https://github.com/actions/checkout
          submodules: recursive
      - name: Use Node.js 20
        uses: actions/setup-node@v4
        with:
          # Examples: 20, 18.19, >=16.20.2, lts/Iron, lts/Hydrogen, *, latest, current, node
          # Ref: https://github.com/actions/setup-node#supported-version-syntax
          node-version: "20"
      - name: Cache NPM dependencies
        uses: actions/cache@v4
        with:
          path: node_modules
          key: ${{ runner.OS }}-npm-cache
          restore-keys: |
            ${{ runner.OS }}-npm-cache
      - name: Install Dependencies
        run: npm install
      - name: Build
        run: npm run build
      - name: Upload Pages artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: ./public
  deploy:
    needs: build
    permissions:
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

检查 https://<你的 GitHub 用户名>.github.io 是否已经部署成功。

### RSS
在 Hexo 根目录执行以下命令安装插件：
```bash
npm install hexo-generator-feed --save
```

在 Hexo 根目录的 _config.yml 文件中，添加以下内容：
```yml
feed:
  type: rss2
  path: sitemap.xml
  limit: 20
  hub:
  content: false
```

在 _config.icarus.yml 文件中，找到RSS配置并修改为以下形式：
```yml
RSS:
    icon: fas fa-rss
    url: /sitemap.xml
```


### 推送
建立存储库，名为 <你的 GitHub 用户名>.github.io

将 main 分支 push 到 GitHub仓库：
```bash
$ git push -u origin main
```
或者使用GitHub Desktop等工具进行推送。

使用 node --version 指令检查你电脑上的 Node.js 版本，并记下该版本 (例如：v18.16.0)  
在储存库中前往 Settings > Pages > Source，并将 Source 改为 GitHub Actions。  
在储存库中建立 .github/workflows/pages.yml，并填入以下内容 (将 18.16.0 替换为上个步骤中记下的版本)：  
```.github/workflows/pages.yml
#注：hexo官网上的wf文件配置出现了问题，因此我手动修改了一部分，以下是我自己使用的文件
name: Pages

on:
  push:
    branches:
      - master # default branch

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          # If your repository depends on submodule, please see: https://github.com/actions/checkout
          submodules: recursive
      - name: Use Node.js 18.16.0
        uses: actions/setup-node@v3
        with:
          node-version: '18.16.0'
      - name: Cache NPM dependencies
        uses: actions/cache@v3
        with:
          path: node_modules
          key: ${{ runner.OS }}-npm-cache
          restore-keys: |
            ${{ runner.OS }}-npm-cache
      - name: Install Dependencies
        run: npm install
      - name: Build
        run: npm run build
      - name: Upload Pages artifact
        uses: actions/upload-pages-artifact@v2
        with:
          path: ./public
  deploy:
    needs: build
    permissions:
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v2
```

添加 CNAME 文件 在/source文件夹下，内容为你的域名，例如：
```CNAME
petalzu.top #替换为你的域名
```

检查 https://<你的 GitHub 用户名>.github.io 或 https://<你的域名> 是否已经部署成功。

## Cloudflare CDN 加速访问和保护网站
需要域名

### Cloudflare 解析
将域名导入cloudflare，设置DNS解析，并在域名供应商处修改DNS服务器为cloudflare提供的DNS服务器。

配置 DNSSEC，勾选其他cloudflare提供的安全选项。

### Cloudflare WAF 配置
#### 严格配置
创建如下规则，并对表达式或选项进行如下配置：

<div style="text-align: center;">
  <img src="/images/page/1.webp" alt="配置" width="50%">
</div>
&nbsp;

放行爬虫
```放行爬虫
(cf.client.bot) or (cf.verified_bot_category eq "Search Engine Crawler") or (cf.verified_bot_category eq "Monitoring & Analytics") or (cf.verified_bot_category eq "Page Preview") or (cf.verified_bot_category eq "Advertising & Marketing")
```
选择操作：跳过 所有其余自定义规则

&nbsp;
质询
```质询
(http.host eq "你的域名") or (http.host eq "你的子域名")
```
选择操作：交互式质询

#### 较为宽松的配置
严格配置会带来很多问题，最明显的就是访问网站的速度变慢，需要用户操作，所以可以使用更加用户友好的托管质询。
托管质询可以自动判断是使用JS质询还是交互式质询，这几种质询方式的区别可以参照[Cloudflare五秒盾、JS质询、托管质询以及交互式质询的区别](https://lot.pm/cloudflare-challenge.html)。
为了进一步防止隐患，可以规定更多的规则。

（实际上，JS质询也会占用不小的时间）


##### WAF规则

&nbsp;
质询
```质询
(http.host eq "你的域名") or (http.host eq "你的子域名")
```
选择操作：托管质询

&nbsp;
防恶意爬虫
```防恶意爬虫
(not cf.client.bot and not ip.geoip.country in {"CN" "HK" "JP" "MO" "SG" "TW" "US"}) or (cf.threat_score ge 5) or (not http.user_agent contains "Mozilla/") or (not http.request.version in {"HTTP/2" "HTTP/3" "SPDY/3.1"})
```
选择操作：阻止

&nbsp;
阻止页面内容爬取
```阻止页面内容爬取
(http.request.uri.path contains ".php")
```
选择操作：阻止

##### 速率限制规则

&nbsp;
速率限制
```速率限制
(http.request.uri.path contains "/")
```
当速率超过 *100* 每 *10秒钟*

选择操作：阻止 - 默认 Cloudflare 速率相应限制

##### HTTP DDoS 攻击防护

&nbsp;
替代名称：ddos

规则操作集：阻止

规则集敏感度：高


## 其他
### 问题

- 在hexo server中显示标签/分类/文章数目混乱，以及出现已删除的页面的情况，关闭server并使用如下命令：
```bash
$ hexo clean
```

- 如果启用了 all_minifier: true，可能会遇到以下问题：  
```bash
FATAL Something's wrong. Maybe you can find the solution here: https://hexo.io/docs/troubleshooting.html
Error: write EOF
    at WriteWrap.onWriteComplete [as oncomplete] (node:internal/stream_base_commons:94:16)
```
暂时只能通过关闭图像压缩解决：
```bash
all_minifier: false
```

- 如果 excerpt 为空，会出现以下报错
```bash
ERROR Process failed:
ValidationError: `null` is not a string!
```

- [Cloudflare SSL边缘证书全部备份的解决方法 同为 ERR_SSL_VERSION_OR_CIPHER_MISMATCH 问题的解决方法](https://petalzu.top/2024/07/24/cloudflare/)

### 建议

除有必要，否则不推荐一键部署

## 参考文档
[在 GitHub Pages 上部署 Hexo](https://hexo.io/zh-cn/docs/github-pages)  
[配置CloudFlare WAF强制交互式质询让你的网站稳如泰山](https://sharpgan.com/using-cloudflare-waf-to-protect-your-website/)  
[简单操作让你的网站不受恶意流量恶意爬虫威胁！Cloudflare防火墙部署指南](https://blog.csdn.net/qq_73142349/article/details/134252695)  
[Cloudflare五秒盾、JS质询、托管质询以及交互式质询的区别](https://lot.pm/cloudflare-challenge.html)  
[Getting Started with Icarus](https://ppoffice.github.io/hexo-theme-icarus/uncategorized/getting-started-with-icarus/)  
