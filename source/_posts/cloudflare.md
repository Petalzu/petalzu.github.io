---
title: Cloudflare 边缘证书全部备份的解决方法
date: 2024-07-24 14:28:13
updated: 2024-07-24 14:28:13
tags: [cloudflare, 边缘证书, ssl,GitHub Pages]
categories: [笔记]
toc: true
---
同为 ERR_SSL_VERSION_OR_CIPHER_MISMATCH 问题的解决方法。
<!-- more -->
## 背景
网站配置：GitHub Pages + Cloudflare CDN + 自定义域名

最近遇到了一个问题，起因是网站的ssl证书到期了，cloudflare一连发了好几份邮件提醒我修改，但我一直没有处理。直到最近，我发现网站访问出现了问题，因此想着处理一下证书的问题。

<div style="text-align: center;">
  <img src="/images/cloudflare/1.webp" alt="cloudflare的提示邮件" style="width: 50%;">
</div>
&nbsp;

但是我授权多次后，发现证书的类型一直属于备份，并且无法自动部署。按照一般流程来说，应该是会有提示部署TXT验证，并且至少有一个ssl证书会处于“待验证”的状态。然而，它们全都是“备份已发放”的状态。

<div style="text-align: center;">
  <img src="/images/cloudflare/2.webp" alt="证书状态异常" style="width: 50%;">
</div>
&nbsp;

## 尝试
因此我尝试着手解决这个问题，首先我尝试了关闭边缘认证，等待一两分钟后再次开启。

<div style="text-align: center;">
  <img src="/images/cloudflare/3.webp" alt="边缘认证开关选项" style="width: 50%;">
</div>
&nbsp;
<div style="text-align: center;">
  <img src="/images/cloudflare/4.webp" alt="证书透明度监视" style="width: 50%;">
</div>
&nbsp;

发现确实多了一个GTS(Google Trust Services)的证书，我尝试部署了它。因为之前开启了证书透明度监视，我确实收到了证书部署成功的邮件。

<div style="text-align: center;">
  <img src="/images/cloudflare/5.webp" alt="成功部署的邮件" style="width: 50%;">
</div>
&nbsp;

然而过了一段时间，GTS的证书又跳出了新的TXT验证，并且我的网站仍然处于 ERR_SSL_VERSION_OR_CIPHER_MISMATCH 的错误状态，抓包流量显示是握手错误，说明证书配置还是有问题。

<div style="text-align: center;">
  <img src="/images/cloudflare/6.webp" alt="Handshake Failure" style="width: 50%;">
</div>
&nbsp;

一开始以为是等待时间的问题，因此等了一天左右，发现还是没有成功。

<div style="text-align: center;">
  <img src="/images/cloudflare/7.webp" alt="为什么我的ACME客户端启动时间应当随机？" style="width: 50%;">
</div>
&nbsp;

然而这段时间我马上要打ciscn决赛，因此暂时放弃了，也导致网站又非预期地挂了好几天，不能正常访问。期间还试过将dns解析迁移回腾讯云（购买域名的地方），以及修改一些其他的设置，修改Github Pages的一些设置等。

<div style="text-align: center;">
  <img src="/images/cloudflare/8.webp" alt="在腾讯云上仍然有问题" style="width: 50%;">
</div>
&nbsp;

## 解决方法
一度认为这个问题没办法解决了，后来发现了这么一篇文章：[Cloudflare 免费版自定义切换边缘证书](https://zikin.org/cloudflare-set-edge-cert/)，想到有可能是证书颁发机构的问题，因此我尝试了一下，将证书通过API（免费版只能通过API切换）换成了Let’s Encrypt的证书。

Cloudflare 用来执行这个操作的 API 是 https://api.cloudflare.com/client/v4/zones/<ZoneID>/ssl/universal/settings ，请求方式是 curl，所以可以通过 curl 下面这个 url 来更换证书
```bash
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/<ZoneID>/ssl/universal/settings" \
     -H "X-Auth-Email: <Cloudflare Email>" \
     -H "X-Auth-Key: <Global API Key>" \
     -H "Content-Type: application/json" \
     --data '{"enabled":true,"certificate_authority":"google"}'
```

其中

- <ZoneID> 为 Cloudflare 控制台某个域名的 Overview (总览) 页面显示的 「API Zone ID」
- <Cloudflare Email> 为注册 Cloudflare 的邮箱
- <Global API Key> 在 [这里](https://dash.cloudflare.com/profile/api-tokens) 查询
- "google" 字段代表签发 GTS 证书，如果需要另外两个 CA 的证书可以分别改为 "digicert" / "lets_encrypt"

如果返回以下字段则代表已经更改成功（类似的，使用lets_encrypt时候会返回"certificate_authority":"lets_encrypt"）

```bash
{"result":{"enabled":true,"certificate_authority":"google"},"success":true,"errors":[],"messages":[]}
```


<div style="text-align: center;"> <img src="/images/cloudflare/9.webp" alt="成功部署lets_encrypt的证书" style="width: 50%;"> </div> &nbsp;

最终通过在dns添加TXT记录，成功部署了Let’s Encrypt的证书，网站恢复正常访问。

## 参考链接
更多使用问题：[Face the fear, create the future.](https://petalzu.top/2024/01/18/page/)
[Cloudflare 免费版自定义切换边缘证书](https://zikin.org/cloudflare-set-edge-cert/)

一并感谢我的好友 ThTsOd 的帮助。