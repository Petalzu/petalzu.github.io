---
title: 2023 Hackergame WriteUp
date: 2024-01-31 15:00:01
updated: 2024-11-09 14:24:50
tags: [CTF,Hackergame]
categories: [笔记]
thumbnail: /images/ctf/hackergame2023/title.webp
cover: /images/ctf/hackergame2023/title.webp
toc: true
---

总结一下参与[2023 Hackergame](https://hack.lug.ustc.edu.cn/)的一些题目的WriteUp。本来早该写来着，结果因为换博客框架一直拖到现在，算是补档了，rip。
<!-- more -->

## Hackergame 启动
此题判定和音频无关，就算提交了一段空音频准确大概也是七十左右。

<div style="text-align: center;">
  <img src="/images/ctf/hackergame2023/2.webp" alt="hackgame" width="50%">
</div>
提交完成后发现url上多了一个 ?similarity=75.55609410192203 的判定，将其修改为100则可以得到flag。

<div style="text-align: center;">
  <img src="/images/ctf/hackergame2023/2.webp" alt="hackgame" width="50%">
</div>
## 猫咪小测
一些问答题，在网上花点时间就能找到。

想要借阅世界图书出版公司出版的《A Classical Introduction To Modern Number Theory 2nd ed.》，应当前往中国科学技术大学西区图书馆的哪一层？  
[相关链接](https://lib.ustc.edu.cn/)

今年 arXiv 网站的天体物理版块上有人发表了一篇关于「可观测宇宙中的鸡的密度上限」的论文，请问论文中作者计算出的鸡密度函数的上限为 10 的多少次方每立方秒差距？  
[相关链接](https://arxiv.org/abs/2303.17626)

为了支持 TCP BBR 拥塞控制算法，在编译 Linux 内核时应该配置好哪一条内核选项？  
[相关链接](https://cateee.net/lkddb/web-lkddb/TCP_CONG_BBR.html)

「我……从没觉得写类型标注有意思过」。在一篇论文中，作者给出了能够让 Python 的类型检查器 MyPY mypy 陷入死循环的代码，并证明 Python 的类型检查和停机问题一样困难。请问这篇论文发表在今年的哪个学术会议上？  
[相关链接](https://arxiv.org/abs/2208.14755)

## 更深更暗
快速往下拖拽网页即可看到潜艇，录屏就能保留flag。
<div style="text-align: center;">
  <img src="/images/ctf/hackergame2023/3.webp" alt="hackgame" style="width: 50%;">
</div>

## 旅行照片 3.0
需要综合搜索信息的题目，根据题目提示寻找一些实验室/活动的网站，通过google地图查询即可得到信息。

一个很有趣的题目，仅仅通过侧面信息就能判断一个人的行程，也许是想提示大家信息安全的重要性。

## 赛博井字棋

正常下是过不了滴，看一下前端是否能有绕过判定的方式。

打开网络请求发现，每次下棋都会向服务器发送一个post请求，包含下棋的 x y 位置，服务器会返回经计算后的棋盘。因此只需要在浏览器中修改post请求的参数，一次性发送两个位置的post就可以了。

<div style="text-align: center;">
  <img src="/images/ctf/hackergame2023/4.webp" alt="hackgame" width="50%">
</div>

## 奶奶的睡前 flag 故事
从图片中找到flag的方式，发现不是简单的图片隐写。通过查看010editor发现，这张图是一个截图，裁剪去了一半，但是仍然保留了下半的数据。尝试一般的恢复方法没有作用。

再通过题意分析，应该是关于截图的bug，正好发现了最近关于windows截图的一个bug信息[Windows 11 截图工具隐私错误暴露裁剪的图像内容](https://zhuanlan.zhihu.com/p/616249684)

从一些国外新闻的报道还有工程师发的推文中，可以找到一个在线恢复照片的网站[acropalypse](https://acropalypse.app/)，逐一尝试即可获得被截取的下半部分照片。

## 组委会模拟器
此题目F12分析，发现在开启时会发送一个 getMessages 的 POST 请求，其中 text 和发送的 delay 都以 json 格式保留；当我们点击消息撤回时，会发送一个 deleteMessage 的 POST 请求。

据此我们可以构造一个脚本来筛选特定的 text ，并在 delay 后一点时间发送一个 POST 请求删除需要撤回的文本，代码如下。

```python
import requests
import json
import re
from time import sleep
from threading import Timer

# 从 http://202.38.93.111:10021/api/getMessages 请求数据，auth(bearer token)为 750:MEQCIFFCYIZkMZQCFQFn6wmDSXdZDDpI6Kvnec8uZoLZS5SqAiABa+jvJdqQxyGQcuHernJ3ej9ze2tLRabegfWl2doxlQ==，将获得的数据保存为json格式
# 登录该页面，输入bearer token，点submit，获得数据

url = "http://202.38.93.111:10021/api/getMessages"

headers = {
    "Host": "202.38.93.111:10021",
    "Connection": "keep-alive",
    "Content-Length": "0",
    "Accept": "application/json, text/plain, */*",
    "Origin": "http://202.38.93.111:10021",
    "User-Agent": "Mozilla/5.0 (Linux; Android 8.1.0; MI 8 Build/OPM1.171019.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Mobile Safari/537.36",
    "Content-Type": "application/json;charset=UTF-8",
    "Referer": "http://202.38.93.111:10021/",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Cookie": "",
}

response = requests.post(url, headers=headers, data={})
json_data = json.loads(response.text)
json_data = json_data["messages"]
# 处理json数据，将每个{}中的数据，delay作为time，如果识别text中有hack[*]，*为通配符，则向http://202.38.93.111:10021/api/deleteMessage 发送请求，删除该条数据，负载为{"id":index},index为该条数据在json中的位置
lst = []
timepast = 0
for i in range(0, len(json_data)):
    time = float(json_data[i]["delay"])
    # time = time - timepast
    timepast = float(json_data[i]["delay"])
    text = json_data[i]["text"]
    if re.search("hack\[", text):
        lst.append([time, i])
    else:
        pass

urls = "http://202.38.93.111:10021/api/deleteMessage"


# 从0s开始执行，将lst中的数据，到达time秒向urls发送请求，内容是{"id":index}
def posted(url, index):
    print(index)
    res = requests.post(url, headers=headers, data=json.dumps({"id": index}))
    print(res.text)

for i in range(0, len(lst)):
    Timer(lst[i][0], posted, (urls, lst[i][1])).start()

flag = requests.post(url="http://202.38.93.111:10021/api/getflag", headers=headers)
print(flag)
print(flag.text)
```

即可得到flag。此题应该注意 delay 的时间，调整了数次才将延迟设置到合适的范围（如果提前撤回了未发送的信息则会error）。

## 虫
使用au等软件打开下载下来的音频，发现并没有规律，因此不是一般的音频隐写方式。

通过题意，该音频应该是传输信号使用的，有没有什么办法将音频信息转为图片呢？

答案是有的，是MMSSTV：[用MMSSTV发送和接收图片](https://zhuanlan.zhihu.com/p/105460358)。慢扫描电视（Slow-scan television）是业余无线电爱好者的一种主要图片传输方法，慢扫描电视通过无线电传输和接收单色或彩色静态图片。正好对应题目信息。

使用音频慢扫（此处可能要用到内置麦克风软件，将播放的音频直接输入到内置麦克风中，避免杂音），得到flag。

<img src="/images/ctf/hackergame2023/5.webp" alt="hackgame" width="50%">

## JSON ⊂ YAML?
此题是找 json 能够解析但是 yaml 无法解析的格式。通过查询 yaml 的更新日志，寻找 yaml 1.1 和 yaml 1.2 修复的内容以及规范定义。

首先 yaml 1.1 的比较简单，一用e就可以解决，因为 yaml 1.1 没有规范没有小数点的小数。

然后就是 yaml 1.2 ，找这个确实比较麻烦，最终在 [yaml 1.2](https://yaml.org/spec/1.2.2/)找到其 key 值不能重复。使用重复的 key 比如输入 {"":1,"":2} 即可。

## Git? Git!
此题和git使用强相关，下载下来代码后使用git bash查看最后一次提交，退回此提交即可回溯文件。查看 README.md 发现flag。

## HTTP 集邮册
5个简单的状态码

200 OK. 点击就送，代表请求成功。
```bash
GET / HTTP/1.1\r\n
Host: example.com\r\n\r\n
```
404 Not Found. 修改路径到一个不存在的文件即可。
```bash
GET /example HTTP/1.1\r\n
Host: example.com\r\n\r\n
```
400 Bad Request. 构造不符合格式的 HTTP 请求即可。
```bash
GET / abcd/1.1\r\n
Host: example.com\r\n\r\n
```
505 HTTP Version Not Supported. 修改 HTTP 版本号。
```bash
GET / HTTP/114514\r\n
Host: example.com\r\n\r\n
```
405 Method Not Allowed. 修改请求方法即可。
```bash
POST / HTTP/1.1\r\n
Host: example.com\r\n\r\n
```
无状态码，删除请求格式内容即可。
```bash
GET /\r\n
Host: example.com\r\n\r\n
```

其他请参考[HTTP 集邮册题解](https://github.com/USTC-Hackergame/hackergame2023-writeups/blob/master/official/HTTP%20%E9%9B%86%E9%82%AE%E5%86%8C/README.md)


## Docker for Everyone
这道题用docker把flag所在目录挂载到容器中，然后通过容器来读取flag即可。

## 惜字如金
该题根据题意和下发的程序，推测输出字符的位置来获得flag即可。
```python
#!/usr/bin/python3

# Th siz of th fil may reduc after XZRJification

def check_equals(left, right):
    # check whether left == right or not
    if left != right:
        pass

def get_cod_dict():
    # prepar th cod dict
    cod_dict = []
    cod_dict += ['nymeh1niwemflcir}echaetA']
    cod_dict += ['a3g7}kidgojernoetlsup?hA']
    cod_dict += ['Aulw!f5soadrhwnrsnstnoeq']
    cod_dict += ['Act{l-findiehaai{oveatas']
    cod_dict += ['Aty9kxborszstguyd?!blm-p']
    print(set(len(s) for s in cod_dict))
    check_equals(set(len(s) for s in cod_dict), {24})
    return ''.join(cod_dict)

def decrypt_data(input_codes):
    # retriev th decrypted data
    cod_dict = get_cod_dict()
    output_chars = [cod_dict[c] for c in input_codes]
    return ''.join(output_chars)

if __name__ == '__main__':
    # check som obvious things
    check_equals('creat', 'cr' + 'at')
    check_equals('referer', 'refer' + 'rer')
    # check th flag
    flag = decrypt_data([53, 41, 85, 109, 75, 1, 33, 48, 77, 90,
                         17, 118, 36, 25, 13, 89, 90, 3, 63, 25,
                         31, 77, 27, 60, 3, 118, 24, 62, 54, 61,
                         25, 63, 77, 36, 5, 32, 60, 67, 113, 28])
    #check_equals(flag.index('flag{'), 0)
    #check_equals(flag.index('}'), len(flag) - 1)
    # print th flag
    print(flag)


```

此题需要结合一定猜测，比如这时候程序输出为 flag{yoA-ve-r3cover3d-7he-an5w3r-r1ght?}，易得第一个单词应为you。


## 高频率星球

首先需要通过题目给的信息，使用 asciinema cat 得到终端字节流，将其输入到一个js文件中。

然后使用脚本去除无关的字符
```python
#去除flag.js中指定的字符，比如
import re
import os

def remove_flag_js():
    with open('flag.js','r') as f:
        data = f.read()
    data = re.sub(r'[KESC','',data)
    with open('flag.js','w') as f:
        f.write(data)

if __name__ == '__main__':
    remove_flag_js()
```
最后得到flag.js源文件，使用nodejs运行即可得到flag。

## 异星歧途
该题使用 Mindustry 地图，其中有汇编代码，通过条件判断该打开哪些按钮。

一共32个，如果时间充裕随便玩玩也能试出来。

## 总结
比赛id： Neur0_5ama

分数：3050， 总排名：218 / 2381

这次做出来的基本上都是一些比较简单的题目，更困难的题只能眠了，总的来说是很棒的比赛。

一些内容引用 [Hackergame 2023 官方writeup](https://github.com/USTC-Hackergame/hackergame2023-writeups)，对更多题目题解感兴趣的朋友可以看看。