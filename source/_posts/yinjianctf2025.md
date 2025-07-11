---
title: 2025 阴间CTF WriteUp
date: 2025-07-11 20:17:00
updated: 2025-07-11 20:17:00
tags: [CTF, 阴间CTF]
categories: [笔记]
thumbnail: /images/ctf/yinjianctf2025/1.webp
cover: /images/ctf/yinjianctf2025/1.webp
toc: true
---

是时候来赚取阴间的财富了……（雾）

<!-- more -->

## 阴曹地府税务总局

flag：容器没了无法复现。

根据时间戳碰撞到随机数序列，得到后续随机数。

```python
#!/usr/bin/env python3
from pwn import remote, log
import re, time, random

HOST = "nc1.ctfplus.cn"
PORT = 47775

p = remote(HOST, PORT)

banner = p.recvuntil("要贿赂工作人员吗？(y/n):")
log.info("收到欢迎信息:")
log.info(banner.decode(errors="ignore"))

p.sendline("y")
log.info("发送贿赂选项: y")

data = p.recvuntil("==== 第1轮交易 ====")
log.info("收到税率历史数据:")
log.info(data.decode(errors="ignore"))

rates = re.findall(r"第\d+轮交易税率:\s*(\d+)%", data.decode())
if len(rates) < 10:
    log.error("未提取到10个税率记录，退出")
    exit(1)
history = list(map(int, rates))
log.success("提取到的税率记录: {}".format(history))

prompt = p.recvuntil("要进行烧纸交易吗？(y/n):")
log.info("收到交易提示:")
log.info(prompt.decode(errors="ignore"))

# --- 利用历史数据恢复随机数种子 ---
# 思路：服务用标准时间戳（秒）作为种子，
# 并且在你来之前已经调用了 5~15 次 random.randint(0,99)（交易轮次前置调用），
# 然后连续 10 次产生的数构成了税率历史记录。

local_time = int(time.time())
found_seed = None
found_offset = None

search_ranges = [
    (local_time - 5, local_time + 5),  # 先搜索最可能的时间窗口
    (local_time - 30, local_time - 5),  # 再搜索更早的时间
    (local_time + 5, local_time + 30)   # 最后搜索更晚的时间
]

for start, end in search_ranges:
    log.info(f"搜索时间范围 {start} 到 {end}")
    for s in range(start, end):
        for off in range(5, 16):
            random.seed(s)
            for _ in range(off):
                random.randint(0, 99)
            sim = [random.randint(0, 99) for _ in range(10)]
            if sim == history:
                found_seed = s
                found_offset = off
                log.success(f"找到匹配! 种子: {s}, 偏移量: {off}")
                break
        if found_seed is not None:
            break
    if found_seed is not None:
        break

if found_seed is None:
    log.error("种子恢复失败，尝试扩大搜索范围")
    exit(1)
    
log.success("恢复到种子: {} (跳过调用次数: {})".format(found_seed, found_offset))

# 经过恢复，随机生成器状态：已耗掉（found_offset + 10）次 randint 调用，
# 接下来每次调用的结果就是下一次交易的税率 n。
random.seed(found_seed)
for _ in range(found_offset + 10):
    random.randint(0, 99)

balance = 1000
log.info("初始账户余额: {}".format(balance))

while True:
    log.info("收到交易交互提示")
    
    n = random.randint(0, 99)
    log.info("预测税率： {}%".format(n))

    p.sendline("y")
    log.info("发送交易确认: y")

    try:
        prompt_rate = p.recvuntil("您预测的当前税率是(0-99%):", timeout=5)
        log.info("收到税率输入提示: " + prompt_rate.decode(errors="ignore").strip())
    except Exception as e:
        log.warning("读取税率输入提示超时")
        continue

    p.sendline(str(n))
    log.info("发送预测税率: {}".format(n))

    try:
        trade_resp = p.recvline(timeout=5)
        log.info("交易反馈: " + trade_resp.decode(errors="ignore").strip())

        balance_resp = p.recvline(timeout=3)
        log.info("余额信息: " + balance_resp.decode(errors="ignore").strip())

        balance_match = re.search(r"余额[:：]\s*(\d+)", balance_resp.decode(errors="ignore"))
        if balance_match:
            balance = int(balance_match.group(1))
            log.success(f"从服务端获取余额: {balance}")
        else:
            gain = 500
            balance += gain
            log.info("模拟账户余额更新: 当前余额 = {}".format(balance))
    except Exception as e:
        log.warning(f"读取交易结果超时: {e}")
        gain = 500
        balance += gain
        log.info("模拟账户余额更新: 当前余额 = {}".format(balance))

    target = 10000
    if balance >= target:
        log.success(f"达到目标! 当前余额 {balance} >= 目标 {target}")
        break

    try:
        all_data = p.recv(timeout=1)
        log.info("收到所有数据: " + all_data.decode(errors="ignore").strip())
    except Exception as e:
        log.warning("读取所有数据超时")

final_output = p.recvall(timeout=5)
log.success("最终返回数据:")
print(final_output.decode(errors="ignore"))

p.close()
```


<div STYLE="page-break-after: always;"></div>

## FiveElementColorFlood

flag：geesec{vniq15sdanub-3a8b26aee5-oJQjpShVldkteWGV}

题解：

第一段flag1在靶机/etc/flag1，发现最后一个链接可以用来获取文件，第一段flag是 vniq15sdanub

![FiveElementColorFlood](/images/ctf/yinjianctf2025/2.webp)

观察app.js，发现

![app.js](/images/ctf/yinjianctf2025/3.webp)

尝试在控制台手动调用该函数

![app.js](/images/ctf/yinjianctf2025/4.webp)

成功

![app.js](/images/ctf/yinjianctf2025/5.webp)

那么接下来就是伪造通关数据。

调用saveUserdata(10000,1000)

![app.js](/images/ctf/yinjianctf2025/6.webp)

成功

![app.js](/images/ctf/yinjianctf2025/7.webp)

获得到第二段flag为 3a8b26aee5

最后一段 ghidra 分析 game.wasm

![逆向](/images/ctf/yinjianctf2025/8.webp)

发现 q1wd556qw1566351

![逆向](/images/ctf/yinjianctf2025/9.webp)

![逆向](/images/ctf/yinjianctf2025/10.webp)

0x5F797274 0x64726168

71317764 35353671 77313536 36333531

魔改tea：异或 lVar6 + V1 + 0x6675636b（即sum+）异或两次，等于没异或。再加上cbc加密

![逆向](/images/ctf/yinjianctf2025/11.webp)

原始数据

![逆向](/images/ctf/yinjianctf2025/12.webp)

最后循环异或

![逆向](/images/ctf/yinjianctf2025/13.webp)

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define DELTA 0x6675636b
#define ROUNDS 32

// TEA 加密
void tea_encrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    for (int i = 0; i < ROUNDS; i++) {
        sum += DELTA;
        v0 += ((v1 << 4) + k[0]) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0;
    v[1] = v1;
}

// TEA 解密
void tea_decrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = DELTA * ROUNDS;
    for (int i = 0; i < ROUNDS; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ ((v1 >> 5) + k[1]);
        sum -= DELTA;
    }
    v[0] = v0;
    v[1] = v1;
}

// CBC模式加密
void tea_cbc_encrypt(uint32_t* data, size_t len, uint32_t* key, uint32_t* iv) {
    uint32_t prev[2] = {iv[0], iv[1]};
    for (size_t i = 0; i < len; i += 2) {
        data[i] ^= prev[0];
        data[i + 1] ^= prev[1];

        tea_encrypt(&data[i], key);

        prev[0] = data[i];
        prev[1] = data[i + 1];
    }
}

// CBC模式解密
void tea_cbc_decrypt(uint32_t* data, size_t len, uint32_t* key, uint32_t* iv) {
    uint32_t prev[2] = {iv[0], iv[1]}, temp[2];
    for (size_t i = 0; i < len; i += 2) {
        temp[0] = data[i];
        temp[1] = data[i + 1];

        tea_decrypt(&data[i], key);

        data[i] ^= prev[0];
        data[i + 1] ^= prev[1];

        prev[0] = temp[0];
        prev[1] = temp[1];
    }
}

int main() {
    uint32_t key[4] = {0x71317764, 0x35353671, 0x77313536, 0x36333531};
    uint32_t iv[2] = {0x5F797274, 0x64726168};

    uint32_t data[] = {0x040AF3BD, 0x688CB776, 0x36252D96, 0xCA62A341};
    size_t len = sizeof(data) / sizeof(data[0]);

    printf("原始数据: ");
    for (size_t i = 0; i < len; i++) printf("%.8x ", data[i]);
    printf("\n");

    tea_cbc_decrypt(data, len, key, iv);
    printf("解密后数据: ");
    for (size_t i = 0; i < len; i++) printf("%.8x ", data[i]);
    printf("\n");

    uint8_t ivv[16] = {0x25, 0x1B, 0x3B, 0x1A, 0x23, 0x3B, 0x3E, 0x3A, 0x08, 0x0F, 0x1F, 0x11, 0x32, 0x10, 0x11, 0x73};
    char xorValue = ivv[0];

    for (int i = 0; i < 16; i++) {
        ivv[15 - i] ^= xorValue;
        xorValue = ivv[15 - i];
    }

    printf("还原数据: ");
    for (int i = 0; i < 16; i++) {
        printf("%.2x ", ivv[i] & 0xff);
    }
    printf("\n"); // 输出处理后数据 oJQjpShVldkteWGV

    return 0;
}

```

验证

![验证](/images/ctf/yinjianctf2025/14.webp)

<div STYLE="page-break-after: always;"></div>


## 总结

ID： NeuroSama

![结果](/images/ctf/yinjianctf2025/15.webp)

赛博比赛给赛博人烧赛博纸……

最后烧给牛肉了，也不知道英国那边地府能不能换外汇，提前攒点钱。

