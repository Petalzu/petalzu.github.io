---
title: 2024 NepCTF WriteUp
date: 2024-08-27 09:44:23
updated: 2024-08-27 09:44:23
tags: [CTF, NepCTF]
categories: [笔记]
thumbnail: /images/ctf/nepctf2024/1.webp
cover: /images/ctf/nepctf2024/1.webp
toc: true
---

相较于往年，今年出题师傅们为大家精心准备了 「Game」 类型的游戏赛题，融入到各个方向当中，来打一场有关网络安全的游戏吧！
<!-- more -->
所以我真的是来玩游戏（

## Misc
### NepMagic —— CheckIn
*玩，需要用到耐心*

- 解题思路：正常玩通关即可。
- flag：NepCTF{50c505f4-2700-11ef-ad49-00155d5e2505}
- 通关截图：<img src="/images/ctf/nepctf2024/2.webp" alt="通关截图" width="50%">
- 碎碎念：黑神话悟空的强力对手，IGN评分⑨.⑨，TGA年度最佳预定。后续会出dlc吗？
<div STYLE="page-break-after: always;"></div>


### 3DNep
*玩，需要用到求知*

- 解题思路：在下载下来的3d建模的底部有一个二维码，搜索鉴定为汉信码。
- 参考：https://www.qrcode-tiger.com/zh-cn/different-types-of-qr-codes
- flag：NepCTF{6e766b59-23d1-395c26d708a4}
- 通关截图：<img src="/images/ctf/nepctf2024/3.webp" alt="通关截图" width="50%">
- 碎碎念：把你nepnep掉！


<div STYLE="page-break-after: always;"></div>

### NepCamera
*玩，需要用到角膜*

- 解题思路：发现jfif文件头，提取出来，文件头有1313个，尾233个，没有遇到尾自动补全。然后用消失的眼角膜看出来一千张图中滚动的flag。
- flag：flag{Th3_c4mer4_takes_c1ear_pictures}
- 通关截图：<img src="/images/ctf/nepctf2024/4.webp" alt="通关截图" width="50%"><img src="/images/ctf/nepctf2024/5.webp" alt="通关截图" width="50%"><img src="/images/ctf/nepctf2024/6.webp" alt="通关截图" width="50%"><img src="/images/ctf/nepctf2024/7.webp" alt="通关截图" width="50%">
- 碎碎念：请选择你的拍屏教派。

脚本如下
```python
import os

def extract_jpegs_from_pcapng(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    start_marker = b'\xFF\xD8\xFF'
    end_marker = b'\xFF\xD9'
    jpeg_count = 0
    current_jpeg = bytearray()
    recording = False

    i = 0
    while i < len(data):
        if data[i:i+3] == start_marker:
            if recording:
                # Save the current JPEG with an added end marker
                current_jpeg.extend(end_marker)
                save_jpeg(current_jpeg, jpeg_count)
                jpeg_count += 1
                current_jpeg = bytearray()
            recording = True
            current_jpeg.extend(start_marker)
            i += 3
        elif recording:
            if data[i:i+2] == end_marker:
                current_jpeg.extend(end_marker)
                save_jpeg(current_jpeg, jpeg_count)
                jpeg_count += 1
                current_jpeg = bytearray()
                recording = False
                i += 2
            else:
                current_jpeg.append(data[i])
                i += 1
        else:
            i += 1

    # If still recording at the end of the file, save the last JPEG
    if recording:
        current_jpeg.extend(end_marker)
        save_jpeg(current_jpeg, jpeg_count)

def save_jpeg(jpeg_data, count):
    file_name = f'image_{count}.webp'
    with open(file_name, 'wb') as f:
        f.write(jpeg_data)
    print(f'Saved {file_name}')

if __name__ == "__main__":
    extract_jpegs_from_pcapng('NepCamera.pcapng')


```
<div STYLE="page-break-after: always;"></div>

### DCTris Evolved
*玩，需要用到肝肾*

- 解题思路：玩一晚上通关，发现提示flag在vmu里。通过查wiki得知vmu是一种显示设备。模拟器设置里打开show in vmu，看左上角滚动的flag。
- flag：NepCTF{Celebrating...Tetris_40TH_Anniversary!}
- 通关截图：<img src="/images/ctf/nepctf2024/8.webp" alt="通关截图" width="50%">
- 碎碎念：玩着玩着安详地睡着了。

<div STYLE="page-break-after: always;"></div>

## Reverse

### Super Neuro : Escape from Flame!
*玩，需要用到里技*
- 解题思路：随机到边缘跳板少的，宏绑定space + 50ms 贴墙开启飞升之路。
- flag：NepCTF{d433dfc5339ff746f6c1f8c5472bac18e4d65f2f0fb1a9d5}
- 通关截图：<img src="/images/ctf/nepctf2024/9.webp" alt="通关截图" width="50%">
- 碎碎念：并非取消。跳跃游戏偶遇neuro，连跳吸附强如怪物，拼尽全力无法战胜。



<div STYLE="page-break-after: always;"></div>


# 总结
ID： Neur0_5ama

非常好比赛，非常好题目，但是感觉自己除了玩游戏什么都没做（躺

前有学习，因此接下来时间很重要。



