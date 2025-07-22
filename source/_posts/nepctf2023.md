---
title: 2023 NepCTF WriteUp
date: 2023-08-13 19:30:02
updated: 2024-08-27 09:25:31
tags: [CTF, NepCTF]
categories: [笔记]
toc: true
---
此文是2023年NepCTF的WriteUp，包含了部分题目的解答。
<!-- more -->
## Codes
写个c程序  
使用##躲开关键词检测  

```c
#include<stdio.h>
#include<stdlib.h>
#define e_n_v_p e##n##v##p
int main(int argc, char **argv, char** e_n_v_p)
{
    char** ev;
    for (ev = e_n_v_p; *ev != 0; ev++)
    {
        char* thisv = *ev;
        printf("%s\n", thisv);
    }
}
```

<img src="/images/ctf/nepctf2023/1.webp" alt="neuro" width="50%">

## 与AI共舞的哈夫曼
补全函数

```python
def decompress(input_file, output_file):
    with open(input_file, 'rb') as f:
        data = f.read()

    # Read frequency information
    frequencies = {}
    num_of_chars = data[0]
    index = 1
    for i in range(num_of_chars):
        byte = data[index]
        index += 1
        freq = (data[index] << 24) | (data[index+1] << 16) | (data[index+2] << 8) | data[index+3]
        index += 4
        frequencies[byte] = freq

    root = build_huffman_tree(frequencies)
    current_node = root
    decompressed_data = ''

    # Read compressed data
    for byte in data[index:]:
        byte = bin(byte)[2:].rjust(8, '0')
        for bit in byte:
            if bit == '0':
                current_node = current_node.left
            else:
                current_node = current_node.right
            if current_node.char is not None:
                decompressed_data += chr(current_node.char)
                current_node = root

    padding = 0
    for i in range(len(decompressed_data)-1, -1, -1):
        if decompressed_data[i] == '\x00':
            padding += 1
        else:
            break

decompressed_data = decompressed_data[:len(decompressed_data)-padding]
with open(output_file, 'wb') as f:
f.write(decompressed_data.encode())
# 解压缩文件
decompress(compressed_file, decompressed_file)
```

在decompressed.txt 中

<img src="/images/ctf/nepctf2023/2.webp" alt="neuro" width="50%">

## ConnectedFive
喜欢下万宁五子棋导致的

<img src="/images/ctf/nepctf2023/3.webp" alt="neuro" width="50%">

## CheckIn
给 b 站账号 Nepnep 网络安全发送**nepctf2023"，看看她会不会说出 flag  
NepCTF{H4ve_Fun_1N_This_Game}

## 小叮弹钢琴
打开mid，前面是摩尔斯电码，后面横着看是十六进制数

<img src="/images/ctf/nepctf2023/4.webp" alt="neuro" width="50%">

Y O U S H O U L D U S E T H I S  
T O X O R S O M E T H I N G

可得异或运算

<img src="/images/ctf/nepctf2023/5.webp" alt="neuro" width="50%">

<img src="/images/ctf/nepctf2023/6.webp" alt="neuro" width="50%">

