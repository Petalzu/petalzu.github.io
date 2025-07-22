---
title: Raspberry Pi 4B 折腾记录
date: 2024-04-28 19:53:45
updated: 2024-06-04 15:53:45
tags: [Raspberry Pi,开发板,硬件,嵌入式]
categories: [笔记]
thumbnail: /images/pi/0.webp
cover: /images/pi/0.webp
toc: true
---
树莓派是一个高度集成化的微型电脑，同时保留了GPIO接口，可以通过这些接口连接各种传感器、执行器等外设，实现各种功能。树莓派的操作系统可以通过SD卡进行安装，同时也支持通过USB接口连接硬盘、U盘等存储设备。
<!-- more -->
从官网介绍上看，树莓派的定义为以下内容：

You can set up your Raspberry Pi as an interactive computer with a desktop, or as a headless computer accessible only over the network.

这次折腾的是树莓派4B，配置如下：

```bash
Broadcom BCM2711, Quad core Cortex-A72 (ARM v8) 64-bit SoC @ 1.8GHz
1GB, 2GB, 4GB or 8GB LPDDR4-3200 SDRAM (depending on model)
2.4 GHz and 5.0 GHz IEEE 802.11ac wireless, Bluetooth 5.0, BLE
Gigabit Ethernet
2 USB 3.0 ports; 2 USB 2.0 ports.
Raspberry Pi standard 40 pin GPIO header (fully backwards compatible with previous boards)
2 × micro-HDMI® ports (up to 4kp60 supported)
2-lane MIPI DSI display port
2-lane MIPI CSI camera port
4-pole stereo audio and composite video port
H.265 (4kp60 decode), H264 (1080p60 decode, 1080p30 encode)
OpenGL ES 3.1, Vulkan 1.0
Micro-SD card slot for loading operating system and data storage
5V DC via USB-C connector (minimum 3A*)
5V DC via GPIO header (minimum 3A*)
Power over Ethernet (PoE) enabled (requires separate PoE HAT)
Operating temperature: 0 – 50 degrees C ambient
```

## 起步
使用官方提供的[Raspberry Pi Imager工具](https://www.raspberrypi.com/software/)，可以很方便的将系统镜像写入SD卡中，然后插入树莓派的SD卡槽中，连接电源，即可启动。

<div style="text-align: center;">
  <img src="/images/pi/1.webp" alt="Raspberry Pi Imager" width="50%">
</div>
&nbsp;

一开始打算试试最近刚出的[ubuntu 24.04 LTS](https://cn.ubuntu.com/blog/canonical-releases-ubuntu-24-04-noble-numbat_cn)，正好镜像烧录工具里也更新了这个版本。然而启动起来非常卡顿，转而使用了官方的[Raspberry Pi OS](https://www.raspberrypi.com/software/operating-systems/)。

## 固定IP
确保重启后树莓派的IP地址不变，可以通过以下方式设置固定（当前链接子网的）IP，比较方便的方式是先看当前链接的信息，然后通过树莓派的网络配置修改。
```bash
ip route
```
或者直接查看网络配置。

在树莓派的网络设置中，当前网络下改成 手动 ，添加IP地址、子网掩码、网关、DNS服务器等信息。

## 超频
树莓派4B默认是1.5GHz，可以通过修改`/boot/frimware/config.txt`文件来进行超频。
```bash
sudo vim /boot/frimware/config.txt
```

在文件末尾添加以下内容：
```bash
over_voltage=5
arm_freq=2000
gpu_freq=700
```
重启后查看频率是否生效。
<div style="text-align: center;">
  <img src="/images/pi/2.webp" alt="超频" width="50%">
</div>
&nbsp;

目前测试的最大超频配置如下，设置成如下配置可能无法启动：
```bash
over_voltage=6
arm_freq=2100
gpu_freq=750
```

如果无法启动，可以用电脑读取SD卡的`config.txt`文件，修改后再插入树莓派。

## 魔改散热
由于现在使用的金属外壳是被动散热，并没有留下风扇的位置，所以只能自己动手魔改。  
首先在外壳和CPU，内存等之间加入导热垫，将热量传导到外壳上，然后在外壳上加入风扇。

修改思路是使用一个3/4pin的风扇，将线头剪掉后焊接上杜邦线，然后通过GPIO口控制风扇的开关。零火线分别接到GPIO的GND 和 5V上，PWM线接到任意GPIO口上，这里使用的是18。

在树莓派 设置配置中，可以管理fan的开关、接口以及工作温度。

## 串口调试

在设置中可以打开串口调试、ssh和vnc连接等。

使用工具连接树莓派的GPIO，TXD接RXD，GND互接，然后通过串口调试工具，比如putty，连接树莓派。

实际上树莓派甚至可以自己通过串口连接自己进行调试。


## 其它
命令行更换wlan链接 ：
```bash
#关闭当前连接
sudo killall wpa_supplicant

#扫描附近的wifi
sudo iwlist wlan0 scan

#连接wifi
sudo wpa_supplicant -c /etc/wpa_supplicant/wpa_supplicant.conf -i wlan0

#查看是否连接成功
ifconfig wlan0
```

树莓派的wlan链接是2.4GHz频率的，如果热点连接需要设置

## 参考链接
[Getting started - Raspberry Pi Documentation](https://www.raspberrypi.com/documentation/computers/getting-started.html#getting-started-with-your-raspberry-pi)

## 碎碎念
本站运行的第100天。