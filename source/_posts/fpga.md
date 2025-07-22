---
title: 从零开始玩开发板
date: 2024-03-09 16:54:03
updated: 2024-03-09 16:54:03
tags: [嵌入式,开发板,FPGA,硬件]
categories: [笔记]
thumbnail: /images/fpga/0.webp
cover: /images/fpga/0.webp
toc: true
---
说是从零开始，其实也不然，因为FPGA是一定接触过的；然而正好符合Re0的主题，因此也在某种程度上也没问题。一些机缘巧合，我从社区借到了两块板子，NXP的FRDM-KL25Z和普中HC6800-ES V2.0，单纯出于兴趣，我决定玩一玩。
<!-- more -->
## FRDM-KL25Z

FRDM-KL25Z有[官网页面](https://www.nxp.com.cn/design/design-center/development-boards/general-purpose-mcus/freedom-development-platform-for-kinetis-kl14-kl15-kl24-kl25-mcus:FRDM-KL25Z)，根据介绍就知道有示例程序和IDE可以下载。

需要注意的是，需要提前下载驱动[P&E OpenSDA驱动](www.pemicro.com/opensda)。

<div style="text-align: center;">
  <img src="/images/fpga/1.webp" alt="FRDM-KL25Z" style="width: 50%;">
</div>
&nbsp;

可以在引导加载程序模式下保存最新固件，在按住 USB 连接器之间的小按钮的同时，将 Freedom 板插入标有 SDA 的连接器，此方法只适用于 Windows 7 或更早的计算机来更新固件。

另外MCUXpresso IDE默认的SDK中是没有这个板子的，因此要专门下软件包，指引非常清晰按照提示操作就可以。

NXP社区有社区开发者[入门参考的帖子](https://www.nxpic.org.cn/module/forum/thread-549104-1-1.html)，官方也有教程：[FRDM-KL25Z快速入门](https://www.nxp.com.cn/document/guide/getting-started-with-the-frdm-kl25z:NGS-FRDM-KL25Z)。

<div style="text-align: center;">
  <img src="/images/fpga/0-1.webp" alt="SDK" style="width: 50%;">
</div>
&nbsp;

FRDM-KL25Z的烧写则极为简单，在其官网介绍页中也提到了它的兼容性接口和“大容量存储设备闪存编程接口(默认) - 无需安装任何工具即可评估演示应用”，直观感受就是写入执行文件即可。在其官网提供的FRDM-KL25Z Quick Start Package中有.srec文件，直接拷入Bootloader磁盘里即可完成MCU的程序烧写。

在quick start package的Precompiled Examples中，提供比如[FRDM-KL25Z快速入门](https://www.nxp.com.cn/document/guide/getting-started-with-the-frdm-kl25z:NGS-FRDM-KL25Z)文档中所提到的”气泡水平仪“演示，可以用板载加速度传感器调整灯光。当板水平时，RGB LED熄灭；当板倾斜时，红色或绿色LED根据X轴和Y轴上的倾斜度逐渐发亮。还有一些如利用电容板/按钮调整灯光闪烁频率的示例，用于检验其功能。

<div style="text-align: center;">
  <img src="https://www.nxp.com.cn/assets/images/en/photography/FRDM-KL25Z-DEMO.webp" alt="演示" style="width: 50%;">
</div>
&nbsp;

作为一个非常小巧轻便的开发板，FRDM-KL25Z的功能还是很强大的，有很多的外设，比如LED、按键、电容触摸、加速度传感器等等，可以用来做很多有趣的东西。兴许可以用到姿态检测之类，或者计步器。

## HC6800-ES V2.0

<div style="text-align: center;">
  <img src="/images/fpga/2.webp" alt="HC6800-ES V2.0" style="width: 50%;">
</div>
&nbsp;

普中的这块板子就是非常典型的STM32开发板了，加上附带的组件，可以说它几乎应有尽有。我使用的是[keil uVision5](https://www.keil.com/download/product/) 和 [普中ISP](https://soft.3dmgame.com/down/217430.html)(3dm真是什么都有)进行开发，烧写和调试。推荐一个视频：[新手必看:普中科技51单片机HC6800 v2.0 的下载程序教程，注意事项，A2开发板的区别，stc89c51芯片](https://www.bilibili.com/video/BV1x34y1a7Cp/?vd_source=72bd08f8e448019af177068235d25f83)

写了一个简单的LED流水灯程序，它会在P2端口的8个引脚上依次点亮LED灯。
```c
#include <REGX52.H>
#include <INTRINS.H>

void Delay500ms()
{
	unsigned char i, j, k;

	_nop_();
	i = 4;
	j = 205;
	k = 187;
	do
	{
		do
		{
			while (--k);
		} while (--j);
	} while (--i);
}


void main()
{
	while(1)
	{
		P2=0xFE;//1111 1110
		Delay500ms();
		P2=0xFD;//1111 1101
		Delay500ms();
		P2=0xFB;//1111 1011
		Delay500ms();
		P2=0xF7;//1111 0111
		Delay500ms();
		P2=0xEF;//1110 1111
		Delay500ms();
		P2=0xDF;//1101 1111
		Delay500ms();
		P2=0xBF;//1011 1111
		Delay500ms();
		P2=0x7F;//0111 1111
		Delay500ms();
	}
}
```
首先使用三层循环实现500ms的延迟，然后在主函数中循环将引脚设置为低电平，点亮相应的LED灯，并调用延时函数使其保持点亮一段时间。

其实还有很多可玩的，比方说我还打算用蜂鸣器来演奏歌曲之类的（新建文件夹）。总之，还是得多学习。