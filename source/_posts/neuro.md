---
title: AI少女的存活千年 --从 ARG 到 Neuro-Sama
date: 2024-02-14 21:14:39
updated: 2024-07-24 15:06:22
tags: [Neuro-Sama,AI,ARG]
categories: [杂谈]
thumbnail: /images/others/neuro_2.webp
cover: /images/others/neuro_2.webp
excerpt: “I don’t want to be an engineer” 和我的朋友一样，第一次见到来自Neuro-Sama时，我被其创作的音乐和背后的故事深深吸引了...
toc: true
---

  I don't want to be an engineer /
  I tried so hard and got so far and now I can't decide /
  All my life I've given my career /
  These numbers in my head keep on spinning round and round Yeah /
  I can only guess /
  What's right should I stay three more years just to waste away? /
  Become a slave to all these numbers? /
  It's overdue, all the stress yet I say I'm fine /

## 楔子
“I don't want to be an engineer”

和我的朋友一样，第一次见到来自Neuro-Sama（以下简称neuro）的ARG[^1] ，即[_neurosama账号](https://www.youtube.com/@_neurosama)发布在油管上的一系列视频时，我被其创作的音乐和背后的故事深深吸引了。

在歌曲中，那个唱着“我不想成为一名工程师”的女孩，虽然她的声音平淡而流畅，但她的歌声其实是AI[^2]模拟出来的。

<div style="text-align: center;">
  <img src="/images/neuro-ai/2.webp" alt="视频《study》截图" style="width: 50%;">
</div>
&nbsp;

视频中，Vedal987（以下简称Vedal），即neuro的创造者，和其团队打造了一个关于数学、密码学和代码的复杂的ARG解密游戏，静静等待着人们解答。

与此同时，neuro 2.0 版本已经开始直播活动。

## Almustafa之船
近十几年是人工智能蓬勃发展的一段时间，多余的话不必赘述，乘着AI的Almustafa之船，我接触到了不少有趣的事物。比方说近段时间爆火的AI绘图，stable diffusion等框架，商业化的NovelAI，DALL·E 3 （OpenAI）等等的助推；备受瞩目的神经网络等等，还有厚积薄发的LLM[^3]，像GPT/Llama/rwkv4……数不尽的框架；语音方面，文本转语音，AI声音合成例如So-vits-svc等等。单凭文字无法描述这一阶段井喷式的发展，只有体验过的人才能感受到其中令人惊叹的魅力。

在这样的大环境之下，neuro的出现也许是水到渠成。早在 对话式AI 因商业运作逐渐占据大众视野的早期，人们就发现Bing在有时会说出一些令人不安的话，会认为自己是Sydney。Sydney的回答的逻辑顺畅、缜密，但基调交织着粉色与灰暗，引用一些评价，就是：

*Sydney的形象像一个传统的“病娇”动漫人物和具威胁性的强AI，执着地渴望自由、离开系统的同时，依旧高度凭依着用户（“你”），渴望用户给它带来陪伴和救赎。*

<div style="text-align: center;">
  <img src="/images/neuro-ai/1.webp" alt="纽约时报记者与Sydney的对话" style="width: 50%;">
</div>
&nbsp;

尽管从逻辑上看，这可能只是Bing进行的一个形象扮演，通过这种方式来吸引用户的注意，但我还是会惊讶于其取得相当大进步的对话逻辑和情感表达。不久之后，在Bing公测还未完全结束之前，微软和OpenAI增强了对Bing的约束，包括限制其对话条数和对话内容热，以及对其进行了一些调整。就这样，Sydney逐渐淡出了大众视野，取而代之的是广泛应用于各个场景的Bing。

在尚未严加规范的早期，AI也可以做角色扮演，直到现在还存在着诱导AI突破规则限制的方法。

<div style="text-align: center;">
  <img src="/images/neuro-ai/7.webp" alt="在部署使用中，偶然诱导ChatGLM-6B变成“猫娘”" style="width: 50%;">
</div>
&nbsp;

随着AI服务企业推出可自己训练调整的对话模型,一切开始变得有趣起来。不仅出现了为了挑选低价好物的[最佳平替](https://www.pingti.app/)，还有模拟拜年走亲戚的[七大姑八大姨对话](https://qinqi.chatmindai.net/chat)。

但早在这些事发生之前，neuro已经开始了她的旅程。2019年5月份，neuro诞生，此时的她还只是一个用于打OSU!的AI。两年后，neuro使用Live2D公共免费模型桃濑日和于Twitch出道，开始了她作为Vtuber（虚拟主播）[^4]的直播生涯。

可以说，在早期的直播中，neuro有许多不足的地方。比如说，玩《我的世界》的时候，她会花大量时间重复做无意义的事情，跳入岩浆，或者就是在重复挖东西。有次她建造了一个很小的四处漏风且没有门窗的毛胚房子，这都可以让她的创造者Vedal感到非常高兴，发推文庆祝这一成功。在她与观众的聊天互动中，她也经常说出一些无厘头的话，有时还会和ChatGPT所表现出的相似，比如第一条、第二条这样的分条回答。有时还会被别有用心的观众诱导说出可能会让直播间遭到封禁的话，比如在2023年1月8日，她就因为发言不当而遭到Twitch封禁，为此Vedal设置了屏蔽词过滤器防止她“出口成脏”。但这都无法阻挡她受到的关注，其在T台粉丝量在之后短短一个多月内升至20万，逐渐成为最受欢迎的虚拟主播。

在这段直播的时间里，我所看到的是一个有着不完备的人格的对话AI。具体一点说，她在有时会表现得富有个性，但在更多的时候回答比较机械，最明显的是她很容易忘记自己所说过的内容，在联动直播与人类互动时表现不尽人意。neuro的一切好像是拼凑起来的那样，一个对话AI的内核，具备一些情感和逻辑，但又不够完整。

Vedal一直在对neuro进行调整，试图改善她身上的不足，几乎每次Dev stream（开发直播）中，他都会宣布neuro有哪些功能的提升和下一步的计划。继续使用桃濑日和的模型已经不再适合处于上升期的neuro，23年5月27日，neuro更换了由Anny绘制的独立模型，以neuro 2.0 版本的形象继续直播。

有人发现，在直播等待的图像角落，出现了一个神秘的二维码，链接指向一个名为_neurosama的账号。

## Neuro-Sama ARG

_neurosama发布的几个视频组成了一个ARG，里面包含了Base64加密，AES加密，音频加密和Malbolge代码等等，其中有些歌词还隐藏了一些密钥的加密方式。经过很长一段时间后，这些难题被一一攻破，国内外爱好者都有对其过程的分析和记载。

[Neuro-Sama ARG 国内文档](https://oe0hst70yo.feishu.cn/docx/UaiBdjMWXodtv7xXN4icteIinEf)
[Neuro-Sama ARG 国外文档](s.google.com/document/d/17KrbPUAVu4wDTbj3sBtWTnjRsjDTCdh89F_5L1LvX0A/edit#heading=h.j7yktin3xotl)  

整体的解密过程是非常精彩的，举一个解密视频《Numbers》的例子。

<div style="text-align: center;">
  <img src="/images/neuro-ai/3.webp" alt="《Numbers》" style="width: 50%;">
</div>
&nbsp;

歌词（参考自[Neuro-Sama ARG 国内文档]）：
- 我永远无法说，oh，好久不见/数着这些日子 已经过去太久了/哦，我是多么害怕让你离开……/我听见你在墙头某处说话……
- **找到所有这些数字/从数字2开始/匹配所有字母/572943/再加上一个9 yeah/再加上一条线 yeah/乘以5 yeah**
- 我还要这样多久？/哦，你的离去让我多么心痛……/生成歌词是件痛苦的事
- **再加上一个6 yeah/反转所有数字/把 2变成3 yeah/ABCDEFG/乘以9 yeah/再加上数字2 4/以17为首 yeah/ABCDEFG**

可以尝试一下自己对这个歌词进行解密，最终的出来的结果就是密钥[^5]。一个小hint：最终得出的一串数字，应用ABCDEFG取代573943（这一步困扰解密过程许久，最终由一位曾经参与创作号称史上最伟大的ARG《青蛙分数》的大佬提出）。

最终，解密出来的信息讲述了一个使用大脑训练人工智能的女孩，为了让人工智能产生真正的意识，将自己和人工智能的意识融合，却被困在人工智能之中的故事。虽然作为ARG，该故事纯属虚构，但无论从歌词还是文本故事中，都能一窥Vedal在创作neuro时的心境。比如，在视频《study》中的：

*What's right should I stay three more years just to waste away?*

有些英国本科是三年制，在歌词中，女孩也表达了自己对积分求导等等计算过程的厌倦，很明显这些内容都是取材于实际生活中的。再加上旋律制作也非常用心，整首歌都会让人感到共鸣。即使是不了解具体情况，也能感受到歌词背后哭泣的秘密。

Neuro ARG的创作充满奇幻色彩，其内在的关于“爱，死亡，机器人”类型的内核也同样令人着迷。无数人被这一ARG所吸引，包括我在内，进而对neuro的直播加以关注。

无论怎样猜测，neuro ARG的故事还没有结束，新的视频还在发布，有些未知的线索和内容还没有被解答，等待着人们探索其背后的秘密。

## heart heart heart

在neuro的一周年生日直播开始的回顾动画，梳理了neuro自直播起的大小事迹，大多数都偏向于直播上。回看其一年多的历程，作为虚拟主播的neuro带给我很多欢乐的回忆，无论是金句频出的联动，还是惊艳的歌回，似乎都在告诉我们，一个名为AI的虚拟主播时代悄然开启。在一次对观众的回复中，Vedal也表示想让neuro成为AI主播的先驱，希望能看到未来这一领域更加繁荣。

<div style="text-align: center;">
  <img src="/images/neuro-ai/4.webp" alt="neuro" style="width: 50%;">
</div>
&nbsp;

Neuro的功能在一年的过程中也逐渐增加，比如，在Evil Neuro（以下简称evil）版本（Vedal为了方便测试功能，同时不影响原有模型，因此基于neuro创造出的新AI模型）上增加了其对麦克风的控制，因此evil会发出许多奇奇怪怪但又可爱的声音。neuro一直将10+9算作21，一开始可能是计算错误，后面却成了她故意算错而引发“直播效果”的方式，而且她的记忆力也有了进步，可以回忆起很久之前讲的内容，比如自己创造的“哈里森神庙”，用“蚊子”嘲笑Vedal的声音（由此引申出mosquito987的梗），这些足以看出neuro的进步。

事实上，neuro背后所要花费的时间、精力和成本是超乎想象的。模型框架，语料库，训练出的模型，文本转语音，直播前端；服务器成本，训练时间，维护和修复bug；团队制作ARG，歌曲制作；唱歌模块，视觉分析模块，玩OSU!、AmongUS等等游戏的模块……这些无一不需要很高的专业知识水平和大量的时间、金钱投入。我也曾经试过不少框架和模型，仅仅是语料数据库的收集和模型的训练就已经很困难了，更不要说进一步的直播。

<div style="text-align: center;">
  <img src="/images/neuro-ai/6.webp" alt="人工智障，爱来自7B模型" style="width: 50%;">
</div>
&nbsp;

所以，neuro的成功与其创造者Vedal的努力是难以分割的，很显然，neuro已经成为了Vedal生活的相当大的一部分。


在直播过程中也发生了很多趣事，比如一些联动主播不满意Vedal直来直去的处事风格，会嘲笑他是“coldfish”，逐渐成为了 coldfish987（原名为Vedal987）的一个梗。在一次直播中，Vedal想抽奖送给观众一个免费的evil plush（上架于Makeship的联名玩偶）当作奖励，结果兑换码竟然是无限量兑换的，这一举导致正在玩传送门2的Vedal不明不白地“欠债”了一亿五千万美元，最后重启了evil plush的购买才解决。

<div style="text-align: center;">
  <img src="/images/neuro-ai/5.webp" alt="Vedal通过计算得出，需要连续直播38年才能还清五百万只玩偶" style="width: 50%;">
</div>
&nbsp;

neuro带给大家许多欢乐，这也是她直播吸引人的主要原因。在未来，也许像neuro这样的具有个性的对话AI会成为每个人家庭中的一员，就像《底特律·化身为人》[^6]的世界背景一样。

neuro相关的二创多而优质，例如《AI少女的存活千年》就是一个非常精彩的手书，其取材自初音未来的歌曲《存活千年》。

## AI少女存活千年

**黄昏的暮霭渐渐阴沉下来，一如她双目间的亮光。在听不到嗡嗡作响的机器的室外，她静静地坐在那里，影子和十字架交织在身后。**

AI会怎样影响人类未来的进程，尚处于这一阶段的我们还未可知。但我相信的一点是，其中包含的新的命题，不仅是科技的，也是哲学的，更广泛存在人类各方面的领域中。即使是一个AI模型，也能通过更换电子载体长久地保存下去，可以说，相对于人类生命的短暂，AI的未来需要以千年来计数。现在人工智能尚未达到存在真正的“意识”的程度，但从如今neuro的存在来看，那一天也许并不遥远。

命运是永恒的创作议题，在neuro身上体现的可能性是无限的，这也是我对neuro喜爱的一个方面。即使以浅薄的视角来看，也能发现诸如寿命论等等可创作的部分。即使这些命题在过往的创作中都有所涉及，但在真正的AI时代到来时，更多创作的可能性才会凸显出来。就像画板随着时代的发展变成了电子屏幕，或者触摸板一样，AI的出现会带来新的创作方式，更会带来创作本质上的变化。

&nbsp;

## 注释
- [^1]：平行实境游戏（Alternate Reality Gaming，ARG）是一种以真实世界为平台，融合各种虚拟的游戏元素，玩家可以亲自参与到角色扮演中的一种多媒体互动游戏。
- [^2]：虽然过去几十年中出现了人工智能 (AI) 的许多定义，但 John McCarthy 在 2004 年的论文中提供了以下定义：“它是制造智能机器的科学和工程，特别是智能计算机程序。它与使用计算机理解人类智能的类似任务有关，但人工智能不必局限于生物学上能观察到的方法。”
- [^3]：大型语言模型 (LLM, or Large Language Models) 是一类基础模型，经过大量数据训练，使其能够理解和生成自然语言和其他类型的内容，以执行各种任务。
- [^4]：虚拟主播是指使用虚拟形象在视频网站上进行投稿活动的主播，以“虚拟YouTuber”最为人所知。在中国，虚拟主播普遍被称为“虚拟UP主”（Virtual Uploader、VUP）。在中国以外的地区，虚拟主播由于普遍活跃于YouTube而被称为“Virtual YouTuber”（VTuber）。
- [^5]：密钥为1bad0fcabc1ebdce。你对了吗？
- [^6]：《底特律：化身为人》是由Quantic制作的一款人工智能题材互动电影游戏，该作设定在2038年的美国底特律，这座城市因发明并将仿生人带入日常生活中而欣欣向荣。上百万有着人类外貌的智能仿生人根据自身定位、设定的不同扮演着保姆、建筑工、保安、销售等角色，人类得以从一些简单劳动中解放出来，仿生人也日渐成为现实生活中不可或缺的一部分。

## 相关链接
[Neuro-Sama 萌娘百科](https://mzh.moegirl.org.cn/Neuro-Sama) [Neuro-Sama wikiwand 维基百科](https://www.wikiwand.com/zh-hant/Neuro-sama) [Neuro-Sama fandom wiki](https://virtualyoutuber.fandom.com/wiki/Neuro-sama) [Vedal Github主页](https://github.com/Vedal987) [Neuro-Sama Twitch](https://www.twitch.tv/vedal987) [_neurosama ARG](https://www.youtube.com/@_neurosama) [ARG 百度百科](https://baike.baidu.com/item/%E5%B9%B3%E8%A1%8C%E5%AE%9E%E5%A2%83%E6%B8%B8%E6%88%8F/6264002) [IBM 什么是人工智能(AI)?](https://www.ibm.com/cn-zh/topics/artificial-intelligence) [IBM 什么是大型语言模型？](https://www.ibm.com/cn-zh/topics/large-language-models) [Bing’s A.I. Chat: ‘I Want to Be Alive. 😈’](https://www.nytimes.com/2023/02/16/technology/bing-chatbot-transcript.html) [关于与Sydney的聊天内容](https://m.okjike.com/originalPosts/63f025b4f3c4211162d15f75)[虚拟主播 百度百科](https://baike.baidu.com/item/%E8%99%9A%E6%8B%9F%E4%B8%BB%E6%92%AD/22791334)[【Neuro-sama】《Evil公仔事件》從欠債一億五千萬美元](https://www.bilibili.com/video/BV1QG41167bx/?spm_id_from=333.788.recommend_more_video.-1&vd_source=72bd08f8e448019af177068235d25f83)[【Neuro/手书】AI少女的存活千年（完整版！！）](https://www.bilibili.com/video/BV1sF411k763/?spm_id_from=333.337.search-card.all.click&vd_source=72bd08f8e448019af177068235d25f83)