1.使用 DeepSeek 或其他大模型，实践课件中基础和进阶技巧的提示词,观察和理解
模型输出的结果 。

基础：

题目1：请解释什么是⽣成式⼈⼯智能 (Generative AI)， 并列举三个它在创意产业中的具体应⽤案例。
请确保每个案例都包含简要描述。

生成式人工智能（Generative AI）是一种能够自主创造新内容（如文本、图像、音频、视频等）的人工智能技术，其核心在于通过学习数据的内在规律生成与训练数据相似但全新的输出。关键技术包括生成对抗网络（GANs）、变分自编码器（VAEs）和大型语言模型（如GPT系列）。

### 创意产业应用案例

1. ‌**艺术创作**‌
   生成式AI可模仿著名画家的风格生成原创绘画，或结合用户输入生成抽象艺术作品，辅助艺术家探索新风格。
2. ‌**音乐作曲**‌
   基于用户设定的风格（如古典、电子），AI自动生成旋律、和声甚至完整编曲，为音乐人提供灵感或快速制作demo。
3. ‌**影视剧本与分镜**‌
   根据剧情大纲生成对话、场景描述或分镜草图，加速剧本创作流程，例如生成科幻故事中的虚拟角色对话。

生成式AI通过增强创意表达的多样性和效率，正在重塑创意产业的生产方式。



题目2：你现在是⼀位经验丰富的⽹络故障排除专家。我的电脑⽆法连接到 Wi-Fi，我已经重启
了路由器和电脑，但问题依旧。请提供⼀些可能的诊断步骤。

###  一、检查硬件与信号状态

1. ‌**确认Wi-Fi开关启用**‌
   - 检查笔记本物理Wi-Fi开关（侧面/前面）或功能键组合（如Fn+F5）
   - 在Windows任务栏点击网络图标 → 确保Wi-Fi开关为开启状态（非飞行模式）
2. ‌**检测信号干扰**‌
   - 将路由器远离微波炉、蓝牙设备、无绳电话等干扰源（至少3米）
   - 用手机测试相同位置Wi-Fi信号强度，若≤2格需调整路由器位置或增加中继

### 二、系统级网络修复

1. ‌**重置网络协议栈**‌（管理员权限运行命令提示符）：

   ```
   batchCopy Codenetsh winsock reset
   netsh int ip reset
   ipconfig /release
   ipconfig /renew
   ipconfig /flushdns
   ```

   完成后重启电脑

2. ‌**启用关键网络服务**‌

   - 按`Win+R`输入`services.msc` → 找到 ‌**WLAN AutoConfig**‌ 服务 → 确保其状态为"正在运行"且启动类型为"自动"

3. ‌**检查IP/DNS设置**‌

   - 控制面板 → 网络和共享中心 → 更改适配器设置 → 右键Wi-Fi适配器 → 属性
   - 双击 ‌**Internet协议版本4 (TCP/IPv4)**‌ → 确认选择 ‌**自动获取IP地址**‌ 和 ‌**自动获取DNS服务器地址**‌

------

### 🔄 三、驱动与系统更新

1. ‌**更新无线网卡驱动**‌
   - 设备管理器 → 网络适配器 → 右键无线网卡 → "更新驱动程序" → 自动搜索更新6
   - 若无效，访问网卡制造商官网下载最新驱动手动安装
2. ‌**操作系统补丁**‌
   - 设置 → Windows更新 → 检查更新（部分网络问题需系统补丁修复）

------

### 🛡️ 四、安全软件与路由器排查

1. ‌**临时禁用防火墙/杀毒软件**‌
   - 控制面板 → Windows Defender防火墙 → "启用或关闭防火墙" → 临时关闭专用/公用网络防火墙
   - 退出第三方安全软件（如360、McAfee）测试连接
2. ‌**路由器深度检查**‌
   - 登录路由器后台（192.168.1.1）：
     - 确认 ‌**MAC地址过滤**‌ 未启用或已添加本机MAC4
     - 更换Wi-Fi信道（推荐2.4GHz用信道1/6/11，5GHz用36/44/149）
     - 检查 ‌**DHCP地址池**‌ 是否耗尽（连接设备过多时新设备无法获取IP）

------

### 💡 终极解决方案

若以上步骤无效：

- ‌**系统还原**‌：回退到网络正常时的系统还原点4

- ‌

  硬件检测

  ‌：

  - 使用USB无线网卡测试，若可连接说明内置网卡故障4
  - 送修检测无线网卡硬件状态（设备管理器出现黄色感叹号需警惕）5

> 执行顺序建议：‌**信号检测 → 网络重置 → 驱动更新 → 路由器设置**‌。每完成一步后验证Wi-Fi连接状态，避免操作冗余



题目3：扮演⼀位⽣活在23世纪的星际探险家，写⼀篇⽇记，记录你第⼀次登陆⼀颗充满奇異
植物的未知⾏星的经历。字数大约300字。

星际历 2247年·新芽月·18日
今天终于踏上了X-3776行星——这颗被探险队戏称为"翡翠噩梦"的星球。当舱门打开的瞬间，淡紫色的雾气中飘来类似茉莉与金属混合的奇异香气。我的生物扫描仪立刻疯狂闪烁：大气含氧量32%（是地球的1.5倍），但检测到未知的惰性神经毒素，好在防护服能完全过滤。

地表覆盖着会脉动的半透明"植物"，它们像水母般悬浮在离地20厘米处，茎秆内流淌着荧光蓝色液体。最惊人的是那些金字塔状的黑色晶体丛，每当我的影子掠过时，晶体表面就会浮现出类似梵高《星空》的漩涡图案——后来才发现这是它们的光合作用器官，通过吸收恒星风中的高能粒子转化能量。

采集样本时遭遇了意外：一株看似枯萎的藤蔓突然缠住我的机械外骨骼，其力量足以压碎钛合金。幸亏副队长用等离子切割器及时解救。回飞船前，我在陨石坑底部发现了更震撼的景象——整片"森林"正在同步发出摩尔斯电码节奏的生物荧光，仿佛在传递某种信息...

（注：所有样本已冷冻保存，建议后续队伍携带神经语言学专家）



进阶技巧：

(1).少样本提示(few-shot prompting)

提示:
文本:
这家餐厅的食物太美味了!
情感:正面
文本:
我对这次的服务感到非常失望
情感:
负面
文本:
这部电影的剧情一般，但演员表现不错。
情感:中性
文本:这款产品超出了我的预期，强烈推荐!
情感:

文本:这款产品超出了我的预期，强烈推荐!
情感:正面

(2): 思维链提示 (Chain-of-Thought, CoT)

提示:
问题:自助餐厅有23个苹果。他们用了20个做午餐，又买了6个。现在他们有多少个苹果?请
逐步思考。
回答:
开始时有23个苹果。
用了20个后，剩下 23-20=3个苹果。
然后他们又买了6个苹果。
所以现在他们有3+6=9个苹果，
答案是9。
问题: Natalia卖了48条头巾，然后她姐姐给了她25条头巾。Natalia现在有多少条头巾?请
逐步思考。
回答:

### 逐步思考：

问题中未给出Natalia的初始头巾数量。为了计算当前数量，我们需要知道初始值，但问题中缺失该信息。
假设初始数量为 S条头巾（其中 S≥48，因为她卖了48条）。

- Natalia卖了48条头巾后，剩余数量为 S−48
- 然后她姐姐给了她25条头巾，因此数量变为 (S−48)+25=S−23。

净变化为减少23条头巾（-48 + 25 = -23），但具体当前数量取决于未知的初始值 S*S。
例如:

- 如果初始 S=48，则剩余 48−48=0，再+25 = 25条。
- 如果初始 S=50，则剩余 50−48=2，再+25 = 27条。

由于问题未提供初始数量，无法确定确切答案。建议补充初始信息以准确计算。

### 回答:

无法确定确切数量（初始数量缺失）。净变化为减少23条头巾。如果需要数字答案，假设初始为48条，则Natalia现在有25条头巾。但此假设可能不准确。



控制输出长度与格式

提示:
请将以下用户信息整理成JSON对象
姓名:张三
邮箱:zhangsan@example.com
城市:上海

{
  "姓名": "张三",
  "邮箱": "zhangsan@example.com",
  "城市": "上海"
}



2.(可选)遵循提示工程的核心原则和 5个技巧，构造 3个正例和反例，加深对提
示工程核心原则和技巧的理解。