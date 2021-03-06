# 基于Libtommath库的SM2协同算法

## Instructions

上一个版本的算法链接：https://github.com/SliverChen/SM2_Coop

鉴于上一个版本使用的是openssl库，而openssl下的关于椭圆曲线运算的函数无法支持协同算法下对（x2,y2) = d1d2C1 - C1的最简实现，考虑这种情况，决定采用另外一个大数库Libtommath来实现协同算法

参考算法的链接：https://github.com/stevenpsm/GM_SM2
<br></br>

## 第一进度——熟悉libtommath的使用

首先通过编译链接对参考算法进行一次正常的执行观察能否通过该参考算法进行修改以达到自身的目的
<br></br>

### 第一进度的补充进度（2021-12-23 13：30）

目前已经将部分比较核心的代码跟着写的一遍，对接口的使用有一定的印象，但是尝试测试原始代码的时候大数库出现了问题，主要是大数库并没有真正的编译链接生成.dll 和 .lib文件，使得出现无法解析的外部符号的错误，但是后续项目链接了利用libtommath本身的sln方案生成后得到的tommath.lib再次进行编译还是出现了这个错误

现在想到一个问题，为什么编译器能够识别这个库下面的接口呢

回答：是该项目本身将libtommath库中的包含文件列为了项目内部的头文件，导致项目不需要额外导入头文件，只需要将其实现文件(.lib .dll)文件链接到项目上即可

通过思考，考虑是生成环境的不同：libtommath本身是需要在win32环境下编译的，但是我们的项目本身是在x64环境下的，这样就导致项目无法识别来自win32下的lib文件（应该是）
<br></br>

### 第一进度的补充进度（2021-12-23 15：40）

目前已经成功编译运行项目，但是在解密的时候出现了错误，但是看不懂具体的报错信息，具体还要研究一下出错代号的详细含义因为今天没有什么动力去研究这个算法，所以先到这了，回去看书。^ ^
<br></br>

### 第一进度的补充进度（2021-12-24 8：44）

目前有一个问题，为什么通过随机数函数生成的随机数的位数只有10位

经过代码的调整和对错误代号的理解，目前推断出出现错误的地方是在解密的时候对C1的提取出现了问题，导致在后续的判断认为C1不在曲线上，但是整体看上去这个步骤没有出现比较明显的问题，而且在对x1的提取当中前56个字符是相等的，但是在后面8个字符中的最后2 3个字符出现了不一样的情况，目前暂时找不到出现这个问题的原因。

有一种可能是在加密的过程中将x1和y1依次放入缓存中时y1覆盖了部分x1下的字符，导致整段y1其实是前移了几个位置进行存储的。

跟我的猜想没错，确实是在将y1存储到x1之后的时候忘记了最前面有个0x04占用了1个位置，错把y1开始存储的位置设置成x1长度

目前原算法已经正常运行，原文在经过加密和解密之后得到一致的字符串，接下来将要检验公式一致性（公钥的生成，解密的(x2,y2)的协同计算）


## 第二进度——私钥 & 公钥的计算

目前通过修改公钥的生成代码以及添加了椭圆曲线的减法运算后，测试了一下效果发现得到的结果坐标x是一样的，但是y的值是不一样的，考虑可能是随机数生成的问题，因为在参考算法下，生成随机数所用到的函数是伪随机数，而且不安全。回忆openssl的使用，先计划利用openssl的BN_rand来生成随机数

经过调整和修改代码，成功将随机数生成的部分修改成了openssl的生成方式，但是通过测试发现，两种公钥的计算方式得到的结果y值还是不一样，考虑两个部分的计算：一个是d1d2-1的计算，一个是d1d2G - G的计算

目前利用观察法检验出d1d2G - G的计算过程是没有问题的，接下来计划观察d1d2-1的计算

