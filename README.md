# 基于Libtommath库的SM2协同算法

## Instructions

上一个版本的算法链接：https://github.com/SliverChen/SM2_Coop

鉴于上一个版本使用的是openssl库，而openssl下的关于椭圆曲线运算的函数无法支持协同算法下对（x2,y2) = d1d2C1 - C1的最简实现，考虑这种情况，决定采用另外一个大数库Libtommath来实现协同算法

参考算法的链接：https://github.com/stevenpsm/GM_SM2
<br></br>

## 第一进度——熟悉libtommath的使用

首先通过编译链接对参考算法进行一次正常的执行观察能否通过该参考算法进行修改以达到自身的目的
