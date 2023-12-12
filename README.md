# 免杀生成器

## 原理

![免杀生成器](images\免杀生成器.png)

## 使用方法

将shellcode放入shellcode.txt

使用任意http服务器实现远程文件下载功能，将生成的文件

填写服务器ip（不用加http）

然后将生成的'fenli.txt'、'miwen.txt'、'update.txt'放入http服务器

然后使用pyinstaller打包loader.py

注意，想实现当loader.exe目录下存在kygvseedc.txt时才会运行payload，否则运行正常程序

## 免杀效果

2023/11.4测试

免杀360静态+动态

免杀火绒静态+动态

免杀WindowsDeFender静态

免杀卡巴静态

其他尚未测试 
