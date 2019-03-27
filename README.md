#  基于Jpcap的sniffer实现

​	使用java语言编写的sniffer工具，可以实现简单的监控网卡数据包，并进行筛选的工作。

- 环境说明

  使用jdk1.8.0_201里边的jre。

  加上Jpcap，由于Jpcap是基于winpcap实现的，因此需要下载安装winpcap以及jpcap。
  
  配置jpcap有很多的教程，直接百度就可以。

  直接在命令行输入以下命令既可以打开程序。（请不要直接双击sun.jar，无法运行）

  ```
  java -jar sun.jar
  ```

- sun文件夹即为项目文件

  使用IDEA作为编程工具。

- 运行时截图

  ![picture](https://github.com/sunSUNQ/MY_Sniffer/raw/master/picture/running.jpg)

- 参考：
  - [ ] https://github.com/nicahead/MySniffer
  - [ ] https://github.com/HassanAdamm/packet-sniffer

