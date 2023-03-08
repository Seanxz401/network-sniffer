# 基于C和QT开发的网络窃听器 network-sniffer
一个可以监视局域网内指定主机网络的状态、 数据流动情况以及在网络上传输的信息的网络窃听器。a network sniffer

主要涉及：ARP扫描存活主机、ARP中间人攻击、监听数据包并分析其中可能存在的敏感信息。

环境：Ubuntu20.04，QT5，libpcap 具体查看项目报告

运行步骤：

1. QT新建一个Widget项目，假如项目名为sniffer
2. 将所有源码拷入项目目录sniffer
3. 编译（注意编译与执行分开）
4. 配置流量转发，具体见下方
5. 进入项目编译后的目录（build...sniffer），通过sudo ./sniffer启动项目，使用底层需要root权限
6. 启动ARP扫描前需要修改界面左侧的配置信息。

实验主机开启流量转发这一步在命令行配置完成。具体操作如下：
1. 修改配置文件`sudo vim /etc/sysctl.conf`，令 net.ipv4.ip_forward=1；
2. 保存并更新修改：`sudo sysctl -p`；
3. 清除所有的 iptables 规则：`sudo iptables -F`；
4. 允许接收数据包：`sudo iptables -P INPUT ACCEPT`；
5. 允许转发数据包：`sudo iptables -P FORWARD ACCEPT`；
6. MASQUERADE 方式配置nat：`sudo iptables -t nat -A POSTROUTING
-s 192.168.32.0/24 -o ens32 -j MASQUERADE `。
