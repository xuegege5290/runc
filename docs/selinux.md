# selinux

## 开启docker selinux的方法:
1. 方法一：
dockerd启动的时候加上--selinux-enabled参数。或者在centos上可以修改systemd Unit文件docker.service

2. 方法二：
在/etc/docker/daemon.json配置文件中加上：
{
    “selinux-enabled”: true
}

可以通过ps -AZ查看相关进程的区别与限制：
1. 开selinux：
[admin@server1 ~]$ ps -AZ | grep nginx
system_u:system_r:svirt_lxc_net_t:s0:c375,c378 2285 ? 00:00:22 nginx

2. 未开启selinux：
[admin@server2 ~]$ ps -AZ | grep nginx
system_u:system_r:spc_t:s0       4375 ?        00:00:00 nginx

## 添加主机侧selinux规则（将要挂载的目录添加到白名单）：
```bash
chcon -Rt svirt_sandbox_file_t /docker/data1
#之后在将对应目录挂载在容器内部
docker run -i -t -v /docker/data1:/data --name eureka1 centos:7.5
```
