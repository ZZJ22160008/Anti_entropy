#!/bin/bash

# 清除旧的编译结果
make clean

# 编译内核模块
make

# 加载内核模块
sudo insmod sys_bpf_delete.ko

clear

# 运行测试程序
./test

# 卸载内核模块
sudo rmmod sys_bpf_delete
