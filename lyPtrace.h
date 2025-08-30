#pragma once
#include <iostream>
#include <errno.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
/**
 * @brief  用于安卓PTRACE封装
 * @author 凌烟
 * @date   2025-08-03
 * @license MIT开源协议
 */
using namespace std;

inline long lyPtrace(long cmd, pid_t pid);//命令，进程
long lyPtrace(long cmd, pid_t pid,void* iovec);//命令，进程, 指向iovec的指针
long lyPtrace(long cmd, pid_t pid,void* addr,void* value);//命令，进程, 指向栈的指针,要写入的值
template <typename...Args>
uint64_t CallFunc(pid_t pid, uint64_t func,Args...args);//进程,调用的函数地址,参数
template <typename...Args>
uint64_t CallFunc_SVC(pid_t pid, int SVC,uint64_t addr,Args...args);//进程,系统调用号,参数