#include "lyPtrace.h"

long lyPtrace(long cmd, pid_t pid)
{
	long result = ptrace(cmd, pid, NULL, NULL);
	return result;
}

long lyPtrace(long cmd, pid_t pid, void *iovec)
{
	long result = ptrace(cmd, pid, NT_PRSTATUS, iovec);
	return result;
}

long lyPtrace(long cmd, pid_t pid, void *addr, void *value)
{
	long result = ptrace(cmd, pid, addr, value);
	return result;
}

template < typename...Args >	// 运用模板和可变量函数
	uint64_t CallFunc(pid_t pid, uint64_t func, Args...args)
{
	struct user_pt_regs regs, original_regs;
	struct iovec iov;
	iov.iov_base = &original_regs;
	iov.iov_len = sizeof(original_regs);
	lyPtrace(PTRACE_ATTACH, pid);
	waitpid(pid, NULL, 0);

	lyPtrace(PTRACE_GETREGSET, pid, &iov);
	memcpy(&regs, &original_regs, sizeof(regs));	// 保存堆栈
	regs.pc = func;
    regs.regs[30] = 0;
	uint64_t param[] = { static_cast < uint64_t > (args)... };
	constexpr size_t param_count = sizeof...(args);
	// ARM64下前8个参数传前8个寄存器
	for (size_t i = 0; i < param_count && i < 8; ++i)
	{
		regs.regs[i] = param[i];
	}
	// 如果参数超过8个，剩余参数需要压栈
	if (param_count > 8)
	{
		uint64_t newsp = regs.sp;
		size_t stack_args_count = param_count - 8;
		size_t stack_space = stack_args_count * sizeof(uint64_t);
		stack_space = (stack_space + 15) & ~15;
		newsp -= stack_space;
		for (size_t i = 8; i < param_count; ++i)
		{
			uint64_t value = param[i];
			lyPtrace(PTRACE_POKEDATA, pid,
					 reinterpret_cast < void *>(newsp + (i - 8) * sizeof(uint64_t)),
					 reinterpret_cast < void *>(value));
		}
		regs.sp = newsp;
	}
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
	lyPtrace(PTRACE_SETREGSET, pid, &iov);
	lyPtrace(PTRACE_SYSCALL, pid);
	waitpid(pid, NULL, 0);
	lyPtrace(PTRACE_SYSCALL, pid);
	waitpid(pid, NULL, 0);
	// 获取函数返回值(x0)
	lyPtrace(PTRACE_GETREGSET, pid, &iov);
	uint64_t result = regs.regs[0];
	iov.iov_base = &original_regs;
	iov.iov_len = sizeof(original_regs);
	lyPtrace(PTRACE_SETREGSET, pid, &iov);	// 恢复堆栈
	lyPtrace(PTRACE_DETACH, pid);
	return result;
}

template < typename...Args >	// 运用模板和可变量函数
	uint64_t CallFunc_SVC(pid_t pid, int SVC, uint64_t addr, Args...args)
{
	struct user_pt_regs regs, original_regs;
	struct iovec iov;
	iov.iov_base = &original_regs;
	iov.iov_len = sizeof(original_regs);
	lyPtrace(PTRACE_ATTACH, pid);
	waitpid(pid, NULL, 0);
	lyPtrace(PTRACE_GETREGSET, pid, &iov);
	memcpy(&regs, &original_regs, sizeof(regs));	// 保存堆栈
	regs.regs[8] = SVC;
	regs.pc = addr;				// 调用的地址指令填SVC #0这里自动帮你写好了孩子
    regs.regs[30] = 0;
	uint32_t svc = 0xD4000001;	// svc指令的十六进制
	lyPtrace(PTRACE_POKEDATA, pid,
			 reinterpret_cast < void *>(addr), reinterpret_cast < void *>(svc));
	uint64_t param[] = { static_cast < uint64_t > (args)... };
	constexpr size_t param_count = sizeof...(args);
	// ARM64系统调用下前8个参数传前8个寄存器(X8作系统调用号)
	for (size_t i = 0; i < param_count && i < 8; ++i)
	{
		regs.regs[i] = param[i];
	}
	// 如果参数超过8个，剩余参数需要压栈
	if (param_count > 8)
	{
		uint64_t newsp = regs.sp;
		size_t stack_args_count = param_count - 8;
		size_t stack_space = stack_args_count * sizeof(uint64_t);
		stack_space = (stack_space + 15) & ~15;
		newsp -= stack_space;
		for (size_t i = 8; i < param_count; ++i)
		{
			uint64_t value = param[i];
			lyPtrace(PTRACE_POKEDATA, pid,
					 reinterpret_cast < void *>(newsp + (i - 8) * sizeof(uint64_t)),
					 reinterpret_cast < void *>(value));
		}
		regs.sp = newsp;
	}
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
	cout << pid << endl;
	lyPtrace(PTRACE_SETREGSET, pid, &iov);
	lyPtrace(PTRACE_SYSCALL, pid);
	waitpid(pid, NULL, 0);
	lyPtrace(PTRACE_SYSCALL, pid);
	waitpid(pid, NULL, 0);
	lyPtrace(PTRACE_GETREGSET, pid, &iov);
	uint64_t result = regs.regs[0];
	iov.iov_base = &original_regs;
	iov.iov_len = sizeof(original_regs);
	lyPtrace(PTRACE_SETREGSET, pid, &iov);	// 恢复堆栈
	lyPtrace(PTRACE_DETACH, pid);
	return result;
}
