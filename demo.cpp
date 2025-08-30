#include <dlfcn.h>
#include <unistd.h>
#include "String/cmpstring.h"
#include "Remote/remote.cpp"
#include "lyPtrace/lyPtrace.cpp"
#include "syscall_mem/syscall_mem.cpp"
/**
 * @brief  用于内存使用例子
 * @author 凌烟
 * @date   2025-08-03
 * @license MIT开源协议
 */
 /*-----------*/
 // 理论上支持所有类型，除了冻结只支持D和F
 // 所以冻结请自己加别的类型
 // 但是可能别的类型有BUG，我没有尝试，不过我也暂时不维护这个了，功能大差不差，库文件也提供了ptrace调用，有需求者自己删改
 // 部分地方参考了AI的语法，如判断模板类型，这个我没学过，又比如获取自变量的数量和值，也是从AI处获取，而内存路径则是AI操作艾琳的，自己根据实际情况把rw改成了r，请注意
 /*-----------*/
int main()
{
	// 特征码使用例子
	/* Mem mem; mem.isCross =
	   true;//根据情况定，路进程读填true，内置填false
	   mem.get_pid("com.xiaoxi.XWar.x7sy");
	   mem.set_memory(Memory::RANGE_CODE_APP);
	   mem.Memory_Search<TYPE::DWORD>(999);
	   mem.Memory_Search_Offest<TYPE::DWORD>(999,0x4);
	   mem.Memory_Search_Offest_Write<TYPE::DWORD>(9999,0x0,false);//参考艾琳的冻结选择方式 
	 */

	// 基址使用例子
	// 动态
	/* 
	   //uint64_t ptr = mem.get_moudle("libil2cpp.so",Head::XA); //uint64_t
	   ptr1 = jump(addr+0x99999); //mem.setValue_addr(999,ptr1,false); */

	// 静态
	/* uint64_t addr =
	   mem.get_moudle("libil2cpp.so",Head::XA,1);//最后一个参数是获取第几个模块
	   mem.setValue_addr(999,addr,false); */
	// ptrace调用函数例子
	Mem mem1;
	mem1.isCross = true;
	pid_t appid = mem1.get_pid("com.xiaoxi.XWar.x7sy");
	cout<<appid<<endl;
	//uint64_t addr = get_mmap_base(appid,"mmap")这是你的
	uint64_t addr = get_func_remote_addr(appid, (uint64_t)mmap);
	uint64_t result = CallFunc(appid, addr,0,4096,7,0x22,0,0);	// 前两个不解释，第三个是你要传的参数，用的可自变量，参数顺序填，如mmap：6个参数----这个是函数调用
	/*uint64_t addr = mem1.findNull_Page(); 
	uint64_t result = CallFunc_SVC(appid, 222, addr, 0, 0x1000, 7, 0x22, 0, 0); //第两个是系统调用号，第三个是你的地址(用来写SVC调用指令)，第四个参数是要传的参数，用的可自变量，参数顺序填，如mmap：6个参数------这个是系统调用 */
	cout << hex<< result;		// result接受的是返回的x0，ARM64下函数返回值放x0(不管是普通调用还是系统调用都是如此)
	return 0;
}