#pragma once
#ifndef _FAKEMODULE_H_
#define _FAKEMODULE_H_
#include <fltKernel.h>
#include <dm_ref.hpp>
#include <dm_utils.h>

typedef struct Context_t
{
	ULONG64 mRax;
	ULONG64 mRcx;
	ULONG64 mRdx;
	ULONG64 mRbx;
	ULONG64 mRbp;
	ULONG64 mRsi;
	ULONG64 mRdi;
	ULONG64 mR8;
	ULONG64 mR9;
	ULONG64 mR10;
	ULONG64 mR11;
	ULONG64 mR12;
	ULONG64 mR13;
	ULONG64 mR14;
	ULONG64 mR15;
	ULONG64 mRsp;
}*PContext_t;

NTSTATUS fakeModuleInit();
void fakeModuleDestory();

NTSTATUS addAFakeModule(const kstd::kwstring& base_module_name);
NTSTATUS addACheatDrv(PDRIVER_OBJECT drv);
NTSTATUS addAHook(void* target_addr/*要hook的函数地址*/, void(*callback)(Context_t* regs, void* context), void* context);
void removeACheatDrv(PDRIVER_OBJECT drv);

EXTERN_C void asm_func_log(void);
#endif