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
NTSTATUS addAHook(void* target_addr/*need to hook functions address*/, void* hook_addr);
void removeACheatDrv(PDRIVER_OBJECT drv);
PLDR_DATA_TABLE_ENTRY findFakeLoadedModuleList(const kstd::kwstring& base_module_name);
PLDR_DATA_TABLE_ENTRY findFakeLoadedModuleList(void* address);
PVOID fakeAddress2OrgAddress(PVOID fake_address);
PVOID OrgAddress2fakeAddress(PVOID org_address);

//through registion context to get arguments
#define ARG1(context) context->mRcx
#define ARG2(context) context->mRdx
#define ARG3(context) context->mR8
#define ARG4(context) context->mR9
#define ARG5(context) (reinterpret_cast<ULONG_PTR*>(context->mRsp)[6])
#define ARG6(context) (reinterpret_cast<ULONG_PTR*>(context->mRsp)[7])
#define ARG7(context) (reinterpret_cast<ULONG_PTR*>(context->mRsp)[8])
#define ARG8(context) (reinterpret_cast<ULONG_PTR*>(context->mRsp)[9])
#define ARG9(context) (reinterpret_cast<ULONG_PTR*>(context->mRsp)[10])
#define ARG10(context) (reinterpret_cast<ULONG_PTR*>(context->mRsp)[11])
#define ARG11(context) (reinterpret_cast<ULONG_PTR*>(context->mRsp)[12])
#define ARG12(context) (reinterpret_cast<ULONG_PTR*>(context->mRsp)[13])
#define ARG13(context) (reinterpret_cast<ULONG_PTR*>(context->mRsp)[14])


EXTERN_C void asm_func_log(void);
#endif