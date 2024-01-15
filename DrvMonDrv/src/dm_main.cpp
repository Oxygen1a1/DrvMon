#include <fltKernel.h>
#include "../include/dm_ref.hpp"
#include "../include/kstl/khook.hpp"
#include "../include/kstl/kstring.hpp"
#include "../include/kstl/klog.hpp"


PEPROCESS hkIoGetCurrentProcess();
PETHREAD hkPsGetCurrentThread();
HANDLE hkPsGetCurrentProcessId();

auto fun1 = reinterpret_cast<PEPROCESS(*)()>(hkIoGetCurrentProcess);
auto fun2 = reinterpret_cast<PETHREAD(*)()>(hkPsGetCurrentThread);
auto fun3 = reinterpret_cast<HANDLE(*)()>(hkPsGetCurrentProcessId);
 

PEPROCESS hkIoGetCurrentProcess() {
	DbgPrintEx(77, 0, "hkIoGetCurrentProcess func is %p\r\n",fun1);

	return fun1();
}

PETHREAD hkPsGetCurrentThread() {
	DbgPrintEx(77, 0, "hkPsGetCurrentThread func is %p\r\n",fun2);

	return fun2();
}

HANDLE hkPsGetCurrentProcessId() {
	DbgPrintEx(77, 0, "hkPsGetCurrentProcessId func is %p\r\n",fun3);
	return fun3();
}




void testInlineHook() {

	auto inlinehk_ins = kstd::InlineHookManager::getInstance();
	if (inlinehk_ins == nullptr) {
		__debugbreak();
	}

	auto status = inlinehk_ins->init();
	if (!NT_SUCCESS(status)) {
		__debugbreak();
	}


	inlinehk_ins->destory();

	//一旦调用完这个 就不要再用了
	inlinehk_ins = kstd::InlineHookManager::getInstance();

	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun1);
	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun1);
	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun1);
	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun1);
	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun1);


	status = inlinehk_ins->init();
	status = inlinehk_ins->init();
	status = inlinehk_ins->init();
	status = inlinehk_ins->init();


	//because the func is speical,it's can called at any irql,so i use ipi to hook
	//but ipi called frecuency will called your cpu block!
	for (int i = 0; i < 100; i++) {
		
		fun1 = hkIoGetCurrentProcess;

		auto status2=inlinehk_ins->inlinehook(IoGetCurrentProcess, (void**)&fun1, kstd::InlineHookManager::HookType::Ipi);

		auto status1=inlinehk_ins->remove(IoGetCurrentProcess);
		

		if (!NT_SUCCESS(status1)) {
			//DbgPrintEx(77, 0, "[+]remove failed \r\n");
			__debugbreak();
		}
		if (!NT_SUCCESS(status2)) {
			//DbgPrintEx(77, 0, "[+]inline hook failed\r\n");
			__debugbreak();

		}

		DbgPrintEx(77, 0, "[+]%d\r\n",i);
	}
	
	for (int i = 0; i < 100; i++) {
		fun1 = hkIoGetCurrentProcess;
		fun2 = hkPsGetCurrentThread;
		fun3 = hkPsGetCurrentProcessId;

		inlinehk_ins->inlinehook(IoGetCurrentProcess, (void**)&fun1,kstd::InlineHookManager::HookType::Ipi);
		inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun2, kstd::InlineHookManager::HookType::Ipi);
		inlinehk_ins->inlinehook(PsGetCurrentProcessId, (void**)&fun3, kstd::InlineHookManager::HookType::Ipi);


		inlinehk_ins->remove(IoGetCurrentProcess);
		inlinehk_ins->remove(PsGetCurrentProcessId);
		inlinehk_ins->remove(PsGetCurrentThread);

		inlinehk_ins->remove(PsGetCurrentThread);// 鲁棒性测试

		DbgPrintEx(77, 0, "[+]%d\r\n", i);

	}


	inlinehk_ins->inlinehook(IoGetCurrentProcess, (void**)&fun1, kstd::InlineHookManager::HookType::Ipi);
	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun2, kstd::InlineHookManager::HookType::Ipi);
	inlinehk_ins->inlinehook(PsGetCurrentProcessId, (void**)&fun3, kstd::InlineHookManager::HookType::Ipi);

	inlinehk_ins->destory();


}


VOID ldImgCallback(_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo);




EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT drv,PUNICODE_STRING) {
	auto status = STATUS_SUCCESS;

	//bypass driver sign,now you can call PsSetLoadImageNotifyRoutine success
	kstd::SysInfoManager::byPassSignCheck(drv);

	drv->DriverUnload = [](PDRIVER_OBJECT)->void {

		PsRemoveLoadImageNotifyRoutine(ldImgCallback);

		kstd::DrvObjHookManager::getInstance()->destory();


	};


	do {

		//init image notify callback
		status = PsSetLoadImageNotifyRoutine(ldImgCallback);
		if (!NT_SUCCESS(status)) {
			LOG_DEBUG("failed to setload image notify! errcode:%x\r\n",status);
			break;
		}


		testInlineHook();


	} while (0);
	
	
	return status;
}


VOID ldImgCallback(_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo) {

	FullImageName; ProcessId; ImageInfo;

	

	//filter r3 image loaded
	if ((unsigned long long)ImageInfo->ImageBase < 0xf000000000000000) return;

	//filtering not driver module
	if (kstd::kwstring(FullImageName->Buffer).find(L".sys") == kstd::kwstring::npos) return;

	kstd::DrvObjHookManager::getInstance()->addDrvObjHook(ImageInfo->ImageBase,
		[](PDRIVER_OBJECT drv, PUNICODE_STRING u, void* context)->NTSTATUS {
			UNREFERENCED_PARAMETER(u);
			DbgPrintEx(77, 0, "[+]drv loaded! %ws \t context %p\r\n", drv->DriverName.Buffer, context);
			return STATUS_SUCCESS;
		},
		[](PDRIVER_OBJECT drv,void* context) {

			DbgPrintEx(77, 0, "[+]drv unloaded! %ws \t context %p\r\n", drv->DriverName.Buffer, context);
		},
		(void*)0x1234,
		(void*)0x4321
		);
}

