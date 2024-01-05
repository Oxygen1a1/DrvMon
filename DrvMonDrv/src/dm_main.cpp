#include <fltKernel.h>
#include "../include/dm_ref.hpp"
#include "../include/kstl/khook.hpp"


PEPROCESS hkIoGetCurrentProcess();
PETHREAD hkPsGetCurrentThread();
HANDLE hkPsGetCurrentProcessId();

auto fun1 = reinterpret_cast<PEPROCESS(*)()>(hkIoGetCurrentProcess);
auto fun2 = reinterpret_cast<PETHREAD(*)()>(hkPsGetCurrentThread);
auto fun3 = reinterpret_cast<HANDLE(*)()>(hkPsGetCurrentProcessId);


PEPROCESS hkIoGetCurrentProcess() {
	DbgPrintEx(77, 0, "hkIoGetCurrentProcess\r\n");

	return fun1();
}

PETHREAD hkPsGetCurrentThread() {
	DbgPrintEx(77, 0, "hkPsGetCurrentThread\r\n");

	return fun2();
}

HANDLE hkPsGetCurrentProcessId() {
	DbgPrintEx(77, 0, "hkPsGetCurrentProcessId\r\n");
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

	__debugbreak();

	for (int i = 0; i < 1000; i++) {

		inlinehk_ins->inlinehook(IoGetCurrentProcess, (void**)&fun1);
		inlinehk_ins->remove(IoGetCurrentProcess);

		fun1 = reinterpret_cast<PEPROCESS(*)()>(hkIoGetCurrentProcess);
		fun2 = reinterpret_cast<PETHREAD(*)()>(hkPsGetCurrentThread);
		fun3 = reinterpret_cast<HANDLE(*)()>(hkPsGetCurrentProcessId);
	}
	
	for (int i = 0; i < 1000; i++) {

		inlinehk_ins->inlinehook(IoGetCurrentProcess, (void**)&fun1);
		inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun2);
		inlinehk_ins->inlinehook(PsGetCurrentProcessId, (void**)&fun3);

		inlinehk_ins->destory();

		fun1 = reinterpret_cast<PEPROCESS(*)()>(hkIoGetCurrentProcess);
		fun2 = reinterpret_cast<PETHREAD(*)()>(hkPsGetCurrentThread);
		fun3 = reinterpret_cast<HANDLE(*)()>(hkPsGetCurrentProcessId);
	}

	inlinehk_ins = kstd::InlineHookManager::getInstance();

	if (inlinehk_ins == nullptr) {
		__debugbreak();
	}

	status = inlinehk_ins->init();
	if (!NT_SUCCESS(status)) {
		__debugbreak();
	}



	__debugbreak();
	for (int i = 0; i < 1000; i++) {

		inlinehk_ins->inlinehook(IoGetCurrentProcess, (void**)&fun1);
		inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun2);
		inlinehk_ins->inlinehook(PsGetCurrentProcessId, (void**)&fun3);


		inlinehk_ins->remove(IoGetCurrentProcess);
		inlinehk_ins->remove(PsGetCurrentThread);
		inlinehk_ins->remove(PsGetCurrentProcessId);
		inlinehk_ins->remove(IoGetCurrentProcess);
		inlinehk_ins->remove(PsGetCurrentThread);
		inlinehk_ins->remove(PsGetCurrentProcessId);
		inlinehk_ins->remove(IoGetCurrentProcess);
		inlinehk_ins->remove(PsGetCurrentThread);
		inlinehk_ins->remove(PsGetCurrentProcessId);


		fun1 = reinterpret_cast<PEPROCESS(*)()>(hkIoGetCurrentProcess);
		fun2 = reinterpret_cast<PETHREAD(*)()>(hkPsGetCurrentThread);
		fun3 = reinterpret_cast<HANDLE(*)()>(hkPsGetCurrentProcessId);

	}

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

	};

	do {

		//init image notify callback
		status = PsSetLoadImageNotifyRoutine(ldImgCallback);
		if (!NT_SUCCESS(status)) {
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


}