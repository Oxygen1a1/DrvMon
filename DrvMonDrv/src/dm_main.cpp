#include <dm_ref.hpp>
#include <dm_fakemodule.h>
#include <dm_hookmodule.h>


VOID ldImgCallback(_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo);


EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT drv,PUNICODE_STRING) {
	auto status = STATUS_SUCCESS;

	//bypass driver sign,now you can call PsSetLoadImageNotifyRoutine success
	kstd::SysInfoManager::byPassSignCheck(drv);
	//init log
	kstd::Logger::init("DrvMon", L"\\??\\C:\\DrvMon.txt");

	//init image notify callback
	status = PsSetLoadImageNotifyRoutine(ldImgCallback);
	if (!NT_SUCCESS(status)) {
		LOG_ERROR("failed to setload image notify! errcode:%x\r\n", status);
		return status;
	}


	do {

		//init fakemodule 
		status=fakeModuleInit();
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("failed to init fakemodule! errcode:%x\r\n", status);
			break;
		}


		//add ntoskrnl.exe to fakemodule list
		status=addAFakeModule(L"ntoskrnl.exe");
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("failed to add fakemodule module name:%s errcoce:%x\r\n", "ntoskrnl.exe", status);
			break;
		}

		status = addAFakeModule(L"HAL.dll");//INSENSITIVE
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("failed to add fakemodule module name:%s errcoce:%x\r\n", "hal.dll", status);
			break;
		}
		status = addAFakeModule(L"FLTMGR.SYS");
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("failed to add fakemodule module name:%s errcoce:%x\r\n", "fltmgr.sys", status);
			break;
		}

		
		//add necessary hooks like ntquerysysteminfomation/mmgetsystemroutineaddress and so on...
		//it's also you can add funcs which you want to hook
		addAHook(MmGetSystemRoutineAddress, hkMmGetSystemRoutineAddress);
		addAHook(ZwQuerySystemInformation, hkZwQuerySystemInformation);
		addAHook(NtQuerySystemInformation, hkNtQuerySystemInformation);
		addAHook(RtlPcToFileHeader, hkRtlPcToFileHeader);

	} while (0);
	
	drv->DriverUnload = [](PDRIVER_OBJECT)->void {
		PsRemoveLoadImageNotifyRoutine(ldImgCallback);

		fakeModuleDestory();
		
		kstd::DrvObjHookManager::getInstance()->destory();
		kstd::InlineHookManager::getInstance()->destory();
		kstd::Logger::destory();
	};

	//now we has set img notify,so need to remove it;
	if(!NT_SUCCESS(status)) PsRemoveLoadImageNotifyRoutine(ldImgCallback);

	return status;
}


VOID ldImgCallback(_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo) {

	UNREFERENCED_PARAMETER(ProcessId);

	//filter r3 image loaded
	if ((unsigned long long)ImageInfo->ImageBase < 0xf000000000000000) return;

	//filtering not driver module
	if (kstd::kwstring(FullImageName->Buffer).find(L".sys") == kstd::kwstring::npos) return;

	//when drv loaded hook it's all the iats func
	//when drv unloaded, remove it from gloabl list to prevent os from memory leak and bsod
	kstd::DrvObjHookManager::getInstance()->addDrvObjHook(ImageInfo->ImageBase,
		[](PDRIVER_OBJECT drv, PUNICODE_STRING u, void* context)->NTSTATUS {
			UNREFERENCED_PARAMETER(u);
			UNREFERENCED_PARAMETER(context);

			auto ldr = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(drv->DriverSection);
			LOG_INFO("drv %ws loaded!\r\n", ldr->FullDllName.Buffer);
			return addACheatDrv(drv);

		},
		[](PDRIVER_OBJECT drv,void* context) {
			UNREFERENCED_PARAMETER(context);

			auto ldr = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(drv->DriverSection);
			LOG_INFO("drv %ws unloaded!\r\n", ldr->FullDllName.Buffer);
			removeACheatDrv(drv);
		},
		nullptr,
		nullptr
		);
}

