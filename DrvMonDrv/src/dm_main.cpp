#include <fltKernel.h>
#include "../include/dm_ref.hpp"

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









	} while (0);
	
	
	return status;
}


VOID ldImgCallback(_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo) {

	FullImageName; ProcessId; ImageInfo;


}