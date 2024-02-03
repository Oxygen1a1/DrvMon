#include <dm_hookmodule.h>

/*
* hook functions definations
* if you want to hook a new functions,pls add hk_functions in this file and call `fakemodule::addAHook`
* 
*/

//replace fake function ptr to cheat driver
auto hkMmGetSystemRoutineAddress(PUNICODE_STRING funcName)->void* {
	auto ret = MmGetSystemRoutineAddress(funcName);
	auto f_nt_ldr = findFakeLoadedModuleList(L"ntoskrnl.exe");
	auto f_hal_ldr = findFakeLoadedModuleList(L"HAL.dll");
	breakOnlyDebug();

	auto nt_size = 0ul,hal_size=0ul;

	auto nt_base=find_module_base(L"ntoskrnl.exe", &nt_size);
	auto hal_base = find_module_base(L"HAL.dll", &hal_size);

	if (nt_base <= ret && (void*)((ULONG_PTR)nt_base + nt_size) >= ret) {

		ret = (void*)((ULONG_PTR)ret - (ULONG_PTR)nt_base + (ULONG_PTR)f_nt_ldr->DllBase);

	}

	if (hal_base <= ret && (void*)((ULONG_PTR)hal_base + hal_size) >= ret) {

		ret = (void*)((ULONG_PTR)ret - (ULONG_PTR)hal_base + (ULONG_PTR)f_hal_ldr->DllBase);

	}
	
	return ret;
}

//replace fake kernel module base to cheat driver
auto NTAPI
hkNtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,OUT PULONG ReturnLength OPTIONAL)->NTSTATUS {

	auto status = NtQuerySystemInformation(SystemInformationClass,
		SystemInformation, SystemInformationLength, ReturnLength);

	if (!NT_SUCCESS(status)) return status;

	//LOG_INFO("NtQuerySystemInformation class is %x\r\n", SystemInformationClass);

	//current we only process `SystemModuleInformation`
	switch (SystemInformationClass)
	{
	case SystemModuleInformation: {
		for (size_t i = 0; i < reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(SystemInformation)->Count; i++) {
			auto module_entry = &reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(SystemInformation)->Module[i];
			auto fake_ldr = findFakeLoadedModuleList(module_entry->BaseAddress);
			if (fake_ldr == nullptr) continue;

			//modify base address
			module_entry->BaseAddress = fake_ldr->DllBase;
		}
	}
	default:
		break;
	}

	return status;

}

//replace fake kernel module base to cheat driver
auto NTAPI
hkZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL)->NTSTATUS {

	auto status = ZwQuerySystemInformation(SystemInformationClass,
		SystemInformation, SystemInformationLength, ReturnLength);

	if (!NT_SUCCESS(status)) return status;

	
	//current we only process `SystemModuleInformation`
	switch (SystemInformationClass)
	{
	case SystemModuleInformation: {
		for (size_t i = 0; i < reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(SystemInformation)->Count; i++) {
			auto module_entry = &reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(SystemInformation)->Module[i];
			auto fake_ldr = findFakeLoadedModuleList(module_entry->BaseAddress);
			if(fake_ldr==nullptr) continue;

			//modify base address
			module_entry->BaseAddress = fake_ldr->DllBase;
		}
	}
	default:
		break;
	}

	return status;
}

/*this also is a important functions,because if called this func use copied module's address,it'll return a nullptr*/
/*so we need progress this condition and return it's fake module base*/
auto hkRtlPcToFileHeader(PVOID pc,PVOID* base)->PVOID {
	auto ret = PVOID(nullptr);

	auto org_address=fakeAddress2OrgAddress(pc);
	if (org_address == nullptr) org_address = pc;/*that means we did not hook this module*/

	ret = RtlPcToFileHeader(org_address, base);

	if (org_address == pc) {
		/*that means we did not hook this module*/
		return ret;
	}
	else {
		/*that means we should modify ret value and base*/
		*base = OrgAddress2fakeAddress(ret);
		return OrgAddress2fakeAddress(ret);
	}

}