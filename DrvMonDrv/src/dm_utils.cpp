#include <dm_ref.hpp>
#include <dm_utils.h>

void breakOnlyDebug() {

	if (!*KdDebuggerNotPresent) __debugbreak();

}

NTSTATUS w2s(const wchar_t* src, char* dest, size_t destSize) {

	if (!src || !dest || destSize == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	size_t i = 0;
	while (src[i] != L'\0' && i < destSize - 1)
	{
		if (src[i] <= 0x7F) // ASCII字符
		{
			dest[i] = (char)src[i];
		}
		else
		{
			// 如果遇到非ASCII字符，可以将其替换为'?'或其他占位符
			dest[i] = '?';
		}
		++i;
	}

	dest[i] = '\0';
	return STATUS_SUCCESS;
}

NTSTATUS s2w(const char* src, wchar_t* dest, size_t destSize) {


	if (!src || !dest || destSize == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	size_t i = 0;
	while (src[i] != '\0' && i < destSize - 1)
	{
		if (src[i] >= 0) // ASCII字符
		{
			dest[i] = (wchar_t)src[i];
		}
		else
		{
			// 如果遇到非ASCII字符，可以将其替换为L'?'或其他占位符
			dest[i] = L'?';
		}
		++i;
	}

	dest[i] = L'\0';

	return STATUS_SUCCESS;
}

auto find_module_base(const wchar_t* w_module_name, ULONG* size) -> void* {
	ULONG needSize = 0;
	ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needSize);
	needSize *= 2;
	void* findBase = nullptr;
	char module_name[256] = {};

	w2s(w_module_name, module_name, sizeof module_name);

	auto info = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(
		ExAllocatePoolWithTag(NonPagedPool, needSize, 'temp'));
	if (info == nullptr) {
		return nullptr;
	}

	do {

		if (!NT_SUCCESS(
			ZwQuerySystemInformation(SystemModuleInformation, info, needSize, &needSize))) {
			break;

		}

		for (size_t i = 0; i < info->Count; i++) {
			SYSTEM_MODULE_ENTRY* module_entry = &info->Module[i];
			if (strstr(module_entry->Name, module_name) != nullptr) {
				findBase = module_entry->BaseAddress;
				if (size != 0) {

					*size = module_entry->Size;
				}
			}
		}

	} while (false);
	ExFreePool(info);


	return findBase;
}


bool _memcpy(PVOID address, PVOID target_address, ULONG length)
{
	//处理跨物理页问题
	auto skipPhyPages = ((((UINT_PTR)(address)+length) >> PAGE_SHIFT) - ((UINT_PTR)address >> PAGE_SHIFT));

	if (!skipPhyPages) {
		bool result = false;
		PHYSICAL_ADDRESS physicial_address;
		physicial_address = MmGetPhysicalAddress(address);
		if (physicial_address.QuadPart)
		{
			PVOID maped_mem = MmMapIoSpace(physicial_address, length, MmNonCached);
			if (maped_mem)
			{
				memcpy(maped_mem, target_address, length);
				MmUnmapIoSpace(maped_mem, length);
				result = true;
			}
		}
		return result;
	}
	else {// 0x200 0x2900 3100 800 1000 
		auto firstPageCopy = PAGE_SIZE - (UINT_PTR)address & 0xfff;
		//需要处理跨页问题
		for (int i = 0; i <= skipPhyPages; i++) {
			if (i == 0) {
				PHYSICAL_ADDRESS physicial_address;
				physicial_address = MmGetPhysicalAddress(address);
				if (physicial_address.QuadPart)
				{
					PUCHAR maped_mem = (PUCHAR)MmMapIoSpace(physicial_address, firstPageCopy, MmNonCached);
					if (maped_mem)
					{
						memcpy(maped_mem, target_address, firstPageCopy);
						MmUnmapIoSpace(maped_mem, firstPageCopy);
					}
				}
				else return false;//没复制成功
			}
			else if (i == skipPhyPages) {
				auto lastPageCopy = length - PAGE_SIZE * (i - 1) - firstPageCopy;

				PHYSICAL_ADDRESS physicial_address;
				physicial_address = MmGetPhysicalAddress((PVOID)((UINT_PTR)(PAGE_ALIGN(address)) + PAGE_SIZE * i));
				if (physicial_address.QuadPart)
				{
					PUCHAR maped_mem = (PUCHAR)MmMapIoSpace(physicial_address, lastPageCopy, MmNonCached);
					if (maped_mem)
					{
						memcpy(maped_mem,
							(PUCHAR)target_address + firstPageCopy + (i - 1) * PAGE_SIZE, lastPageCopy);
						MmUnmapIoSpace(maped_mem, lastPageCopy);
					}
				}
				else return false;//没复制成功

			}
			else {
				PHYSICAL_ADDRESS physicial_address;
				physicial_address = MmGetPhysicalAddress((PVOID)((UINT_PTR)(PAGE_ALIGN(address)) + PAGE_SIZE * i));
				if (physicial_address.QuadPart)
				{
					PUCHAR maped_mem = (PUCHAR)MmMapIoSpace(physicial_address, PAGE_SIZE, MmNonCached);
					if (maped_mem)
					{
						memcpy(maped_mem,
							(PUCHAR)target_address + firstPageCopy + (i - 1) * PAGE_SIZE, PAGE_SIZE);
						MmUnmapIoSpace(maped_mem, PAGE_SIZE);
					}
				}
				else return false;//没复制成功

			}
		}
	}

	return true;
}


