//include all the externl head files

#ifndef _DM_REF_
#define _DM_REF_

#include <fltKernel.h>
#include <ntstrsafe.h>

#include <kstl/kpe_parse.hpp>
#include <kstl/ksystem_info.hpp>
#include <kstl/khook.hpp>
#include <kstl/kstring.hpp>
#include <kstl/klog.hpp>
#include <kstl/kcallback.hpp>
#include <kstl/klist.hpp>
#include <kstl/kautolock.hpp>
#include <kstl/kstring.hpp>
#include <kstl/kavl.hpp>
#include <kstl/kmemory.hpp>

typedef struct LDR_DATA_TABLE_ENTRY {

	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	VOID* ExceptionTable;                                                   //0x10
	ULONG ExceptionTableSize;                                               //0x18
	VOID* GpValue;                                                          //0x20
	void* NonPagedDebugInfo;                        //0x28
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	struct _UNICODE_STRING FullDllName;                                     //0x48
	struct _UNICODE_STRING BaseDllName;                                     //0x58
	ULONG Flags;                                                            //0x68
	USHORT LoadCount;                                                       //0x6c
	union
	{
		USHORT SignatureLevel : 4;                                            //0x6e
		USHORT SignatureType : 3;                                             //0x6e
		USHORT Unused : 9;                                                    //0x6e
		USHORT EntireField;                                                 //0x6e
	} u1;                                                                   //0x6e
	VOID* SectionPointer;                                                   //0x70
	ULONG CheckSum;                                                         //0x78
	ULONG CoverageSectionSize;                                              //0x7c
	VOID* CoverageSection;                                                  //0x80
	VOID* LoadedImports;                                                    //0x88
	VOID* Spare;                                                            //0x90
	ULONG SizeOfImageNotRounded;                                            //0x98
	ULONG TimeDateStamp;                                                    //0x9c
	char padding[0x78];														//����WIN7 WIN8


}*PLDR_DATA_TABLE_ENTRY;


#define MAXIMUM_FILENAME_LENGTH 256

typedef struct _SYSTEM_MODULE_ENTRY
{
#ifdef _WIN64
	ULONGLONG Unknown1;
	ULONGLONG Unknown2;
#else
	ULONG Unknown1;
	ULONG Unknown2;
#endif
	PVOID BaseAddress;
	ULONG Size;
	ULONG Flags;
	ULONG EntryIndex;
	USHORT NameLength;  // Length of module name not including the path, this field contains valid value only for NTOSKRNL module
	USHORT PathLength;  // Length of 'directory path' part of modulename
	CHAR Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
#ifdef _WIN64
	ULONG Unknown1;
#endif
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 0xb,
	SystemKernelDebuggerInformation = 0x23,
	SystemFirmwareTableInformation = 0x4c
} SYSTEM_INFORMATION_CLASS;

extern "C" {
	NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength);
	NTKERNELAPI NTSTATUS NTAPI NtQuerySystemInformation(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	NTKERNELAPI PVOID RtlPcToFileHeader(PVOID pc, PVOID* base);
};




#endif // !_DM_REF_

