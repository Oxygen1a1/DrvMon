#pragma once
#ifndef _DM_HOOKMODULE_H_
#define  _DM_HOOKMODULE_H_
#include <dm_ref.hpp>
#include <dm_fakemodule.h>


auto hkMmGetSystemRoutineAddress(PUNICODE_STRING funcName)->void*;

auto NTAPI
hkNtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL)->NTSTATUS;

auto NTAPI
hkZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL)->NTSTATUS;

auto hkRtlPcToFileHeader(PVOID pc, PVOID* base)->PVOID;

#endif

