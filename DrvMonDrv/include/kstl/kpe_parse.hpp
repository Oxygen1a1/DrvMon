#pragma once
#ifndef _KPE_PARSE_
#define _KPE_PARSE_

#include <fltKernel.h>
#include <ntstrsafe.h>
#include <ntimage.h>
/*���ڽ����洢�ڴ����ϵ��ļ��������Ѿ����ڴ��е��ļ�*/
/*�ṩ
1.ö�ٵ����� ��
2.ö�ٵ���� ��
3.ö��ǩ����Ϣ ��
4.ö�ٺ����쳣�� ��
5.ö�����PE�ļ���ʼ��ַ ��
6.rva to va ��
7.va to rva ��
8.map to memory(����PE�����޸�)��
9.get sections ��
10.get entry point ��
11.pattern find in pe ��
*/
namespace kstd {


	//ע�� �ܶຯ��ֻ֧��x64��
	//�ṩ������ĺ���  �����������̳�
	//ע�� ����ຯ��һ��ֻ��ʹ���ڴ� ����ʹ��·���;��
	//Ŀǰ��֪���Ƿ�������PE�Ͳ�������������? ��ʵ���������,����ֻ����������(���������ָ�Ը���������,��Ȼ����rav to foa foa to rva)
	//���Ǹ�������Ŀ¼���õĶ���rva ���Ե�����
	//�������������г�Ա�����ĵ�һ����Աbase�������쵽�ڴ��PE�ļ�
	class PeParseBaisc {
	public:
		enum class OperType {
			r0,
			r3
		};

		typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
			DWORD32 BeginAddress;
			DWORD32 EndAddress;
			union {
				DWORD32 UnwindInfoAddress;
				DWORD32 UnwindData;
			} DUMMYUNIONNAME;

		} RUNTIME_FUNCTION, * PRUNTIME_FUNCTION, _IMAGE_RUNTIME_FUNCTION_ENTRY, * _PIMAGE_RUNTIME_FUNCTION_ENTRY;
	public:
		//��R3��GetProcAddresһ��
		UINT_PTR getProcAddress(void* module_base,char* func_name,bool is_ordinal);

	public:

		//ö�ٸ�PE�ļ�������IAT
		NTSTATUS enumrateIat(
			void* base, 
			void(*callback)(UINT_PTR* iat, UINT_PTR* _int, char* dllname, bool is_ordinal, char* func_name, void* context), 
			void* context
		);

		//ö��PE�ļ��ĺ�����ʼ��ַ�ͽ�����ַ ͨ���쳣��ö��
		NTSTATUS enumrateFuncs(void* base, void(*callback)(ULONG start_rva, ULONG end_rva, void* context), void* context);

		//ö��PE�ļ��ĵ�����
		NTSTATUS enumrateExportTable(void* base, void(*callback)(char* name,
			int index,/*�����name��nametable��˳��,��Ҫͨ��ordtableת����funtable��λ��*/
			PSHORT ord_table ,
			PULONG func_table,
			void* context), void* context);

		//ö��PE�ļ����쳣��
		NTSTATUS enumrateExceptionTable(void* base, void(*callback)(PRUNTIME_FUNCTION runtime_func,void* context), void* context);

		//base������֮���
		ULONG rva2foa(void* base, ULONG rva);
		ULONG foa2rva(void* base,ULONG foa);

		//base�Ǿ�������֮���
		NTSTATUS mapToMemory(void* base, void* map_addr, size_t map_size,OperType map_type=OperType::r0);


		PIMAGE_SECTION_HEADER getSections(void* base,ULONG* size_of_sections=nullptr);
		
		ULONG getEntryPointRva(void* base);

		//���ں˻�ȡPE�ļ���ǩ����Ϣ δʵ��
		char* getIssuerName(void* base);
		char* getSubjectName(void* base);

		//ģʽƥ�� 
		//pattern k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".text");
		UINT_PTR patternFind(unsigned long long addr, unsigned long size, const char* pattern, const char* mask);

		UINT_PTR patternFindSections(unsigned long long base, const char* pattern, const char* mask, const char* name);

		bool isValidX64PE(char* base);
	private:
		static const DWORD X64 = 0x8664;
		bool patternCheck(const char* data, const char* pattern, const char* mask);

		void* getModuleBase(char* module_name, OperType type = OperType::r0,ULONG* size=nullptr);

		static void reloc(void* base);
	
	public:
	};


	inline NTSTATUS PeParseBaisc::enumrateExceptionTable(
		void* base, 
		void(*callback)(PeParseBaisc::PRUNTIME_FUNCTION runtime_func, void* context),
		void* context)
	{
		if (!isValidX64PE((char*)base)) return STATUS_INVALID_PARAMETER;

		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((UINT_PTR)base + dos_header->e_lfanew);
		auto opt_header = nt_headers->OptionalHeader;
		auto datadir = opt_header.DataDirectory;
		if (datadir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size == 0) return STATUS_SUCCESS;

		auto exception_table= reinterpret_cast<_IMAGE_RUNTIME_FUNCTION_ENTRY*>((UINT_PTR)base + datadir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
		
		//��ʼ����
		for (auto table = exception_table;
			(uintptr_t)table < (uintptr_t)exception_table + datadir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size
			; table++) {

			callback(table, context);

		}

		return STATUS_SUCCESS;
	}

	inline ULONG PeParseBaisc::rva2foa(void* base, ULONG rva)
	{
		auto foa = 0ul;
		auto count_sections = 0ul;
		auto sections = getSections(base,&count_sections);
		if (sections == nullptr) return foa;

		for (auto i=0ul;i<count_sections;i++) {
			auto sec = sections[i];

			if (rva >= sec.VirtualAddress || rva <= sec.VirtualAddress + sec.Misc.VirtualSize) {
				//find
				foa = rva - sec.VirtualAddress + sec.PointerToRawData;
				break;
			}

		}

		return foa;
	}

	inline ULONG PeParseBaisc::foa2rva(void* base, ULONG foa)
	{
		auto rva = 0ul;
		auto count_sections = 0ul;
		auto sections = getSections(base, &count_sections);
		if (sections == nullptr) return rva;

		for (auto i = 0ul; i < count_sections; i++) {
			auto sec = sections[i];

			if (foa >= sec.PointerToRawData || foa <= sec.PointerToRawData + sec.SizeOfRawData) {

				rva = foa - sec.PointerToRawData + sec.VirtualAddress;
				break;
			}
		}

		return rva;
	}

	//�������Ѿ��������!
	inline NTSTATUS PeParseBaisc::mapToMemory(void* base, void* map_addr, size_t map_size, OperType map_type)
	{
		//�ж��ǲ�����Ч���ض�λ����
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG RELOC_FLAG64

		auto status = STATUS_SUCCESS;
		if (map_type == OperType::r3) {
			status = STATUS_NOT_SUPPORTED;
			return status;
		}

		if (!isValidX64PE((char*)base) || !MmIsAddressValid(map_addr)) {
			status = STATUS_INVALID_PARAMETER;
			return status;
		}
		
		//��������ڴ浽map_addr
		memcpy(map_addr, base, map_size);
		//��ʼ�޸�iat

		struct Input_t {
			PeParseBaisc* _this;
			PeParseBaisc::OperType type;
		};

		auto input = Input_t{ this,map_type };

		if (!NT_SUCCESS(
			enumrateIat(
				map_addr,
				[](UINT_PTR* iat, UINT_PTR* _int, char* dllname, bool is_ordinal, char* func_name, void* context) {
					UNREFERENCED_PARAMETER(_int);
					auto input = reinterpret_cast<Input_t*>(context);

					//*iat = getProcAddress();
					auto dll_base = input->_this->getModuleBase(dllname, input->type);
					if (MmIsAddressValid(iat)) {
						*iat = input->_this->getProcAddress(dll_base, func_name, is_ordinal);
					}
				},
				&input
			)
		)) {
			//failed
			return STATUS_UNSUCCESSFUL;
		}

		reloc(map_addr);
		return status;
	}

	inline UINT_PTR PeParseBaisc::getProcAddress(void* module_base, char* func_name, bool is_ordinal)
	{
		if (!MmIsAddressValid((void*)func_name) && !is_ordinal) return 0;

		if (!isValidX64PE((char*)module_base)) return 0;

		struct Input_t {
			char* func_name;
			bool is_ordinal;
			void* module_base;
			UINT_PTR find_addr;
		};

		auto input = Input_t{ func_name,is_ordinal,module_base,0 };
		//���ú�������export
		enumrateExportTable(module_base,
		[](char* name, int index, PSHORT ord_table, PULONG func_table, void* context){
			auto input = reinterpret_cast<Input_t*>(context);
			if (!input->is_ordinal) {

				if (strcmp(name,input->func_name) != 0) return;
				//find
				input->find_addr= func_table[ord_table[index]]+(UINT_PTR)input->module_base;
				return;
			}
			else {

				auto ord = (unsigned long long)(input->func_name)-1;
				input->find_addr = func_table[ord] + (UINT_PTR)input->module_base;

			}
		},
		(void*)&input//context
		);


		return input.find_addr;
	}

	//sync function
	inline NTSTATUS PeParseBaisc::enumrateIat(
		void* base, 
		void(*callback)(UINT_PTR* iat, UINT_PTR* _int, char* dllname, bool is_ordinal,char* func_name, void* context), 
		void* context
	) {
		if(!isValidX64PE((char*)base)) return STATUS_INVALID_PARAMETER;

		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((UINT_PTR)base+dos_header->e_lfanew);
		auto opt_header = nt_headers->OptionalHeader;
		auto datadir=opt_header.DataDirectory;
		if (datadir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) return STATUS_SUCCESS;

		auto import_descr = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>((UINT_PTR)base+datadir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		

		while (import_descr->Name) {

			auto iat = reinterpret_cast<ULONG_PTR*>(import_descr->FirstThunk + (UINT_PTR)(base));
			auto _int = reinterpret_cast<ULONG_PTR*>(import_descr->OriginalFirstThunk + (UINT_PTR)(base));
			if (_int == nullptr) _int = iat;

			for (; *iat; ++iat, ++_int) {


				if (IMAGE_SNAP_BY_ORDINAL(*_int)) {
					callback(iat, _int, (char*)((UINT_PTR)base + import_descr->Name), true, (char*)*_int, context);

				}
				else {
					callback(iat, _int, (char*)((UINT_PTR)base + import_descr->Name), false, 
						((IMAGE_IMPORT_BY_NAME*)((UINT_PTR)base + *_int))->Name,
						context);
				}

			}

			import_descr++;
		}

		return STATUS_SUCCESS;
	}

	inline NTSTATUS PeParseBaisc::enumrateFuncs(void* base, void(*callback)(ULONG start_rva,ULONG end_rva, void* context), void* context)
	{
		if (!isValidX64PE((char*)base)) return STATUS_INVALID_PARAMETER;

		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((UINT_PTR)base + dos_header->e_lfanew);
		auto opt_header = nt_headers->OptionalHeader;
		auto datadir = opt_header.DataDirectory;
		if (datadir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size == 0) return STATUS_SUCCESS;

		auto exception_table = reinterpret_cast<_IMAGE_RUNTIME_FUNCTION_ENTRY*>((UINT_PTR)base + datadir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

		//��ʼ����
		for (auto table = exception_table;
			(uintptr_t)table < (uintptr_t)exception_table + datadir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size
			; table++) {

			callback(table->BeginAddress,table->EndAddress,context);

		}

		return STATUS_SUCCESS;
	}

	inline NTSTATUS PeParseBaisc::enumrateExportTable(void* base, void(*callback)(char* name, int index, PSHORT ord_table, PULONG func_table, void* context), void* context)
	{
		if (!isValidX64PE((char*)base)) return STATUS_INVALID_PARAMETER;

		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((UINT_PTR)base + dos_header->e_lfanew);
		auto opt_header = nt_headers->OptionalHeader;
		auto datadir = opt_header.DataDirectory;

		if (datadir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) return STATUS_SUCCESS;

		auto export_table = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((UINT_PTR)base + datadir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		//nameTable����Ǻ�������RVA
		auto name_table = (PULONG)(export_table->AddressOfNames + (PUCHAR)base);
		//������funcTable����ת����Ҫ���
		auto ordinal_table = (PSHORT)(export_table->AddressOfNameOrdinals + (PUCHAR)base);
		auto func_table = (PULONG)(export_table->AddressOfFunctions + (PUCHAR)base);


		for (unsigned i=0;i<export_table->NumberOfNames;i++) {
			auto name = (char*)(name_table[i] + (ULONG_PTR)base);
			callback(name, i, ordinal_table, func_table, context);
		}

		return STATUS_SUCCESS;
	}

	inline PIMAGE_SECTION_HEADER PeParseBaisc::getSections(void* base, ULONG* size_of_sections)
	{
		if(!isValidX64PE((char*)base)) return nullptr;

		auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew + (UINT_PTR)(base));
		if (MmIsAddressValid(size_of_sections)) {

			*size_of_sections = nt_headers->FileHeader.NumberOfSections;
		}

		return IMAGE_FIRST_SECTION(nt_headers);
	}

	inline ULONG PeParseBaisc::getEntryPointRva(void* base)
	{
		if (!isValidX64PE((char*)base)) return 0;

		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((UINT_PTR)base + dos_header->e_lfanew);
		auto opt_header = nt_headers->OptionalHeader;

		return opt_header.AddressOfEntryPoint;

	}

	inline UINT_PTR PeParseBaisc::patternFind(unsigned long long addr, unsigned long size, const char* pattern, const char* mask)
	{
		size -= (unsigned long)strlen(mask);

		for (unsigned long i = 0; i < size; i++)
		{
			if (patternCheck((const char*)addr + i, pattern, mask))
				return addr + i;
		}

		return 0;
	}

	inline UINT_PTR PeParseBaisc::patternFindSections(unsigned long long base, const char* pattern, const char* mask, const char* name)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
		for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER p = &section[i];

			if (strstr((const char*)p->Name, name))
			{
				unsigned long long result = patternFind(base + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
				if (result) return result;
			}
		}

		return 0;
	}

	inline bool PeParseBaisc::patternCheck(const char* data, const char* pattern, const char* mask)
	{
		size_t len = strlen(mask);

		for (size_t i = 0; i < len; i++)
		{
			if (data[i] == pattern[i] || mask[i] == '?')
				continue;
			else
				return false;
		}

		return true;
	}


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
	};

	inline bool PeParseBaisc::isValidX64PE(char* base)
	{
		if (!MmIsAddressValid(base)) return false;

		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return false;

		auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((UINT_PTR)base + dos_header->e_lfanew);
		if (nt_headers->FileHeader.Machine != X64) return false;

		return true;
	}

	inline void* PeParseBaisc::getModuleBase(char* module_name, OperType type, ULONG* size)
	{
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




		// now not support r3 
		if (type == OperType::r3) return nullptr;

		ULONG needSize = 0;
		ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needSize);
		needSize *= 2;
		void* findBase = nullptr;

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
					if (MmIsAddressValid(size)) {

						*size = module_entry->Size;
					}
				}
			}

		} while (false);

		ExFreePool(info);
		return findBase;
	}

	inline void PeParseBaisc::reloc(void* base)
	{
		//�޸�reloc table
		char* pBase = (char*)base;
		auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;
		char* LocationDelta = pBase - pOpt->ImageBase;
		if (LocationDelta) {
			if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
				auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
				const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
				while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
					//�ض�λ���кܶ��
					//�ض�λ�ĸ���������IMAGE_BASE_RELOCATION����ط�
					//�ض�λ��ƫ�ƵĴ�С��WORD
					UINT64 AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(short);
					//ָ���ض�λ��ƫ��
					//typedef struct _IMAGE_BASE_RELOCATION {
					//	DWORD   VirtualAddress; //�ض�λ����ʼ��ַ��RVA
					//	DWORD   SizeOfBlock;
					//	//  WORD    TypeOffset[1];
					//Windows�ض�λ���ǰ�ҳ�漰��
					//����ĵ�ַ,����������һ��RVA����.
					//TypeOffset�и�4λ������ض����������
					//��12λ ��ʾ�����һҳ(4KB)��ƫ��
					unsigned short* pRelativeInfo = reinterpret_cast<unsigned short*>(pRelocData + 1);

					for (UINT64 i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
						//�����ض����TypeOffset
						if (RELOC_FLAG(*pRelativeInfo)) {
							//�жϸ�4λ �Ƿ���Ҫ�ض�λ

							//ֻ��ֱ��Ѱַ����Ҫ�ض�λ
							//pBase+RVA==��Ҫ�ض�λҳ��
							//ҳ��+0xfff & TypeOffset ����Ҫ�ض�λ�ĵ�ַ(һ��ֱ�ӵ�ַ)
							UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
							//��������Ҫ�������ַ��������װ�ص�ַ��ȥImageBase
							*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
						}
					}
					//��һ���ض�λ��(�Ͼ���ֹһ��ҳ����Ҫ�ض�λ)
					pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<char*>(pRelocData) + pRelocData->SizeOfBlock);
				}
			}
		}
	}


	//ֻ�ǹ��������ͬ,���캯����һ���ļ�·��/�Ѿ����ڴ��ָ�� ���ڸ�Baisc�ṩ
	class ParsePE : public PeParseBaisc {
	public:
		ParsePE(const wchar_t* file_path);
		ParsePE(const UNICODE_STRING& u_file_path);//nt path ����dos path����

		ParsePE(unsigned char* base, size_t size);
		ParsePE(void* base,size_t size):ParsePE((unsigned char*)(base),size){ }

		~ParsePE();

		//�����ƶ�����/��������
		ParsePE& operator= (const ParsePE& rhs);
		ParsePE& operator= (ParsePE&& rhs);

		ParsePE(const ParsePE& rhs);
		ParsePE(ParsePE&& rhs);

		void setBase();
	public:
		static bool isNtPath(const wchar_t* path);
	private:
		HANDLE __h_file;
		size_t __size;//pe file size
	private:
		static const unsigned pool_tag = 'Prpe';

	private:
		void* __base;//read pe file in memory  һ��Ҫ������������ĸ�!
		void* __noclean_base;//from memory do not need to clean memory
	public:
		void* _base;
	};


	inline ParsePE::ParsePE(const wchar_t* file_path):__h_file(0),__base(0),__size(0),__noclean_base(0),_base(0)
	{
		const unsigned MAX_PATH = 560;
		wchar_t file_full_path[MAX_PATH] = {};
		bool failed = true;
		UNICODE_STRING u_full_path = {};
		OBJECT_ATTRIBUTES oa{};
		IO_STATUS_BLOCK isb{};
		void* pe_buf = nullptr;

		//�����Ƿ�ҳ�ڴ���
		if (file_path == nullptr || !MmIsAddressValid((void*)file_path)) return;

		if (!isNtPath(file_path)) {
			//tansfrom dos path to nt path
			wcscpy(file_full_path, L"\\??\\");
			wcscat(file_full_path, file_path);
		}
		else {
			wcscpy(file_full_path, file_path);
		}

		RtlInitUnicodeString(&u_full_path, file_full_path);

		do {

			InitializeObjectAttributes(&oa, &u_full_path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0);
			//create file
			if (!NT_SUCCESS(
				ZwCreateFile(&__h_file, GENERIC_ALL, &oa, &isb, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, 0, 0, 0)
			)) {
				break;
			}

			FILE_STANDARD_INFORMATION file_info{};
			LARGE_INTEGER offset{ 0 };
			//get file size
			if (!NT_SUCCESS(ZwQueryInformationFile(__h_file, &isb,
				&file_info, sizeof(file_info), FileStandardInformation)))
			{
				break;
			}

			__size = file_info.EndOfFile.LowPart;
			
			//��ΪPEBaiscȫ�ǽ��ܵ���map���� ����������Ȱ��ڴ�mapһ��
			pe_buf = ExAllocatePoolWithTag(NonPagedPool, __size, pool_tag);
			if (pe_buf == nullptr) {
				break;
			}

			if (!NT_SUCCESS(ZwReadFile(__h_file, 0, 0, 0, &isb, pe_buf, (ULONG)__size, &offset, 0))) {
				break;
			}

			if (!NT_SUCCESS(ZwFlushBuffersFile(__h_file, &isb))) {
				break;
			}

			if(!isValidX64PE((char*)pe_buf)) break;

			auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(pe_buf);
			auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((UINT_PTR)pe_buf + dos_header->e_lfanew);
			auto opt_header = nt_headers->OptionalHeader;
			//��ʼmap
			__base = ExAllocatePoolWithTag(NonPagedPool, opt_header.SizeOfImage, pool_tag);
			if (!__base) {
				break;
			}

			auto section = IMAGE_FIRST_SECTION(nt_headers);

			//�����Ǹ�����PEͷ
			memcpy(__base, pe_buf, PAGE_SIZE);

			for (USHORT i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
				if (!section[i].SizeOfRawData) continue;
				memcpy((PUCHAR)__base + section[i].VirtualAddress,(PUCHAR)pe_buf+section[i].PointerToRawData , section[i].SizeOfRawData);
			}

			failed = false;

		} while (false);



		//clean up
		if (pe_buf) {
			ExFreePool(pe_buf);
		}
		if (failed) {
			if (__h_file != 0) {
				ZwClose(__h_file);
				__h_file = 0;
			}
			if (__base != nullptr) {
				ExFreePool(__base);
				__base = nullptr;
			}
		}

		setBase();
	}

	//ֻ��Ҫ����һ��
	inline ParsePE::ParsePE(const UNICODE_STRING& u_file_path) : ParsePE(u_file_path.Buffer)
	{
	}

	inline ParsePE::ParsePE(unsigned char* base, size_t size) : __noclean_base(0),__base(0),__h_file(0),__size(0), _base(0)
	{
		if (!MmIsAddressValid(base) || size == 0) return;

		__noclean_base = base;
		__size = size;

		setBase();
	}

	//dtor ֻclean ��Ҫclean��
	inline ParsePE::~ParsePE()
	{
		if (MmIsAddressValid(__base)) {
			ExFreePool(__base);
			__base = nullptr;
		}
		if (__h_file) {
			ZwClose(__h_file);
			__h_file = nullptr;
		}
	}

	//��ֵ����
	inline ParsePE& ParsePE::operator=(const ParsePE& rhs)
	{
		_base = nullptr;
		//�ж�һ����ͨ��memory�ķ�ʽ����Ļ���ͨ��·��+readfile��ʽ�����
		if (MmIsAddressValid(rhs.__base)) {
			//����ֱ��ʡ��h_file,�Ҳ�������,ֱ�Ӹ���__base
			__base = ExAllocatePoolWithTag(NonPagedPool, rhs.__size, pool_tag);
			if (__base) {
				memcpy(__base, rhs.__base, rhs.__size);
			}
		}
		else if (MmIsAddressValid(rhs.__noclean_base)) {
			//���ֱ�Ӹ��ƾ�����
			__noclean_base = rhs.__noclean_base;
		}
		else {
			//��֪����ɶ����� Ӧ���ǳ�����
		}

		setBase();
		return *this;
	}

	//�ƶ���ֵ ��ԭ�������ݸ��ƹ�ȥ����
	inline ParsePE& ParsePE::operator=(ParsePE&& rhs)
	{
		_base = nullptr;
		//�ж�һ����ͨ��memory�ķ�ʽ����Ļ���ͨ��·��+readfile��ʽ�����
		if (MmIsAddressValid(rhs.__base)) {
			__base = rhs.__base;
			__h_file = rhs.__h_file;

			//���ԭ�������� ������
			rhs.__base = nullptr;
			rhs.__h_file = 0;
			
		}
		else if (MmIsAddressValid(rhs.__noclean_base)) {
			//���ֱ�Ӹ��ƾ�����
			__noclean_base = rhs.__noclean_base;
		}
		else {
			//��֪����ɶ����� Ӧ���ǳ�����
		}

		setBase();
		return *this;
	}

	//��������
	inline ParsePE::ParsePE(const ParsePE& rhs)
	{
		this->operator=(rhs);
	}

	//�ƶ�����
	inline ParsePE::ParsePE(ParsePE&& rhs):__h_file(0), __base(0), __size(0), __noclean_base(0)
	{
		_base = nullptr;
		//�ж�һ����ͨ��memory�ķ�ʽ����Ļ���ͨ��·��+readfile��ʽ�����
		if (MmIsAddressValid(rhs.__base)) {
			__base = rhs.__base;
			__h_file = rhs.__h_file;

			//���ԭ�������� ������
			rhs.__base = nullptr;
			rhs.__h_file = 0;

		}
		else if (MmIsAddressValid(rhs.__noclean_base)) {
			//���ֱ�Ӹ��ƾ�����
			__noclean_base = rhs.__noclean_base;
		}
		else {
			//��֪����ɶ����� Ӧ���ǳ�����
		}

		setBase();
	}

	inline void ParsePE::setBase()
	{
		_base = (__base) ? __base : __noclean_base;
	}

	inline bool ParsePE::isNtPath(const wchar_t* path)
	{
		auto ret = false;
		if (MmIsAddressValid((void*)path)) {

			if (wcsstr(path, L"\\??\\") != nullptr || wcsstr(path, L"\\DosDevice\\") != nullptr) {

				ret = true;
			}
		}
		return ret;
	}

}



#endif