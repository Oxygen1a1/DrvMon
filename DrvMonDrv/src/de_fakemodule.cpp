#include <dm_fakemodule.h>


//Module used to generate and save kernel reloads
//Maintain related data structures
//Maintain a binary tree at the same time. This binary tree is a distributor. The distributor is responsible for finding the hooks added by the hookmodule module.
//Fakemodule also has an asm file, which also belongs to the fakemodule module. It is mainly responsible for saving the register environment. Jump to fakemodule.dispatcherFunc.

const unsigned pool_tag = 'fkMd';

//Fake PsLoadedModuleList
LDR_DATA_TABLE_ENTRY g_fake_loadedmodule;
//Fake PsLoadedModuleList lock
KSPIN_LOCK g_fake_loadedmodule_lock;

PLDR_DATA_TABLE_ENTRY findFakeLoadedModuleList(const kstd::kwstring& base_module_name);
void removeFakeLoaedModuleList(PLDR_DATA_TABLE_ENTRY entry);
PLDR_DATA_TABLE_ENTRY insertFakeLoadedModuleList(PLDR_DATA_TABLE_ENTRY entry, bool is_copy = true);
NTSTATUS initFakeLloadedModuleList();

//check is good opcode's first byte
#define isGoodOpcode(byte) (	\
(byte>=0x50 && byte<=0x57) ||	\
byte==0x41 ||	\
byte==0x48 || \
byte==0x4c || \
byte==0x49 || \
byte==0x4d \
)


struct FakeModuleEntry {
	MUSTADDED
	kstd::kwstring base_name;
	void* fake_base;
	ULONG image_size;
	void* org_base;
	LIST_ENTRY link;
	NTSTATUS status;

	NTSTATUS hookFakeModuleFuns() {
		
		if (!MmIsAddressValid(fake_base) || !MmIsAddressValid(org_base)) {
			status = STATUS_INVALID_PARAMETER;
			return status;
		}

		kstd::ParsePE ppe(org_base, image_size);
		//emumrate all the functions of module,then get the rva,hook copied module functions and jmp to really functions
		ppe.enumrateFuncs(ppe._base, [](ULONG start_rva,ULONG end_rva,void* context) ->void {
			
			unsigned char jmp_code[] = {
				0x48,0xb8,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,//mov rax,0
				0xff,0xd0,//call rax(call log function)
				0x48,0xb8,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,//mov rax,0
				0xff,0xe0//jmp rax(jmp to original func) 
			};

			if (end_rva - start_rva < sizeof jmp_code) return;/*too small to can not hook*/

			auto _this = reinterpret_cast<FakeModuleEntry*>(context);

			//get funtions start,it'll a big problem

			//that's may still get error function head,looking following code,even though we skip the 0xcc to the function's head,but -
			// actually,000000014040103 is what we really needed,so we also should check -
			// the Is the address align with 0x10
			
			//.text:0000000140401027 CC CC CC CC CC CC 0F 1F + align 10h
			//.text : 0000000140401030; Exported entry 370. ExpInterlockedPopEntrySList
			
			// however...that's also will get error function head...
			//fffff801`5fb636ab cc              int     3
			//nt!KiInitializeMutant:
			//fffff801`5fb636ac 48896c2408      mov     qword ptr[rsp + 8], rbp

			/*while ((start_rva & 0xf) != 0) start_rva++;*/

			//so I decide to use the following check way
			//1.get first 0xcc
			//2.if not align with 0x10,check it's byte,if is 0x48,assume it's function head
			//3.if not begin with 0x48,start_rva++ untill to align with 0x10
			if (*((PUCHAR)(_this->fake_base) + start_rva - 1) != 0xcc) {

				//if not begin with 0xcc,skip all the bytes untill to 0xcc
				while (*((PUCHAR)(_this->fake_base) + start_rva) != 0xcc) start_rva--;
				start_rva++;

				//then check if align with 0x10
				//if not,check it begin with good opcode
				//if it is,that's probably function head.if not,start_rva dec untill align with 0x10
				if ((start_rva & 0xf) != 0) { 

					if (!isGoodOpcode(*((PUCHAR)(_this->fake_base) + start_rva))) while ((start_rva & 0xf) != 0) start_rva++;

				}

			}

			*reinterpret_cast<UINT_PTR*>(jmp_code + 2) = (UINT_PTR)asm_func_log;
			*reinterpret_cast<UINT_PTR*>(jmp_code + 14) = start_rva + (ULONG_PTR)_this->org_base;

			//this address we can modify directly because the memory is rwx
			memcpy((PUCHAR)(_this->fake_base) + start_rva, jmp_code, sizeof jmp_code);

			
		},this);

		return STATUS_SUCCESS;
	}

	FakeModuleEntry(const kstd::kwstring& base_module_name) : 
		fake_base(nullptr), image_size(0), org_base(nullptr), base_name(base_module_name), link({}),status(STATUS_SUCCESS)
	{
		org_base = find_module_base(base_module_name.c_str(), &image_size);

		do {

			if (!org_base) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			//alloc a memory
			fake_base = ExAllocatePoolWithTag(NonPagedPool, image_size, pool_tag);
			if (!fake_base) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			//这里一定一定要置0xcc,因为后面有用!
			memset(fake_base, 0xcc, image_size);

			//开始拷贝
			for (ULONG bytes = 0; bytes < image_size; bytes += PAGE_SIZE) {
				if (MmIsAddressValid((PUCHAR)org_base + bytes)) {
					memcpy((PUCHAR)fake_base + bytes, (PUCHAR)org_base + bytes, PAGE_SIZE);
				}
			}

			//when the copy done,we start to hook all the function of the module, 
			status=hookFakeModuleFuns();
			if (!NT_SUCCESS(status)) {
				break;
			}

		} while (false);

		if (!NT_SUCCESS(status)) {
			if (MmIsAddressValid(fake_base)) {
				ExFreePool(fake_base);
				fake_base = nullptr;
			}
				
		}

		return;
	
	}

	FakeModuleEntry() : fake_base(0), status(STATUS_UNSUCCESSFUL) {};
	~FakeModuleEntry() {
		if (MmIsAddressValid(fake_base) && NT_SUCCESS(status)) {
			ExFreePool(fake_base);
			fake_base = nullptr;
		}
	}

	//delete copy ctor and copy operator 
	FakeModuleEntry(const FakeModuleEntry& rhs) = delete;
	FakeModuleEntry& operator=(const FakeModuleEntry& rhs) = delete;

	FakeModuleEntry(FakeModuleEntry&& rhs) : base_name(nullptr) {
		this->base_name = rhs.base_name;
		this->fake_base = rhs.fake_base;
		this->image_size = rhs.image_size;
		this->org_base = rhs.org_base;

		rhs.fake_base = nullptr;
	}

	FakeModuleEntry& operator=(FakeModuleEntry&& rhs) {
		this->base_name = rhs.base_name;
		this->fake_base = rhs.fake_base;
		this->image_size = rhs.image_size;
		this->org_base = rhs.org_base;

		rhs.fake_base = nullptr;
		return *this;
	}

};

//maintian fakemodule global list and it's thread-safty
kstd::Klist<FakeModuleEntry> g_fake_modules;

struct DriverCheatEntry {
	MUSTADDED

	PDRIVER_OBJECT drv;
	PLDR_DATA_TABLE_ENTRY org_ldr;
	PLDR_DATA_TABLE_ENTRY new_ldr;/*for cheating drivers*/
	kstd::kwstring full_path;
	LIST_ENTRY link;
	NTSTATUS status;

	void iatSwift(const kstd::Klist<FakeModuleEntry>& fake_modules) {
		if (!MmIsAddressValid(drv) || !MmIsAddressValid(new_ldr)) {
			return;
		}

		kstd::ParsePE ppe(drv->DriverStart, drv->DriverSize);
		ppe.enumrateIat(ppe._base, [](UINT_PTR* iat,UINT_PTR* _int,char* dllname,bool is_ordinal,char* func_name,void* context)->void {
			UNREFERENCED_PARAMETER(_int);
			auto modules = reinterpret_cast<kstd::Klist<FakeModuleEntry>*>(context);
			FakeModuleEntry find;
			wchar_t w_base_name[256]{};

			s2w(dllname,w_base_name,sizeof w_base_name/sizeof wchar_t);
			find.fake_base = nullptr;
			find.base_name = w_base_name;


			auto find_entry=modules->find(find, [](const FakeModuleEntry& x,const FakeModuleEntry& y) {
				return x.base_name == y.base_name;
			});


			if (find_entry == nullptr) {
				//fatal error
				LOG_ERROR("failed to find module:%ws\r\n", w_base_name); /*that means this func locating module not be copied*/
				breakOnlyDebug();
				return;
			}

			kstd::ParsePE pe_fakemodule(find_entry->fake_base, find_entry->image_size);
			auto addr=pe_fakemodule.getProcAddress(pe_fakemodule._base, func_name, is_ordinal);
			if (addr == 0) {
				LOG_ERROR("failed to get func %s addr\r\n", func_name);
				breakOnlyDebug();
				return;
			}

			//This has a very weird BUG. The triggering conditions are extremely harsh, but it may also be triggered.
			//1. The function is a leaf function of no excpet. There is no record in the pdata section. However, this kind of function is generally small, so it doesn’t matter if you use the fake module directly.
			//2. However, the memory happens to be relatively small, which causes ntos page change, which is more embarrassing. At this time, the copy is not successful!
			//3. BSOD will occur directly at this time!, so strategically abandon this incredible shit dick function, because generally this function is an irrelevant function like PsGetThreadTeb
			//4. Before, the content of the fake module was set value `0xcc` by memset. I only need to determine whether this place is byte OXCC. If so, it means that it was not copied.
			//Then just use the original one. If this small function is missing, it will be missed.
			if (*(PUCHAR)addr == '\xcc') {
				//说明没有复制
				LOG_INFO("whatever,for some reasons,func %s from module %s not be copied!\r\n", func_name, dllname);
			}
			else {
				// *iat = addr; × because this address is read-only
				_memcpy(iat, &addr, sizeof addr);
			}

		}, (void*)&fake_modules);
	}

	DriverCheatEntry() =default;

	DriverCheatEntry(PDRIVER_OBJECT _drv) : drv(_drv), org_ldr(nullptr), new_ldr(nullptr), full_path(nullptr), link({}),status(STATUS_SUCCESS) {
	
		status = STATUS_SUCCESS;

		if (!MmIsAddressValid(drv)) return;

		do {

			org_ldr = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(drv->DriverSection);

			new_ldr = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ExAllocatePoolWithTag(NonPagedPool, sizeof LDR_DATA_TABLE_ENTRY, pool_tag));
			if (!new_ldr) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			memcpy(new_ldr, org_ldr, sizeof LDR_DATA_TABLE_ENTRY);

			full_path = org_ldr->FullDllName.Buffer;
			//at same time insert global fake PsLoadedModuleList,attention,
			//I will control this LDR_ENTRY,so do not copy it to fake PsLoadedModuleList
			insertFakeLoadedModuleList(new_ldr,false);
			//Modify iat according to fakemodule
			iatSwift(g_fake_modules);
			//modify driver's ldr to cheat drv
			drv->DriverSection = new_ldr;
		} while (false);


		if (!NT_SUCCESS(status)) {
			if (MmIsAddressValid(new_ldr)) {

				drv->DriverSection = org_ldr;
				removeFakeLoaedModuleList(new_ldr);
				ExFreePool(new_ldr);
				new_ldr = nullptr;
			}
		}

	}
	~DriverCheatEntry() {

		if (!MmIsAddressValid(new_ldr) || !MmIsAddressValid(drv) || !MmIsAddressValid(org_ldr)) return;

		//resume driver's ldr to avoid to bsod
		drv->DriverSection = org_ldr;
		removeFakeLoaedModuleList(new_ldr);
		ExFreePool(new_ldr);
		new_ldr = nullptr;
		
	}


	DriverCheatEntry(const DriverCheatEntry& rhs) = delete;
	DriverCheatEntry& operator=(const DriverCheatEntry& rhs) = delete;

	DriverCheatEntry(DriverCheatEntry&& rhs) {
		this->drv = rhs.drv;
		this->full_path = rhs.full_path;
		this->new_ldr = rhs.new_ldr;
		this->org_ldr = rhs.org_ldr;

		rhs.new_ldr = nullptr;

	}

	DriverCheatEntry& operator=(DriverCheatEntry&& rhs) {
		this->drv = rhs.drv;
		this->full_path = rhs.full_path;
		this->new_ldr = rhs.new_ldr;
		this->org_ldr = rhs.org_ldr;

		rhs.new_ldr = nullptr;
		return *this;
	}
};


struct DispatcherEntry {
	MUSTADDED

	kstd::kwstring base_name;
	void* org_func;
	void(*callback)(Context_t* regs, void* context);
	void* context;
};


//maintians the gloal list which contained all the cheated driver module 
kstd::Klist<DriverCheatEntry> g_cheats_drvs;

//<discord>
kstd::kavl<DispatcherEntry> g_hook_dispatcher;

//ONLY SUPPORT above WIN10 
EXTERN_C ERESOURCE* PsLoadedModuleResource;


PVOID fakeAddress2OrgAddress(PVOID fake_address) {

	FakeModuleEntry fake_entry;
	fake_entry.fake_base = fake_address;

	auto fake_module = g_fake_modules.find(fake_entry, [](const FakeModuleEntry& x, const FakeModuleEntry& y) {
		return (y.fake_base <= x.fake_base && (UINT_PTR)y.fake_base + y.image_size >= (UINT_PTR)x.fake_base);
	});


	if (fake_module == nullptr) return nullptr;
	else return reinterpret_cast<PVOID>((UINT_PTR)fake_address - (UINT_PTR)fake_module->fake_base + (UINT_PTR)fake_module->org_base);

}

PVOID OrgAddress2fakeAddress(PVOID org_address) {
	FakeModuleEntry fake_entry;
	fake_entry.org_base = org_address;

	auto fake_module = g_fake_modules.find(fake_entry, [](const FakeModuleEntry& x, const FakeModuleEntry& y) {
		return (y.org_base <= x.org_base && (UINT_PTR)y.org_base + y.image_size >= (UINT_PTR)x.org_base);
	});


	if (fake_module == nullptr) return nullptr;
	else return reinterpret_cast<PVOID>((UINT_PTR)org_address - (UINT_PTR)fake_module->org_base + (UINT_PTR)fake_module->fake_base);

	
}

//get fake PLDR_DATA_TABLE_ENTRY according the address(address is really addess in org modules)
PLDR_DATA_TABLE_ENTRY findFakeLoadedModuleList(void* address) {
	FakeModuleEntry fake_entry;
	auto find = PLDR_DATA_TABLE_ENTRY{ nullptr };

	fake_entry.org_base = address;
	//first,we need to get fake base according module really base
	auto fake_module = g_fake_modules.find(fake_entry, [](const FakeModuleEntry& x, const FakeModuleEntry& y) {
		return (y.org_base <= x.org_base && (UINT_PTR)y.org_base+y.image_size>=(UINT_PTR)x.org_base);
	});

	if (fake_module == nullptr) return nullptr;

	//if find copied module,get it's fake base
	address = fake_module->fake_base;

	kstd::AutoLock<kstd::SpinLock> spinlock(&g_fake_loadedmodule_lock);

	for (auto link = &g_fake_loadedmodule.InLoadOrderLinks; ; ) {
		auto entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (address == entry->DllBase) {
			//find
			find = entry;
			break;
		}


		link = link->Flink;

		if (link == &g_fake_loadedmodule.InLoadOrderLinks) break;

	}

	return find;
}

//at same time,this func can be called by externl module,like de_hookmodule
PLDR_DATA_TABLE_ENTRY findFakeLoadedModuleList(const kstd::kwstring& base_module_name) {
	auto find = PLDR_DATA_TABLE_ENTRY{ nullptr };

	kstd::AutoLock<kstd::SpinLock> spinlock(&g_fake_loadedmodule_lock);

	for (auto link = &g_fake_loadedmodule.InLoadOrderLinks; ; ) {
		auto entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		
		//if (base_module_name==entry->BaseDllName.Buffer/*we need ingore senstive*/) {
		//
		//}

		if (_wcsnicmp(base_module_name.c_str(), entry->BaseDllName.Buffer,wcslen(entry->BaseDllName.Buffer))==0) {
			//find
			find = entry;
			break;
		}

		link = link->Flink;
		if (link == &g_fake_loadedmodule.InLoadOrderLinks) break;
	}

	return find;

}

void removeFakeLoaedModuleList(PLDR_DATA_TABLE_ENTRY entry) {

	kstd::AutoLock<kstd::SpinLock> _autolock(&g_fake_loadedmodule_lock);
	RemoveEntryList(&(entry->InLoadOrderLinks));
}

//accept a entry,if argument 2 set true,will copied and insert fake PsLoadedModuleList else will directly insert it to the list
PLDR_DATA_TABLE_ENTRY insertFakeLoadedModuleList(PLDR_DATA_TABLE_ENTRY entry,bool is_copy) {
	
	PLDR_DATA_TABLE_ENTRY ldr_entry = nullptr;
	if (!MmIsAddressValid(entry)) return nullptr;
	
	if (is_copy) {
		ldr_entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ExAllocatePoolWithTag(NonPagedPool, sizeof LDR_DATA_TABLE_ENTRY, pool_tag));
		if (!ldr_entry) return nullptr;
		memcpy(ldr_entry, entry, sizeof LDR_DATA_TABLE_ENTRY);
	}
	else {
		ldr_entry = entry;
	}

	//auto lock raii
	kstd::AutoLock<kstd::SpinLock> _autolock(&g_fake_loadedmodule_lock);
	InsertTailList(&(g_fake_loadedmodule.InLoadOrderLinks), &(ldr_entry->InLoadOrderLinks));

	return ldr_entry;
}

NTSTATUS initFakeLloadedModuleList() {
	auto ldr = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(kstd::SysInfoManager::getInstance()->getSysInfo()->PsLoadedModuleList);
	if (ldr == nullptr) return STATUS_NOT_SUPPORTED;

	//raii auto lock
	kstd::AutoLock<kstd::Resource> autolock(PsLoadedModuleResource);

	for ( auto link=ldr->InLoadOrderLinks.Flink;link!=&ldr->InLoadOrderLinks;link=link->Flink) {
		auto entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		
		if (kstd::kwstring(entry->BaseDllName.Buffer) == L"ntoskrnl.exe") {
			kstd::AutoLock<kstd::SpinLock> spinlock(&g_fake_loadedmodule_lock);
			//ntoskrnl.exe we need  a speical treatment
			auto org_link = g_fake_loadedmodule.InLoadOrderLinks;
			memcpy(&g_fake_loadedmodule, entry, sizeof LDR_DATA_TABLE_ENTRY);
			g_fake_loadedmodule.InLoadOrderLinks = org_link;/*resume to avoid to list corrupt*/
			continue;
		}
		
		//insert to fake PsLoadedModuleList 
		insertFakeLoadedModuleList(entry);

	}

	return STATUS_SUCCESS;
}

void destoryFakeLoadedModuleList() {

	kstd::AutoLock<kstd::SpinLock> spinlock(&g_fake_loadedmodule_lock);

	for (auto link = g_fake_loadedmodule.InLoadOrderLinks.Flink; link != &g_fake_loadedmodule.InLoadOrderLinks; ) {
		auto entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		link = link->Flink;
		RemoveEntryList(&(entry->InLoadOrderLinks));
		ExFreePool(entry);
	}

}


NTSTATUS fakeModuleInit() {

	//init list head
	g_fake_modules.init();
	g_cheats_drvs.init();

	auto suc = g_hook_dispatcher.init([]
	(_In_ struct _RTL_AVL_TABLE* Table,
	_In_ PVOID first,
	_In_ PVOID second)->RTL_GENERIC_COMPARE_RESULTS {
		UNREFERENCED_PARAMETER(Table);
		if ((ULONG_PTR)reinterpret_cast<DispatcherEntry*>(first)->org_func == 
			(ULONG_PTR)reinterpret_cast<DispatcherEntry*>(second)->org_func) 
			return GenericEqual;
		else if ((ULONG_PTR)reinterpret_cast<DispatcherEntry*>(first)->org_func <
			(ULONG_PTR)reinterpret_cast<DispatcherEntry*>(second)->org_func) 
			return GenericLessThan;
		else return GenericGreaterThan;
	}
	);

	if (!suc) return STATUS_UNSUCCESSFUL;

	//init fake loadedmodule list
	InitializeListHead(&g_fake_loadedmodule.InLoadOrderLinks);
	KeInitializeSpinLock(&g_fake_loadedmodule_lock);

	auto status=initFakeLloadedModuleList();
	if (!NT_SUCCESS(status)) {
		LOG_DEBUG("failed to init fake loadedmodule list! errcode:%x\r\n", status);
	}

	return status;

}

//add a fakemodule
NTSTATUS addAFakeModule(const kstd::kwstring& base_module_name) {

	FakeModuleEntry entry(base_module_name);
	if (!NT_SUCCESS(entry.status)) {
		LOG_DEBUG("failed to create a fake module!\r\n");
		return entry.status;
	}
	
	auto new_base = entry.fake_base;

	auto inserted=g_fake_modules.insert(kstd::move(entry), kstd::InsertType::tail);
	if (!inserted) {
		LOG_ERROR("failed to insert fakemodule to module list!\r\n");
		return STATUS_FAIL_FAST_EXCEPTION;
	}

	//modify it's entry in fake PsLoadedModuleList
	auto fake_ldr = findFakeLoadedModuleList(base_module_name);
	if (!fake_ldr) {
		//fatal error if occurs
		LOG_ERROR("failed to find module:%ws in fake PsLoadedModule List\r\n", base_module_name.c_str());
		
	}else fake_ldr->DllBase = new_base;
	
	return STATUS_SUCCESS;
}


/*when a driver loaded,call this function,and it will modify the driver's driver section(Ldr)*/
NTSTATUS addACheatDrv(PDRIVER_OBJECT drv) {
	auto status = STATUS_SUCCESS;

	if (!MmIsAddressValid(drv)) return STATUS_INVALID_PARAMETER;

	do {

		DriverCheatEntry entry(drv);

		if (!NT_SUCCESS(entry.status)) {
			LOG_DEBUG("failed to create a driver cheat entry! errcode:%x\r\n", entry.status);
			status = entry.status;
			break;
		}

		//insert this driver to global list
		auto suc=g_cheats_drvs.insert(kstd::move(entry), kstd::InsertType::tail);
		if (!suc) {
			LOG_DEBUG("failed to insert a drv cheat to list!\r\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}


	} while (false);


	return status;
}

//when driver unload,call this funcitons,it will resume the driver's ldr(driver section)
void removeACheatDrv(PDRIVER_OBJECT drv) {
	DriverCheatEntry find;
	find.new_ldr = nullptr;
	find.drv = drv;

	//LOG_INFO("current cheat drv size:%d\r\n", g_cheats_drvs.size());
	g_cheats_drvs.remove(find, [](const DriverCheatEntry& x,const DriverCheatEntry& y) {
		return x.drv == y.drv;
	});
	//LOG_INFO("current cheat drv size:%d\r\n", g_cheats_drvs.size());
}

//fakemodule destory
void fakeModuleDestory() {


	g_cheats_drvs.destory(nullptr);
	g_fake_modules.destory(nullptr);
	g_hook_dispatcher.destory(nullptr);
	destoryFakeLoadedModuleList();

}


//add a functions hook
//
//mov rax,log func
//call rax
//mov rax,o_func
//jmp o_func 
NTSTATUS addAHook(void* target_addr/*the address which you want to hook*/, void* hook_addr) {
	auto hook_module_base = (void*)0;
	auto hook_module_name = getModuleNameByPtr((PVOID)target_addr, &hook_module_base);
	FakeModuleEntry entry;

	if (hook_module_base == nullptr) {
		LOG_ERROR(" the address which needed to be hooked is not in any modules!\r\n");
		return STATUS_INVALID_PARAMETER;
	}

	auto rva = (ULONG_PTR)target_addr - (ULONG_PTR)hook_module_base;
	rva += 14/*skip the assblemy mov rax,call rax*/;

	entry.org_base = (void*)hook_module_base;
	auto fake_module = g_fake_modules.find(entry, [](const FakeModuleEntry& x, const FakeModuleEntry& y) {
		return y.org_base == x.org_base;
	});
	
	if (fake_module == nullptr) {
		LOG_ERROR("the module which the address you given has not  be copied!\r\n");
		return STATUS_INVALID_PARAMETER;
	}

	*reinterpret_cast<void**>((ULONG_PTR)fake_module->fake_base + rva) = hook_addr;
	return STATUS_SUCCESS;
}

//we do not use pdb,so only record iat functions
kstd::kstring getFuncNameFromExportByPtr(void* address) {
	auto caller_base = (void*)0;
	auto size = 0ull;
	kstd::kstring ret = "not found";

	getModuleNameByPtr((PVOID)address, &caller_base,&size);
	if (caller_base == nullptr) return ret;

	struct input_t {
		ULONG rva;/*in*/
		char func_name[100];/*out*/
	};

	input_t tmp = { (ULONG)((ULONG_PTR)address - (ULONG_PTR)caller_base),{} };
	kstd::ParsePE parse_pe(caller_base, size);

	parse_pe.enumrateExportTable(caller_base, [](char* name, int index, PSHORT ord_table, PULONG func_table, void* context) {
		if (func_table[ord_table[index]] == ((input_t*)context)->rva) strcpy_s(((input_t*)context)->func_name, name);		
	}, & tmp);


	if (tmp.func_name[0] != 0) ret = tmp.func_name;
	return ret;

}

//The assembly call is a function declaration in C language. 
// It is responsible for finding the next function to be executed, which is the global kavl maintained.
//The original function will be searched from kavl. If not, record it and return
extern "C" void dispatcherFunc(PContext_t context) {
	FakeModuleEntry entry;
	auto rsp = reinterpret_cast<ULONG_PTR*>(context->mRsp);
	auto caller_base = (void*)(0);
	//The stack recorded by context currently looks like this
	//| |
	//| |
	//|retadd2|<-conext.rsp
	//|retadd1|
	//retadd1 is the address where the deceived driver calls iat, just quote it directly;
	//retadd2 is the address of the fake module mov rax and call rax, so it needs to be converted. In fact, it is [context.rsp]-12 to get the function header.
	
	auto called_va = rsp[0] - 12;
	auto caller_va = rsp[1];


	//Search in g_fake_modules through called_va
	entry.org_base = (void*)called_va;

	auto fake_module = g_fake_modules.find(entry, [](const FakeModuleEntry& x, const FakeModuleEntry& y) {
		auto caller = reinterpret_cast<ULONG_PTR>(x.org_base);

		return ((UINT_PTR)y.fake_base <= caller && (ULONG_PTR)y.fake_base + y.image_size >= caller);
	});

	auto caller_module_name = getModuleNameByPtr((PVOID)caller_va,&caller_base);
	if (caller_module_name == L"unknow module") {
		entry.org_base = (void*)called_va;
		auto unknow_module =g_fake_modules.find(entry, [](const FakeModuleEntry& x, const FakeModuleEntry& y) {
		auto caller = reinterpret_cast<ULONG_PTR>(x.org_base);

		return ((UINT_PTR)y.fake_base <= caller && (ULONG_PTR)y.fake_base + y.image_size >= caller);
		});

		if (unknow_module != nullptr) {
			caller_module_name = unknow_module->base_name;
			caller_base = unknow_module->fake_base;
		}
	}

	if (fake_module == nullptr) {
		FLOG_ERROR("%p\tcalled unknow module:%p\r\n", caller_va, called_va);
	}
	else {
		
		auto caller_rva = caller_va - (ULONG_PTR)caller_base;
		auto called_rva = called_va - (ULONG_PTR)fake_module->fake_base;
		auto& called_module_name = fake_module->base_name;

		auto really_called_va = (ULONG_PTR)fake_module->org_base + called_rva;

		auto called_func_name = getFuncNameFromExportByPtr((void*)(really_called_va));
		
		if (called_func_name == "not found") FLOG_INFO("%50ws + 0x%x (0x%p)\tcalled\t%15ws + 0x%x (0x%p)\r\n",
				caller_module_name.c_str(), caller_rva, caller_va,
				called_module_name.c_str(), called_rva, really_called_va);
		
		else FLOG_INFO("%50ws + 0x%x (0x%p)\tcalled\t%15ws + 0x%x (0x%p)(%s)\r\n",
				caller_module_name.c_str(), caller_rva, caller_va,
				called_module_name.c_str(), called_rva, really_called_va,called_func_name.c_str());
	
	}
	

}