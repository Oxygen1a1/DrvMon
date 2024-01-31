#include <dm_fakemodule.h>

//���ڲ��� �� �����ں����ص�ģ��
//ά��������ݽṹ
//ͬʱά��һ��������,�����������һ���ַ���,�ַ��������ҵ�hookmodule���ģ����ӵ�hook
//fakemodule����һ��asm���ļ�,Ҳ������fakemoduleģ��,��Ҫ�Ǹ��𱣴�Ĵ������� ����fakemodule.dispatcherFunc��


const unsigned pool_tag = 'fkMd';

//�Լ�ά���ļٵ�PsLoadedModuleList
LDR_DATA_TABLE_ENTRY g_fake_loadedmodule;
//�Լ�ά���ļٵ�PsLoadedModuleList lock
KSPIN_LOCK g_fake_loadedmodule_lock;

PLDR_DATA_TABLE_ENTRY findFakeLoadedModuleList(const kstd::kwstring& base_module_name);
void removeFakeLoaedModuleList(PLDR_DATA_TABLE_ENTRY entry);
PLDR_DATA_TABLE_ENTRY insertFakeLoadedModuleList(PLDR_DATA_TABLE_ENTRY entry, bool is_copy = true);
NTSTATUS initFakeLloadedModuleList();

struct FakeModuleEntry {
	//������������,�����Ҫʹ��kstl������,����Ǳ���ӵ�,��Ȼû�а취����!
	//��Ϊ��û��ʵ��ȫ�ֵ�new,����delete����һ������;
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
		//������ǰģ������к��� Ȼ��õ�rva,�ü�ģ���Ӧ�ĺ���jmp��
		ppe.enumrateFuncs(ppe._base, [](ULONG start_rva,ULONG end_rva,void* context) ->void {
			
			unsigned char jmp_code[] = {
				0x48,0xb8,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,//mov rax,0
				0xff,0xd0,//call rax(call log function)
				0x48,0xb8,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,//mov rax,0
				0xff,0xe0//jmp rax(jmp to original func) 
			};

			if (end_rva - start_rva < sizeof jmp_code) return;/*����̫С,�����ڲ���hook*/

			auto _this = reinterpret_cast<FakeModuleEntry*>(context);

			//��ʱ������쳣�����...���Ǻ�����ʼrva,����ȡ����,������ �ҵ���һ��0xcc,�������ɺ���ͷ ��Ȼ���ܻ��������
			while (*((PUCHAR)(_this->fake_base) + start_rva) != 0xcc) start_rva--;
			start_rva++;

			*reinterpret_cast<UINT_PTR*>(jmp_code + 2) = (UINT_PTR)asm_func_log;
			*reinterpret_cast<UINT_PTR*>(jmp_code + 14) = start_rva + (ULONG_PTR)_this->org_base;

			//�����ǿ����޸ĵ�,��Ϊ������ڴ��ִ��,�ɶ�,��д
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

			//����һ��һ��Ҫ��0xcc,��Ϊ��������!
			memset(fake_base, 0xcc, image_size);

			//��ʼ����
			for (ULONG bytes = 0; bytes < image_size; bytes += PAGE_SIZE) {
				if (MmIsAddressValid((PUCHAR)org_base + bytes)) {
					memcpy((PUCHAR)fake_base + bytes, (PUCHAR)org_base + bytes, PAGE_SIZE);
				}
			}

			//�������֮��,��ʼ����hook ģ������к���,����jmp �������ĺ�����ַ
			status=hookFakeModuleFuns();
			if (!NT_SUCCESS(status)) {
				break;
			}

		} while (false);

		if (!NT_SUCCESS(status)) {
			if (!fake_base) {
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

	//��������ɾ��!
	FakeModuleEntry(const FakeModuleEntry& rhs) = delete;
	FakeModuleEntry& operator=(const FakeModuleEntry& rhs) = delete;
	//�ƶ��������Ҫ��
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

//ά����ģ���ȫ�ֱ��� �̰߳�ȫ��
kstd::Klist<FakeModuleEntry> g_fake_modules;

struct DriverCheatEntry {
	MUSTADDED

	PDRIVER_OBJECT drv;
	PLDR_DATA_TABLE_ENTRY org_ldr;
	PLDR_DATA_TABLE_ENTRY new_ldr;/*Ϊ����ƭ����*/
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
				LOG_ERROR("failed to find module:%ws\r\n", w_base_name); /*˵����û��Ϊ�����Ӽ�ģ��*/
				breakOnlyDebug();
				return;
			}

			kstd::ParsePE pe_fakemodule(find_entry->fake_base, find_entry->image_size);
			auto addr=pe_fakemodule.getProcAddress(pe_fakemodule._base, func_name, is_ordinal);
			if (addr == 0) {
				LOG_ERROR("failed to get func %s addr\r\n", func_name);
				breakOnlyDebug();
			}

			//���ֵ��� ����и��������BUG..��������������� ����Ҳ���ܻᴥ��
			//1.������no excpet��Ҷ���� ��pdata����û�м�¼ �������ֺ���һ���С��ֱ���ü�ģ���Ҳûɶ��ϵ
			//2.���ǣ������ڴ�Ƚ�С������ntos�Ļ�ҳ���ͱȽ������� ���ʱ����û���Ƴɹ���!
			//3.���ʱ��ֱ�ӻ�BSOD!,����ս���Է����������캯��,��Ϊһ�����ֺ�������ʲôPsGetThreadTeb�޹ؽ�Ҫ�ĺ���
			//4.��֮ǰ ��ģ������ݱ���RtlSecureZero�ˣ���ֻ��Ҫ�ж�һ������ط��ǲ����ֽ�0 �����,˵��û����
			//��ô��ֱ����ԭ���ľ��� ����С����©�˾�©��
			if (*(PUCHAR)addr == '\xcc') {
				//˵��û�и���
				LOG_INFO("whatever,for some reasons,func %s from module %s not be copied!\r\n", func_name, dllname);
			}
			else {
				// *iat = addr; �� �����ַ����д
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

			//������ȥ
			memcpy(new_ldr, org_ldr, sizeof LDR_DATA_TABLE_ENTRY);

			full_path = org_ldr->FullDllName.Buffer;

			//ͬʱ�����Լ�ά���ļٵ�PsLoadedModuleList ע��,��������������ҹ���ģ���˲�����
			insertFakeLoadedModuleList(new_ldr,false);
			//����fakemodule,�����޸�iat
			iatSwift(g_fake_modules);

			//�޸����������Ldr
			drv->DriverSection = new_ldr;
		} while (false);


		if (!NT_SUCCESS(status)) {
			if (MmIsAddressValid(new_ldr)) {
				//���޸�������ldr
				drv->DriverSection = org_ldr;
				removeFakeLoaedModuleList(new_ldr);
				ExFreePool(new_ldr);
				new_ldr = nullptr;
			}
		}

	}
	~DriverCheatEntry() {

		if (!MmIsAddressValid(new_ldr) || !MmIsAddressValid(drv) || !MmIsAddressValid(org_ldr)) return;

		//���޸�������ldr
		drv->DriverSection = org_ldr;
		removeFakeLoaedModuleList(new_ldr);
		ExFreePool(new_ldr);
		new_ldr = nullptr;
		
	}

	//��������ɾ��
	DriverCheatEntry(const DriverCheatEntry& rhs) = delete;
	DriverCheatEntry& operator=(const DriverCheatEntry& rhs) = delete;

	//�ƶ�������
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


//ά��iat hook������
kstd::Klist<DriverCheatEntry> g_cheats_drvs;

//ά��һ���ַ��� ��Ҫ������hook������
kstd::kavl<DispatcherEntry> g_hook_dispatcher;

//ONLY SUPPORT above WIN10 
//���������PsLoadedModuleList��ʱ��Ҫ����!
EXTERN_C ERESOURCE* PsLoadedModuleResource;


PLDR_DATA_TABLE_ENTRY findFakeLoadedModuleList(const kstd::kwstring& base_module_name) {
	auto find = PLDR_DATA_TABLE_ENTRY{ nullptr };

	kstd::AutoLock<kstd::SpinLock> spinlock(&g_fake_loadedmodule_lock);

	//��Ϊ�����û������ͷ��,���Ե���������
	for (auto link = &g_fake_loadedmodule.InLoadOrderLinks; ; ) {
		auto entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		
		if (base_module_name==entry->BaseDllName.Buffer) {
			//find
			find = entry;
			break;
		}

		if (link == &g_fake_loadedmodule.InLoadOrderLinks) break;

		link = link->Flink;
	}

	return find;

}

void removeFakeLoaedModuleList(PLDR_DATA_TABLE_ENTRY entry) {

	kstd::AutoLock<kstd::SpinLock> _autolock(&g_fake_loadedmodule_lock);
	RemoveEntryList(&(entry->InLoadOrderLinks));
}

//����һ��entry,������,Ȼ�����ӵ�ά���ļٵ�,ͬʱ���ز��뵽�ĵط�
PLDR_DATA_TABLE_ENTRY insertFakeLoadedModuleList(PLDR_DATA_TABLE_ENTRY entry,bool is_copy) {
	
	PLDR_DATA_TABLE_ENTRY ldr_entry = nullptr;
	if (!MmIsAddressValid(entry)) return nullptr;
	//������һ���ڴ����ڲ��뵽�������
	
	if (is_copy) {
		ldr_entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ExAllocatePoolWithTag(NonPagedPool, sizeof LDR_DATA_TABLE_ENTRY, pool_tag));
		if (!ldr_entry) return nullptr;
		memcpy(ldr_entry, entry, sizeof LDR_DATA_TABLE_ENTRY);
	}
	else {
		ldr_entry = entry;
	}

	//��ȡ��
	kstd::AutoLock<kstd::SpinLock> _autolock(&g_fake_loadedmodule_lock);
	InsertTailList(&(g_fake_loadedmodule.InLoadOrderLinks), &(ldr_entry->InLoadOrderLinks));

	return ldr_entry;
}

NTSTATUS initFakeLloadedModuleList() {
	auto ldr = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(kstd::SysInfoManager::getInstance()->getSysInfo()->PsLoadedModuleList);
	if (ldr == nullptr) return STATUS_NOT_SUPPORTED;

	//��ȡ�� ����
	kstd::AutoLock<kstd::Resource> autolock(PsLoadedModuleResource);

	for ( auto link=ldr->InLoadOrderLinks.Flink;link!=&ldr->InLoadOrderLinks;link=link->Flink) {
		auto entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		
		if (kstd::kwstring(entry->BaseDllName.Buffer) == L"ntoskrnl.exe") {
			kstd::AutoLock<kstd::SpinLock> spinlock(&g_fake_loadedmodule_lock);
			//����Ƚ����� ֱ�ӿ���
			auto org_link = g_fake_loadedmodule.InLoadOrderLinks;
			memcpy(&g_fake_loadedmodule, entry, sizeof LDR_DATA_TABLE_ENTRY);
			g_fake_loadedmodule.InLoadOrderLinks = org_link;/*Ҫ�ָ�����,��Ȼ�������*/
			continue;
		}
		
		//��ȡ�Լ�ά���ļٵ�PsLoadedModuleList��,ͬʱ�����entry����
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

//��ӵ�g_fake_modules��
NTSTATUS addAFakeModule(const kstd::kwstring& base_module_name) {

	FakeModuleEntry entry(base_module_name);
	if (!NT_SUCCESS(entry.status)) {
		LOG_DEBUG("failed to create a fake module!\r\n");
		return entry.status;
	}
	
	//���뵽ȫ��ά����������
	auto new_base = entry.fake_base;

	auto inserted=g_fake_modules.insert(kstd::move(entry), kstd::InsertType::tail);
	if (!inserted) {
		LOG_ERROR("failed to insert fakemodule to module list!\r\n");
		return STATUS_FAIL_FAST_EXCEPTION;
	}


	//ͬʱ�޸��Լ�ά���ļٵ�PsLoadedModuleList
	auto fake_ldr = findFakeLoadedModuleList(base_module_name);
	if (!fake_ldr) {
		//��Ӧ�÷���
		LOG_ERROR("failed to find module:%ws in fake PsLoadedModule List\r\n", base_module_name.c_str());
		
	}else fake_ldr->DllBase = new_base;
	
	return STATUS_SUCCESS;
}

//һ����������(image callback�� ����,�һ��޸�Ldr �������ŵ�g_cheats_drvs)
//ͬʱ�һ���ݴ�ʱ��g_fake_modules�������޸�iat ͬʱ��һ���ַ��� de_log��
//һ����Ҫ����DrvEntry��!Ҳ����hook DrvEntry�ص�
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

		//��ӵ�ȫ��ά��������
		auto suc=g_cheats_drvs.insert(kstd::move(entry), kstd::InsertType::tail);
		if (!suc) {
			LOG_DEBUG("failed to insert a drv cheat to list!\r\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}


	} while (false);


	return status;
}

//����ж�ص�ʱ��,�ǵûָ�,��Ҫ�Ƴ��������
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

//fakemoduleģ������ һ�������һ�����ٵ�
void fakeModuleDestory() {



	g_cheats_drvs.destory(nullptr);
	g_fake_modules.destory(nullptr);
	g_hook_dispatcher.destory(nullptr);

	destoryFakeLoadedModuleList();

}


//���һ��hook
//һ���ɹ������hook ��ôԭ��ģ��ĺ��� jmp org_func�ͻᱻ�滻��ret
//�Ӷ����᷵��ԭʼ����
NTSTATUS addAHook(void* target_addr/*Ҫhook�ĺ�����ַ*/, void(*callback)(Context_t* regs, void* context), void* context) {
	context;
	auto status = STATUS_SUCCESS;
	if (target_addr == nullptr || callback == nullptr) return STATUS_INVALID_PARAMETER;
	return status;
}

//�����ù��� ��C���Եĺ������� ��������һ��Ҫȥִ�еĺ��� Ҳ����ά����ȫ��kavl
//���kavl�������ԭʼ����,���û��,�ͼ�¼һ��,�ͷ���
extern "C" void dispatcherFunc(PContext_t context) {
	FakeModuleEntry entry;
	auto rsp = reinterpret_cast<ULONG_PTR*>(context->mRsp);
	auto caller_base = (void*)(0);
	//context��¼�Ķ�ջĿǰ��������
	//|		  |
	//|		  |
	//|retadd2|<-conext.rsp
	//|retadd1|
	//retadd1 �� ����ƭ����������iat�ĵ�ַ ֱ�����ü���;
	//retadd2 �� ��ģ��mov rax, call rax�ĵ�ַ,�����Ҫת��һ��,��ʵ����[context.rsp]-12 ���ܵõ�����ͷ
	auto called_va = rsp[0] - 12;
	auto caller_va = rsp[1];

	//ͨ��called_va ��g_fake_modules�в���
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
		//�����caller��called ��rva,��չʾ
		auto caller_rva = caller_va - (ULONG_PTR)caller_base;
		auto called_rva = called_va - (ULONG_PTR)fake_module->fake_base;
		auto& called_module_name = fake_module->base_name;

		//������call�ĵط�,�����Ǽ�ģ��ĵ�ַ,����������
		auto really_called_va = (ULONG_PTR)fake_module->org_base + called_rva;

		FLOG_INFO("%50ws + 0x%x (0x%p)\tcalled\t%15ws + 0x%x (0x%p)\r\n",
		caller_module_name.c_str(),caller_rva, caller_va,
		called_module_name.c_str(),called_rva, really_called_va);
	}
	

}