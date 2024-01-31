#include <dm_fakemodule.h>

//用于产生 和 保存内核重载的模块
//维护相关数据结构
//同时维护一个二叉树,这个二叉树是一个分发器,分发器负责找到hookmodule这个模块添加的hook
//fakemodule还有一个asm的文件,也是属于fakemodule模块,主要是负责保存寄存器环境 跳到fakemodule.dispatcherFunc中


const unsigned pool_tag = 'fkMd';

//自己维护的假的PsLoadedModuleList
LDR_DATA_TABLE_ENTRY g_fake_loadedmodule;
//自己维护的假的PsLoadedModuleList lock
KSPIN_LOCK g_fake_loadedmodule_lock;

PLDR_DATA_TABLE_ENTRY findFakeLoadedModuleList(const kstd::kwstring& base_module_name);
void removeFakeLoaedModuleList(PLDR_DATA_TABLE_ENTRY entry);
PLDR_DATA_TABLE_ENTRY insertFakeLoadedModuleList(PLDR_DATA_TABLE_ENTRY entry, bool is_copy = true);
NTSTATUS initFakeLloadedModuleList();

struct FakeModuleEntry {
	//这个东西必须加,如果想要使用kstl的容器,这个是必须加的,不然没有办法析构!
	//因为我没有实现全局的new,所以delete调用一律蓝屏;
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
		//遍历当前模块的所有函数 然后得到rva,让假模块对应的函数jmp到
		ppe.enumrateFuncs(ppe._base, [](ULONG start_rva,ULONG end_rva,void* context) ->void {
			
			unsigned char jmp_code[] = {
				0x48,0xb8,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,//mov rax,0
				0xff,0xd0,//call rax(call log function)
				0x48,0xb8,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,//mov rax,0
				0xff,0xe0//jmp rax(jmp to original func) 
			};

			if (end_rva - start_rva < sizeof jmp_code) return;/*函数太小,以至于不能hook*/

			auto _this = reinterpret_cast<FakeModuleEntry*>(context);

			//有时候这个异常表会抽风...不是函数开始rva,这里取个巧,往上找 找到第一个0xcc,把他当成函数头 当然可能会存在误判
			while (*((PUCHAR)(_this->fake_base) + start_rva) != 0xcc) start_rva--;
			start_rva++;

			*reinterpret_cast<UINT_PTR*>(jmp_code + 2) = (UINT_PTR)asm_func_log;
			*reinterpret_cast<UINT_PTR*>(jmp_code + 14) = start_rva + (ULONG_PTR)_this->org_base;

			//这里是可以修改的,因为申请的内存可执行,可读,可写
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

			//拷贝完成之后,开始进行hook 模块的所有函数,让他jmp 到真正的函数地址
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

	//拷贝构造删除!
	FakeModuleEntry(const FakeModuleEntry& rhs) = delete;
	FakeModuleEntry& operator=(const FakeModuleEntry& rhs) = delete;
	//移动语义必须要有
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

//维护假模块的全局变量 线程安全的
kstd::Klist<FakeModuleEntry> g_fake_modules;

struct DriverCheatEntry {
	MUSTADDED

	PDRIVER_OBJECT drv;
	PLDR_DATA_TABLE_ENTRY org_ldr;
	PLDR_DATA_TABLE_ENTRY new_ldr;/*为了欺骗驱动*/
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
				LOG_ERROR("failed to find module:%ws\r\n", w_base_name); /*说明还没有为这个添加假模块*/
				breakOnlyDebug();
				return;
			}

			kstd::ParsePE pe_fakemodule(find_entry->fake_base, find_entry->image_size);
			auto addr=pe_fakemodule.getProcAddress(pe_fakemodule._base, func_name, is_ordinal);
			if (addr == 0) {
				LOG_ERROR("failed to get func %s addr\r\n", func_name);
				breakOnlyDebug();
			}

			//名字导入 这个有个很逆天的BUG..触发条件极其苛刻 但是也可能会触发
			//1.函数是no excpet的叶函数 在pdata节区没有记录 但是这种函数一般较小，直接用假模块的也没啥关系
			//2.但是，正好内存比较小，导致ntos的换页，就比较尴尬了 这个时候是没复制成功的!
			//3.这个时候直接会BSOD!,所以战略性放弃这种逆天函数,因为一般这种函数都是什么PsGetThreadTeb无关紧要的函数
			//4.在之前 假模块的内容被我RtlSecureZero了，我只需要判断一下这个地方是不是字节0 如果是,说明没复制
			//那么就直接用原来的就行 这种小函数漏了就漏了
			if (*(PUCHAR)addr == '\xcc') {
				//说明没有复制
				LOG_INFO("whatever,for some reasons,func %s from module %s not be copied!\r\n", func_name, dllname);
			}
			else {
				// *iat = addr; × 这个地址不可写
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

			//拷贝过去
			memcpy(new_ldr, org_ldr, sizeof LDR_DATA_TABLE_ENTRY);

			full_path = org_ldr->FullDllName.Buffer;

			//同时插入自己维护的假的PsLoadedModuleList 注意,这个生命周期是我管理的，因此不拷贝
			insertFakeLoadedModuleList(new_ldr,false);
			//根据fakemodule,进行修改iat
			iatSwift(g_fake_modules);

			//修改这个驱动的Ldr
			drv->DriverSection = new_ldr;
		} while (false);


		if (!NT_SUCCESS(status)) {
			if (MmIsAddressValid(new_ldr)) {
				//先修改驱动的ldr
				drv->DriverSection = org_ldr;
				removeFakeLoaedModuleList(new_ldr);
				ExFreePool(new_ldr);
				new_ldr = nullptr;
			}
		}

	}
	~DriverCheatEntry() {

		if (!MmIsAddressValid(new_ldr) || !MmIsAddressValid(drv) || !MmIsAddressValid(org_ldr)) return;

		//先修改驱动的ldr
		drv->DriverSection = org_ldr;
		removeFakeLoaedModuleList(new_ldr);
		ExFreePool(new_ldr);
		new_ldr = nullptr;
		
	}

	//拷贝构造删除
	DriverCheatEntry(const DriverCheatEntry& rhs) = delete;
	DriverCheatEntry& operator=(const DriverCheatEntry& rhs) = delete;

	//移动语义有
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


//维护iat hook的驱动
kstd::Klist<DriverCheatEntry> g_cheats_drvs;

//维护一个分发器 主要是用来hook函数的
kstd::kavl<DispatcherEntry> g_hook_dispatcher;

//ONLY SUPPORT above WIN10 
//这个东西读PsLoadedModuleList的时候要加锁!
EXTERN_C ERESOURCE* PsLoadedModuleResource;


PLDR_DATA_TABLE_ENTRY findFakeLoadedModuleList(const kstd::kwstring& base_module_name) {
	auto find = PLDR_DATA_TABLE_ENTRY{ nullptr };

	kstd::AutoLock<kstd::SpinLock> spinlock(&g_fake_loadedmodule_lock);

	//因为这个是没有链表头的,所以得这样遍历
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

//接受一个entry,拷贝他,然后连接到维护的假的,同时返回插入到的地方
PLDR_DATA_TABLE_ENTRY insertFakeLoadedModuleList(PLDR_DATA_TABLE_ENTRY entry,bool is_copy) {
	
	PLDR_DATA_TABLE_ENTRY ldr_entry = nullptr;
	if (!MmIsAddressValid(entry)) return nullptr;
	//先申请一块内存用于插入到这个链接
	
	if (is_copy) {
		ldr_entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(ExAllocatePoolWithTag(NonPagedPool, sizeof LDR_DATA_TABLE_ENTRY, pool_tag));
		if (!ldr_entry) return nullptr;
		memcpy(ldr_entry, entry, sizeof LDR_DATA_TABLE_ENTRY);
	}
	else {
		ldr_entry = entry;
	}

	//获取锁
	kstd::AutoLock<kstd::SpinLock> _autolock(&g_fake_loadedmodule_lock);
	InsertTailList(&(g_fake_loadedmodule.InLoadOrderLinks), &(ldr_entry->InLoadOrderLinks));

	return ldr_entry;
}

NTSTATUS initFakeLloadedModuleList() {
	auto ldr = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(kstd::SysInfoManager::getInstance()->getSysInfo()->PsLoadedModuleList);
	if (ldr == nullptr) return STATUS_NOT_SUPPORTED;

	//获取锁 遍历
	kstd::AutoLock<kstd::Resource> autolock(PsLoadedModuleResource);

	for ( auto link=ldr->InLoadOrderLinks.Flink;link!=&ldr->InLoadOrderLinks;link=link->Flink) {
		auto entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		
		if (kstd::kwstring(entry->BaseDllName.Buffer) == L"ntoskrnl.exe") {
			kstd::AutoLock<kstd::SpinLock> spinlock(&g_fake_loadedmodule_lock);
			//这个比较特殊 直接拷贝
			auto org_link = g_fake_loadedmodule.InLoadOrderLinks;
			memcpy(&g_fake_loadedmodule, entry, sizeof LDR_DATA_TABLE_ENTRY);
			g_fake_loadedmodule.InLoadOrderLinks = org_link;/*要恢复回来,不然链表会损坏*/
			continue;
		}
		
		//获取自己维护的假的PsLoadedModuleList锁,同时将这个entry插入
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

//添加到g_fake_modules中
NTSTATUS addAFakeModule(const kstd::kwstring& base_module_name) {

	FakeModuleEntry entry(base_module_name);
	if (!NT_SUCCESS(entry.status)) {
		LOG_DEBUG("failed to create a fake module!\r\n");
		return entry.status;
	}
	
	//插入到全局维护的链表中
	auto new_base = entry.fake_base;

	auto inserted=g_fake_modules.insert(kstd::move(entry), kstd::InsertType::tail);
	if (!inserted) {
		LOG_ERROR("failed to insert fakemodule to module list!\r\n");
		return STATUS_FAIL_FAST_EXCEPTION;
	}


	//同时修改自己维护的假的PsLoadedModuleList
	auto fake_ldr = findFakeLoadedModuleList(base_module_name);
	if (!fake_ldr) {
		//不应该发生
		LOG_ERROR("failed to find module:%ws in fake PsLoadedModule List\r\n", base_module_name.c_str());
		
	}else fake_ldr->DllBase = new_base;
	
	return STATUS_SUCCESS;
}

//一个驱动加载(image callback中 到这,我会修改Ldr 并把它放到g_cheats_drvs)
//同时我会根据此时的g_fake_modules来进行修改iat 同时有一个分发器 de_log中
//一般是要放在DrvEntry中!也就是hook DrvEntry回调
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

		//添加到全局维护的链表
		auto suc=g_cheats_drvs.insert(kstd::move(entry), kstd::InsertType::tail);
		if (!suc) {
			LOG_DEBUG("failed to insert a drv cheat to list!\r\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}


	} while (false);


	return status;
}

//驱动卸载的时候,记得恢复,需要移除这个东西
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

//fakemodule模块销毁 一般是最后一个销毁的
void fakeModuleDestory() {



	g_cheats_drvs.destory(nullptr);
	g_fake_modules.destory(nullptr);
	g_hook_dispatcher.destory(nullptr);

	destoryFakeLoadedModuleList();

}


//添加一个hook
//一旦成功添加了hook 那么原来模块的函数 jmp org_func就会被替换成ret
//从而不会返回原始函数
NTSTATUS addAHook(void* target_addr/*要hook的函数地址*/, void(*callback)(Context_t* regs, void* context), void* context) {
	context;
	auto status = STATUS_SUCCESS;
	if (target_addr == nullptr || callback == nullptr) return STATUS_INVALID_PARAMETER;
	return status;
}

//汇编调用过来 是C语言的函数声明 负责找下一个要去执行的函数 也就是维护的全局kavl
//会从kavl里面查找原始函数,如果没有,就记录一下,就返回
extern "C" void dispatcherFunc(PContext_t context) {
	FakeModuleEntry entry;
	auto rsp = reinterpret_cast<ULONG_PTR*>(context->mRsp);
	auto caller_base = (void*)(0);
	//context记录的堆栈目前是这样的
	//|		  |
	//|		  |
	//|retadd2|<-conext.rsp
	//|retadd1|
	//retadd1 是 被欺骗的驱动调用iat的地址 直接引用即可;
	//retadd2 是 假模块mov rax, call rax的地址,因此需要转换一下,其实就是[context.rsp]-12 才能得到函数头
	auto called_va = rsp[0] - 12;
	auto caller_va = rsp[1];

	//通过called_va 在g_fake_modules中查找
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
		//计算出caller和called 的rva,以展示
		auto caller_rva = caller_va - (ULONG_PTR)caller_base;
		auto called_rva = called_va - (ULONG_PTR)fake_module->fake_base;
		auto& called_module_name = fake_module->base_name;

		//真正该call的地方,而不是假模块的地址,这里计算出来
		auto really_called_va = (ULONG_PTR)fake_module->org_base + called_rva;

		FLOG_INFO("%50ws + 0x%x (0x%p)\tcalled\t%15ws + 0x%x (0x%p)\r\n",
		caller_module_name.c_str(),caller_rva, caller_va,
		called_module_name.c_str(),called_rva, really_called_va);
	}
	

}