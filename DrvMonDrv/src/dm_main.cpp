#include <dm_ref.hpp>
#include <dm_fakemodule.h>


PEPROCESS hkIoGetCurrentProcess();
PETHREAD hkPsGetCurrentThread();
HANDLE hkPsGetCurrentProcessId();

auto fun1 = reinterpret_cast<PEPROCESS(*)()>(hkIoGetCurrentProcess);
auto fun2 = reinterpret_cast<PETHREAD(*)()>(hkPsGetCurrentThread);
auto fun3 = reinterpret_cast<HANDLE(*)()>(hkPsGetCurrentProcessId);


PEPROCESS hkIoGetCurrentProcess() {
	DbgPrintEx(77, 0, "hkIoGetCurrentProcess func is %p\r\n",fun1);

	return fun1();
}

PETHREAD hkPsGetCurrentThread() {
	DbgPrintEx(77, 0, "hkPsGetCurrentThread func is %p\r\n",fun2);

	return fun2();
}

HANDLE hkPsGetCurrentProcessId() {
	DbgPrintEx(77, 0, "hkPsGetCurrentProcessId func is %p\r\n",fun3);
	return fun3();
}




void testInlineHook() {

	auto inlinehk_ins = kstd::InlineHookManager::getInstance();
	if (inlinehk_ins == nullptr) {
		__debugbreak();
	}

	auto status = inlinehk_ins->init();
	if (!NT_SUCCESS(status)) {
		__debugbreak();
	}


	inlinehk_ins->destory();

	//一旦调用完这个 就不要再用了
	inlinehk_ins = kstd::InlineHookManager::getInstance();

	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun1);
	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun1);
	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun1);
	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun1);
	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun1);


	status = inlinehk_ins->init();
	status = inlinehk_ins->init();
	status = inlinehk_ins->init();
	status = inlinehk_ins->init();


	//because the func is speical,it's can called at any irql,so i use ipi to hook
	//but ipi called frecuency will called your cpu block!
	for (int i = 0; i < 100; i++) {
		
		fun1 = hkIoGetCurrentProcess;

		auto status2=inlinehk_ins->inlinehook(IoGetCurrentProcess, (void**)&fun1, kstd::InlineHookManager::HookType::Ipi);

		auto status1=inlinehk_ins->remove(IoGetCurrentProcess);
		

		if (!NT_SUCCESS(status1)) {
			//DbgPrintEx(77, 0, "[+]remove failed \r\n");
			__debugbreak();
		}
		if (!NT_SUCCESS(status2)) {
			//DbgPrintEx(77, 0, "[+]inline hook failed\r\n");
			__debugbreak();

		}

		DbgPrintEx(77, 0, "[+]%d\r\n",i);
	}
	
	for (int i = 0; i < 100; i++) {
		fun1 = hkIoGetCurrentProcess;
		fun2 = hkPsGetCurrentThread;
		fun3 = hkPsGetCurrentProcessId;

		inlinehk_ins->inlinehook(IoGetCurrentProcess, (void**)&fun1,kstd::InlineHookManager::HookType::Ipi);
		inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun2, kstd::InlineHookManager::HookType::Ipi);
		inlinehk_ins->inlinehook(PsGetCurrentProcessId, (void**)&fun3, kstd::InlineHookManager::HookType::Ipi);


		inlinehk_ins->remove(IoGetCurrentProcess);
		inlinehk_ins->remove(PsGetCurrentProcessId);
		inlinehk_ins->remove(PsGetCurrentThread);

		inlinehk_ins->remove(PsGetCurrentThread);// 鲁棒性测试

		DbgPrintEx(77, 0, "[+]%d\r\n", i);

	}


	inlinehk_ins->inlinehook(IoGetCurrentProcess, (void**)&fun1, kstd::InlineHookManager::HookType::Ipi);
	inlinehk_ins->inlinehook(PsGetCurrentThread, (void**)&fun2, kstd::InlineHookManager::HookType::Ipi);
	inlinehk_ins->inlinehook(PsGetCurrentProcessId, (void**)&fun3, kstd::InlineHookManager::HookType::Ipi);

	inlinehk_ins->destory();


}

void eExpTable(kstd::PeParseBaisc::PRUNTIME_FUNCTION runtime_func, void* context) {

	LOG_INFO("exception table: begin addr ->%p,context -> %llx\r\n",runtime_func->BeginAddress,context);
}

void eExportTable(char* name, int index, PSHORT ord_table, PULONG func_table, void* context) {
	func_table,ord_table;
	LOG_INFO("export table:name -> %s, idx->%d,context->%p\r\n", name, index, context);
}

void eFuncs(ULONG start_rva, ULONG end_rva, void* context) {
	LOG_INFO("funcs: start rva-> %llx,end rva->%llx,context ->%p\r\n", start_rva, end_rva, context);
}

void eIats(UINT_PTR* iat, UINT_PTR* _int, char* dllname, bool is_ordinal, char* func_name, void* context) {
	is_ordinal, _int, iat;
	LOG_INFO("iats: dllname -> %s ,func_name -> %s,context->%p\r\n", dllname, func_name, context);
}
void testPeParse(PDRIVER_OBJECT drv) {
	
	//test pe file
	auto p=kstd::ParsePE(L"C:\\Users\\Administrator\\Desktop\\km_callback.sys");
	auto pp = kstd::ParsePE(L"C:\\Windows\\System32\\ntoskrnl.exe");
	//test image base
	auto i = kstd::ParsePE((unsigned char*)drv->DriverStart, drv->DriverSize);


	pp.enumrateExportTable(pp._base, eExportTable, (void*)0X11111);


	p.enumrateExceptionTable(p._base, eExpTable,(void*)0x11111);
	p.enumrateExportTable(p._base, eExportTable, (void*)0x11111);
	p.enumrateFuncs(p._base, eFuncs, (void*)0x11111);
	p.enumrateIat(p._base, eIats, (void*)0x11111);
	auto rva=p.foa2rva(p._base, p.rva2foa(p._base, p.getEntryPointRva(p._base)));
	LOG_INFO("rva entrypoint -> %llx\r\n", rva);

	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(p._base);
	auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((UINT_PTR)p._base + dos_header->e_lfanew);
	auto opt_header = nt_headers->OptionalHeader;

	auto map_addr = ExAllocatePoolWithTag(NonPagedPool, opt_header.SizeOfImage, 'tmp');
	p.mapToMemory(p._base, map_addr, opt_header.SizeOfImage);

	//创建个线程执行过去 类似kdmapper


	//PsCreateSystemThread(&h_thread, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, [](void* base) {

	//	auto entry = reinterpret_cast<NTSTATUS(*)(PDRIVER_OBJECT, PUNICODE_STRING)>((UINT_PTR)base + 0X5000);
	//	entry((PDRIVER_OBJECT)base, 0);

	//}, map_addr);

	i.enumrateExceptionTable(i._base, eExpTable, (void*)0x11111);
	i.enumrateExportTable(i._base, eExportTable, (void*)0x11111);
	i.enumrateFuncs(i._base, eFuncs, (void*)0x11111);
	i.enumrateIat(i._base, eIats, (void*)0x11111);
	

}

VOID ldImgCallback(_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo);



void testAvl() {

	struct structTest {
		int a;
		int b;
	};

	kstd::kavl<int> avl1;
	kstd::kavl<structTest> avl2;

	avl2.init([](_In_ struct _RTL_AVL_TABLE* Table,
		_In_ PVOID first,
		_In_ PVOID second)->RTL_GENERIC_COMPARE_RESULTS {
			UNREFERENCED_PARAMETER(Table);
			if (reinterpret_cast<structTest*>(first)->a == reinterpret_cast<structTest*>(second)->a) return GenericEqual;
			else if (reinterpret_cast<structTest*>(first)->a < reinterpret_cast<structTest*>(second)->a) return GenericLessThan;
			else return GenericGreaterThan;
		});

	//avl1 test
	avl1.init();
	avl1.insert(12345);
	avl1.insert(123);
	avl1.insert(333333);

	auto find1=avl1.find(123);
	auto find2 = avl1.find(1111);

	LOG_INFO("avl1 find 1 %p find 2 %p\r\n", find1, find2);
	for (auto i = 0ul; i < avl1.size(); i++)
		LOG_INFO("avl1 %d value %d\r\n", i, avl1[i]);
	avl1.remove(find1);
	LOG_INFO("avl1.size() %d\r\n", avl1.size());


	//avl2 test
	avl2.insert({ 1,2 });
	avl2.insert({ 11111,2 });
	avl2.insert({ 1231,2 });
	avl2.insert({ 1,2 });
	LOG_INFO("avl2.size() %d\r\n", avl2.size());
	for (auto i = 0ul; i < avl2.size(); i++)
		LOG_INFO("avl2 %d value.a %d\r\n", i, avl2[i].a);
	//avl2[1].a = 12312312;
	avl2.insert({ 1232 });
	auto find3=avl2.find({ 1,0 });
	LOG_INFO("avl1 find 3 %p\r\n", find3);
	avl2.remove(find3);
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT drv,PUNICODE_STRING) {
	auto status = STATUS_SUCCESS;

	
	
	//bypass driver sign,now you can call PsSetLoadImageNotifyRoutine success
	kstd::SysInfoManager::byPassSignCheck(drv);

	drv->DriverUnload = [](PDRIVER_OBJECT)->void {

		fakeModuleDestory();
		PsRemoveLoadImageNotifyRoutine(ldImgCallback);

		kstd::DrvObjHookManager::getInstance()->destory();
		kstd::InlineHookManager::getInstance()->destory();

		kstd::Logger::destory();
	};


	do {

		//init log
		kstd::Logger::init("DrvMon",L"\\??\\C:\\DrvMon.txt");

		//init image notify callback
		status = PsSetLoadImageNotifyRoutine(ldImgCallback);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("failed to setload image notify! errcode:%x\r\n",status);
			break;
		}

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

	} while (0);
	
	
	return status;
}


VOID ldImgCallback(_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo) {

	FullImageName; ProcessId; ImageInfo;

	

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

