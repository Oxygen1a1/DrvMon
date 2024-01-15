## drvMon项目构成

### **项目约定**:

- 源码中de_xxx.cpp和de_xxx.h开头的是项目文件,不可以独立使用
- 非de_xxx的源文件和头文件,比如kstl的`.hpp`均为可以单独使用的头文件+源码,包含定义和实现,一般为一些库

`bin`文件夹产生的是目标文件,包括驱动,exe

`DrvMonDrv`是驱动的源码,其中包括

- `include` 外部的库,主要是`kstl`
- `include`还可以包含`de_xx.h`头文件,这是项目内部头文件,不可以移除单独使用

### `DrvMonDrv`

此文件夹是驱动的源码,**DrvMonDrv分为下面几个模块**

- `de_main`定义了驱动的`DriverEntry`,初始化了一些东西,比如`ImgCallback`等等;

- `de_fakemodule.cpp`和`de_fakemodule.h`是维护了内核重载假模块的数据结构,不可单独使用,项目内部文件

- `de_hookmodule.cpp`和`de_hookmodule.h`是通过PE的`pdata`节区遍历所有的函数,然后jmp到真正模块的函数,在这之前,会有shellcode 先jmp到`de_log.cpp`和`de_log.asm`。此外,`de_hookmodule.cpp`还负责hook比如`MmGetSystemRoutineAddress`和`ZwQuerySystemInfo`等这些关键函数,**因为这些特殊函数hook是为了达到DrvMon运行的最基本条件,所以放在这,而不是放在下面的`de_user.cpp`**同时,他对外提供接口,可以方便地hook函数,同时他还维护了当前已经被hook的驱动,等等,是最复杂的模块

- `de_log.cpp` `de_log_.asm`,`de_log.h``de_hookmodule`hook假模块 从函数头跳转过来的`de_log.asm`主要是为了维护原先的堆栈,保存寄存器环境，`de_log.cpp`记录寄存器,堆栈数据,同时拷贝寄存器有用的数据(可能)
- `de_user.cpp`是调用`de_hookmodule`的接口,hook一些用户感兴趣的函数,比如`ExAllocatePoolWithTag`,从而获取一些关键的信息

### `DrvMonConsole`

### `DrvMonGUI`







