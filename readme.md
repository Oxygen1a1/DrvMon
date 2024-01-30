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
- `de_fakemodule.cpp`和`de_fakemodule.h`是维护了内核重载假模块的数据结构,不可单独使用,项目内部文件。他的功能的
  - 他会hook 假模块的所有函数到真模块,同时调用日志.
  - 同时提供接口，可以添加假模块和欺骗的驱动,外加增加hook的选项等等。
  - 维护相关数据结构


- `de_hookmodule.cpp`和`de_hookmodule.h`主要是声明和定义自定义hook函数,调用`fakemodule`模块的接口
  - 它会调用`fakemodule`模块的`addhook`接口,增加很多hook,打印出来相关的信息(根据不同函数)。
  - 它处理了特殊的函数,比如`ZwQuery/NtQueryXXXInfomation`,使内核重载更加真实。

- de_utils模块声明和定义了一些常用的杂项函数,比如w2s,s2w等等

### `DrvMonConsole`

## Todo

- [x] 大体框架

- [ ] hook 必须的函数
- [ ] LOG记录时间更加人性化
- [ ] hook 额外附加函数
- [ ] 堆栈遍历
- [ ] R3程序PDB重新解析
- [ ] 处理data区域,

### 







