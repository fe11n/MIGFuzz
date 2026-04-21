  Crash发生在 sub_10001D50C:17 调用 CFArrayGetCount((CFArrayRef)qword_100090B18) 时，全局变量 qword_100090B18 为 NULL，导致对空指针解引用。

  调用链

  harness!LLVMFuzzerTestOneInput
    → sub_100054B00 (0x54b00) - MIG message handler
      → sub_10001D748 (0x1d748)
        → sub_10001D50C (0x1d50c)
          → CFArrayGetCount(NULL) → EXC_BAD_ACCESS

  根本问题

  你的fuzz直接调用了 sub_100054B00（这是一个MIG消息处理函数），但 powerd 的初始化代码没有被执行，导致全局的 CFArray qword_100090B18 未被创建。

  ---
  推荐的 start_func_offset

  初始化函数: sub_10001BE30
  偏移量: 0x1BE30

  这个函数（位于 0x10001be30.c:35）负责初始化关键全局状态：

  qword_100090B18 = CFArrayCreateMutable(kCFAllocatorDefault, 100, ...);

  此外它还初始化：
  - qword_100091340 - os_log 日志句柄
  - dword_100090B20 - IOPMrootDomain service
  - dword_100090B24 - IOService connection
  - 注册 IOKit 通知等

  ---
  建议

  设置 start_func_offset = 0x1BE30

  但需注意，这个初始化函数会尝试连接 IOPMrootDomain 等内核服务。在fuzz环境中，如果这些服务不可用，初始化可能会提前返回（第41行的 asl_log 返回）。你可能需要：

  1. 确保fuzz环境能提供必要的IOKit服务，或者
  2. 对初始化函数进行mock/patch，跳过IOKit相关调用，只保留CFArray的创建