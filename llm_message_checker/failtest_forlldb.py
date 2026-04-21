import json
import lldb
import os
import shlex

def is_conditional_branch(mnemonic):
    """辅助函数，判断一个指令是否是 ARM64 上的条件分支指令。"""
    return mnemonic.startswith('b.') or \
           mnemonic in ['cbz', 'cbnz', 'tbz', 'tbnz']

def get_expected_offset(name):
    """从sub_偏移形式获取期望的偏移（相对于基址0x100000000）"""
    if not name.startswith('sub_'):
        return None
    try:
        offset_str = name[4:]  # 去掉'sub_'
        absolute_addr = int(offset_str, 16)  # 这是绝对地址
        base_addr = 0x100000000  # funca和funcb的基址
        return absolute_addr - base_addr  # 返回相对偏移
    except ValueError:
        return None

def get_current_func_offset(frame):
    """获取当前函数相对于其模块基址的偏移"""
    target = frame.GetThread().GetProcess().GetTarget()
    # 获取当前函数的起始地址
    if frame.GetFunction().IsValid():
        current_addr = frame.GetFunction().GetStartAddress().GetLoadAddress(target)
    else:
        # 对于unnamed symbol，使用当前PC作为近似
        current_addr = frame.GetPCAddress().GetLoadAddress(target)
    
    module = frame.GetModule()
    if module:
        module_base = module.GetObjectFileHeaderAddress().GetLoadAddress(target)
        return current_addr - module_base
    return current_addr  # 如果获取不到模块基址，返回绝对地址作为fallback

def automated_debugging(debugger, command, result, internal_dict):

    # 从配置文件读取func_a、func_b和msgid
    config_path = os.path.join(os.path.dirname(__file__), 'failtest_forlldb.config')
    if not os.path.exists(config_path):
        print("错误：找不到failtest_forlldb.config", file=result)
        return
    with open(config_path) as f:
        line = f.read().strip()
        if not line:
            print("错误：failtest_forlldb.config为空", file=result)
            return
        parts = line.split()
        if len(parts) == 4:
            func_a, func_b, msgid, service = parts
        else:
            print("错误：failtest_forlldb.config内容格式应为：funca funcb msgid service", file=result)
            return
        print(f"配置：func_a={func_a}, func_b={func_b}, msgid={msgid}, service={service}")

    args = ["-i", str(msgid), "-s", service]

    target = debugger.GetSelectedTarget()
    if not target:
        print("错误：没有有效的 target。", file=result)
        return



    error = lldb.SBError()
    # 在checker.mm:88设置断点
    breakpoint = target.BreakpointCreateByLocation("checker.mm", 88)
    if not breakpoint or breakpoint.GetNumLocations() == 0:
        print("警告：无法在checker.mm:88设置断点", file=result)
    process = target.Launch(
        debugger.GetListener(), args, None, None, None, None,
        os.getcwd(), lldb.eLaunchFlagNone, True, error
    )
    if not process or error.Fail():
        print(f"错误：启动进程失败: {error.GetCString()}", file=result)
        return

    # 运行到断点
    process.Continue()
    # 检查是否命中断点
    hit_bp = False
    for thread in process:
        if thread.GetStopReason() == lldb.eStopReasonBreakpoint:
            hit_bp = True
            break
    if not hit_bp:
        print("[WARN] 未命中断点，直接开始单步。", file=result)




    step_count = 0
    max_steps = 1000  # 防止死循环
    prev_stack = []  # 用于跟踪栈变化
    execution_log = []  # 记录从进入funca到结束的所有执行过程
    in_funca = False
    funca_stack_name = None  # 记录funca在栈中的实际名字
    result_state = None  # 'success' or 'fail'
    reason = ''

    # 断点后再单步
    while True:
        state = process.GetState()
        if state in [lldb.eStateExited, lldb.eStateCrashed, lldb.eStateDetached]:
            execution_log.append(f"进程结束: {state}")
            break

        thread = process.GetSelectedThread()
        if not thread.IsValid():
            execution_log.append("线程无效")
            break

        # 记录当前指令和栈
        frame0 = thread.GetFrameAtIndex(0)
        pc_addr = frame0.GetPCAddress()
        inst = target.ReadInstructions(pc_addr, 1)[0]
        mnemonic = inst.GetMnemonic(target)
        operands = inst.GetOperands(target)
        instruction_entry = f"{hex(pc_addr.GetLoadAddress(target))}: {mnemonic} {operands}"
        current_stack = [f.GetFunctionName() or '' for f in thread]

        # 检查funca和funcb的匹配函数
        def match_func(name, target_func_name, current_frame=None):
            if not name.startswith('sub_'):
                return name.lstrip('_') in target_func_name.lstrip('_') or target_func_name.lstrip('_') in name.lstrip('_')
            
            if current_frame is None:
                return False
            
            expected_offset = get_expected_offset(name)
            current_offset = get_current_func_offset(current_frame)
            print(f"匹配函数 {target_func_name}: 当前偏移 {hex(current_offset)} 期望偏移 {hex(expected_offset)}")
            return current_offset == expected_offset if expected_offset is not None else False

        # 检测栈变化
        stack_changed = prev_stack != current_stack
        new_function_entered = False
        entered_function = None

        if stack_changed and prev_stack:
            # 找出新进入的函数（栈顶函数）
            if len(current_stack) > len(prev_stack):
                entered_function = current_stack[0]  # 栈顶函数
                new_function_entered = True
                execution_log.append(f"进入新函数: {entered_function}")
            elif len(current_stack) < len(prev_stack):
                execution_log.append(f"函数返回: 从 {prev_stack[0]} 返回到 {current_stack[0] if current_stack else 'main'}")

        # 主逻辑处理
        if not in_funca:
            # 未进入funca时的处理
            if new_function_entered and entered_function:
                if match_func(func_a, entered_function, frame0):
                    in_funca = True
                    funca_stack_name = entered_function  # 记录funca在栈中的实际名字
                    print(f"[状态变化] 进入funca: {entered_function}")
                    execution_log.clear()  # 清空之前的记录，开始记录funca过程
                    execution_log.append(f"检测到funca: {entered_function}，开始跟踪")
                # else:
                #     execution_log.append(f"非目标函数 {entered_function}，执行finish跳过")
                #     thread.StepOut()
                #     prev_stack = []
                #     continue
        else:
            # 已进入funca时的处理
            if new_function_entered and entered_function:
                if match_func(func_b, entered_function, frame0):
                    result_state = 'success'
                    reason = f"在funca中检测到funcb调用: {entered_function}"
                    execution_log.append(f"命中目标! {reason}")
                    break
                else:
                    execution_log.append(f"funca内调用非目标函数 {entered_function}，执行finish跳过")
                    thread.StepOut()
                    prev_stack = []
                    continue

            # 检查funca是否还在栈中
            if funca_stack_name and funca_stack_name not in current_stack:
                result_state = 'fail'
                reason = f"funca执行结束，未检测到funcb调用"
                execution_log.append(f"失败: {reason}")
                break

        # 单步执行
        prev_stack = current_stack.copy()
        if in_funca:
            execution_log.append(f"执行: {instruction_entry}")
        thread.StepInstruction(False)
        step_count += 1

        if step_count > max_steps:
            result_state = 'fail'
            reason = f"超过最大单步数{max_steps}"
            execution_log.append(f"超时: {reason}")
            break




    # 最终分析
    print("\n--- 调试分析结果 ---")
    result_data = {'success': result_state == 'success'}

    if result_state == 'success':
        print(f"成功：{reason}")
    elif result_state == 'fail':
        print(f"失败：{reason}")
        result_data['trace'] = list(execution_log)
    else:
        print("未能判断funca到funcb的变化。")
        result_data['trace'] = list(execution_log)

    result_json_path = os.path.join(os.path.dirname(config_path), 'result.json')
    with open(result_json_path, 'w') as result_file:
        json.dump(result_data, result_file, ensure_ascii=False, indent=2)

    if process.IsValid() and process.GetState() not in [lldb.eStateExited, lldb.eStateDetached]:
        process.Kill()

def __lldb_init_module(debugger, internal_dict):
    cmd = f'command script add -f {__name__}.automated_debugging start_analysis'
    debugger.HandleCommand(cmd)
    print("命令 'start_analysis' 已添加，用于在失败时显示关键决策点汇编。")