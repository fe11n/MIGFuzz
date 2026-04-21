import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

def check_crash_sample(crash_sample_path, verbose=False, log_file=None):
    """
    使用 LLDB 自动化分析 crash 样本。
    返回包含分析结果的字典：
    - is_crash: True 如果检测到崩溃，False 否则
    - crash_in_module: True 如果崩溃触及服务模块，False 否则（仅当 is_crash=True 时有效）
    - bt_output: backtrace 输出字符串
    """
    crash_path = Path(crash_sample_path).resolve()
    service_dir = crash_path.parent.parent.parent  # fuzz_exec/service_name
    service_name = service_dir.name
    
    # 1. 模块名的确定方法：找到mig_services或other_mig_services/{servicename}/文件夹中的无后缀二进制文件名
    workspace_dir = service_dir.parent.parent
    mig_service_dir = workspace_dir / "mig_services" / service_name
    other_mig_service_dir = workspace_dir / "other_mig_services" / service_name
    module_name = None
    
    if mig_service_dir.exists():
        for item in mig_service_dir.iterdir():
            if item.is_file() and '.' not in item.name:
                module_name = item.name
                break
    
    if module_name is None and other_mig_service_dir.exists():
        for item in other_mig_service_dir.iterdir():
            if item.is_file() and '.' not in item.name:
                module_name = item.name
                break
                
    if module_name is None:
        module_name = service_name.split('.')[-1]  # Fallback

    harness_path = service_dir / "harness"
    
    if not harness_path.exists():
        print(f"Harness not found: {harness_path}")
        return {"is_crash": False, "crash_in_module": False, "bt_output": ""}
    
        # 第一次运行：获取 bt
    with tempfile.NamedTemporaryFile(mode='w', suffix='.lldb', delete=False) as f:
        f.write("r\n")
        f.write("bt\n")
        f.write("quit\n")
        bt_script_path = f.name
    
    cmd_bt = ["sudo", "lldb", "-s", bt_script_path, "--", str(harness_path), "-f", str(crash_path)]
    try:
        proc_bt = subprocess.Popen(
            cmd_bt,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=service_dir
        )
        stdout_bt, stderr_bt = proc_bt.communicate(timeout=30)  # 增加超时时间
    except subprocess.TimeoutExpired:
        print(f"LLDB process timed out during bt for {crash_sample_path}.")
        proc_bt.kill()
        return {"is_crash": False, "crash_in_module": False, "bt_output": ""}
    except Exception as e:
        print(f"Error during bt: {e}")
        return {"is_crash": False, "crash_in_module": False, "bt_output": ""}
    finally:
        os.unlink(bt_script_path)
    
    # 解析 bt，找到 harness 帧
    harness_frame = -1
    frame_addresses = {}
    lines = stdout_bt.split('\n')
    import re
    for line in lines:
        # Extract frame address
        match_addr = re.search(r'frame #(\d+): (0x[0-9a-fA-F]+)', line)
        if match_addr:
            frame_num = int(match_addr.group(1))
            addr_str = match_addr.group(2)
            frame_addresses[frame_num] = int(addr_str, 16)

        if 'harness`' in line:
            # 提取 frame 号，如 frame #8
            match = re.search(r'frame #(\d+):', line)
            if match:
                harness_frame = int(match.group(1))
                break
    
    # 检查是否有 crash
    crash_indicators = ["stopped", "EXC_BAD_ACCESS", "SIGSEGV", "SIGABRT"]
    has_crash = any(indicator in stdout_bt or indicator in stderr_bt for indicator in crash_indicators)
    
    is_crash = has_crash
    crash_in_module = False
    bt_output = ""
    
    if has_crash:
        bt_output = stdout_bt  # 记录整个第一次 LLDB 交互日志，包括 r 和 bt
        
        # 第二层检查：bt 中是否包含服务模块名至少两次
        # 格式化分析 frame 结构，获取其中的模块名
        import re
        module_frames = set()
        matched_lines = []
        for line in stdout_bt.split('\n'):
            # frame #0: 0x000000018afa8884 libsystem_malloc.dylib`small_free_list_add_ptr + 252
            match = re.search(r'frame #(\d+): 0x[0-9a-fA-F]+ (.+?)`', line)
            if match:
                frame_idx = match.group(1)
                mod_name = match.group(2)
                if mod_name == module_name:
                    if frame_idx not in module_frames:
                        module_frames.add(frame_idx)
                        matched_lines.append(line)
        
        module_count = len(module_frames)
        crash_in_module = module_count >= 1 # 按理只调用一个目标模块函数时只是dispatch函数，不会报错。不过既然报错了，还是看看吧
        # crash_in_module = module_count >= 2
        
        if crash_in_module:
            # Generate message_content.json using harness -v
            cmd_generate = ["sudo", str(harness_path), "-f", str(crash_path), "-v"]
            try:
                result_generate = subprocess.run(cmd_generate, cwd=service_dir, capture_output=True, text=True, timeout=30)
                if result_generate.returncode != 0:
                    print(f"Failed to generate message_content.json: {result_generate.stderr}")
            except subprocess.TimeoutExpired:
                print("Harness generation timed out.")
            except Exception as e:
                print(f"Error generating message_content.json: {e}")
            # 提取需要查询的符号
            symbols_to_lookup = set()
            for line in matched_lines:
                # 提取符号名，例如 screensharingd`___lldb_unnamed_symbol600 中的 ___lldb_unnamed_symbol600
                match = re.search(rf'{re.escape(module_name)}`(\S+)', line)
                if match:
                    symbols_to_lookup.add(match.group(1))

            # 选择帧：从 0 到 harness_frame - 1，最多 10 帧
            selected_frames = list(range(min(harness_frame, 10))) if harness_frame > 0 else []
            
            # 第二次运行：获取 disassemble 和 image lookup
            with tempfile.NamedTemporaryFile(mode='w', suffix='.lldb', delete=False) as f:
                f.write("r\n")
                f.write("bt\n")
                for frame in selected_frames:
                    if frame in frame_addresses and frame_addresses[frame] == 0:
                        continue
                    f.write(f"frame select {frame}\n")
                    f.write("disassemble -f\n")
                
                # 添加 image lookup 命令
                for symbol in symbols_to_lookup:
                    f.write(f"image lookup -n {symbol}\n")
                
                f.write("quit\n")
                script_path = f.name
            
            cmd = ["sudo", "lldb", "-s", script_path, "--", str(harness_path), "-f", str(crash_path)]
            
            try:
                # 启动 LLDB 进程
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=service_dir  # 切换到服务目录
                )
                
                # 等待进程完成并获取输出
                stdout, stderr = proc.communicate(timeout=30)  # 设置超时
                
                # 删除临时文件
                os.unlink(script_path)
                
                # 构造精简版日志
                # 1. 提取 bt 部分
                bt_section = ""
                if "* thread #1" in stdout:
                    parts = stdout.split("* thread #1")
                    # 取最后一个包含 thread #1 的部分（通常是 crash 时的状态）
                    # 或者是第一次出现的 bt
                    # 简单起见，我们尝试提取 (lldb) bt 之后的内容
                    pass
                
                # 2. 提取 disassemble 部分
                # 3. 提取 image lookup 部分（可选，或者只保留分析结果）
                
                # 由于 LLDB 输出混合在一起，简单过滤比较困难。
                # 我们采用保留完整 stdout 但将分析结果置顶的策略，或者尝试简单的标记分割。
                
                # 策略：保留原始 stdout，但在最后清晰地附加分析结果。
                # 如果用户坚持要过滤，我们可以尝试只保留包含特定关键字的行，但这容易丢失上下文。
                # 既然用户要求“保留bt、dis、最终分析出来的偏移信息”，我们可以尝试构造一个新的输出字符串。
                
                final_log = ""
                
                # 提取 Backtrace
                import re
                bt_match = re.search(r'\(lldb\) bt\n(.*?)\(lldb\)', stdout, re.DOTALL)
                if bt_match:
                    final_log += "=== Backtrace ===\n" + bt_match.group(1).strip() + "\n\n"
                else:
                    # Fallback: 如果正则匹配失败，保留包含 frame # 的行
                    bt_lines = [line for line in stdout.split('\n') if 'frame #' in line]
                    if bt_lines:
                        final_log += "=== Backtrace (Filtered) ===\n" + "\n".join(bt_lines) + "\n\n"

                # 提取 Disassemble
                dis_blocks = re.findall(r'\(lldb\) disassemble -f\n(.*?)\(lldb\)', stdout, re.DOTALL)
                if dis_blocks:
                    final_log += "=== Disassembly ===\n"
                    for block in dis_blocks:
                        final_log += block.strip() + "\n---\n"
                    final_log += "\n"

                # 解析 image lookup 输出，提取文件偏移
                analysis_result = "=== Function Offsets ===\n"
                for symbol in symbols_to_lookup:
                    # 为了防止不同符号的输出混淆，我们需要定位到特定符号的查询命令输出块
                    cmd_marker = f"image lookup -n {symbol}"
                    
                    # 循环查找正确的命令位置，避免前缀匹配问题（如 symbol="A" 匹配到 "A_1"）
                    start_idx = stdout.find(cmd_marker)
                    real_start_idx = -1
                    
                    while start_idx != -1:
                        # 检查命令后的字符，确保是完整匹配
                        after_idx = start_idx + len(cmd_marker)
                        if after_idx >= len(stdout) or stdout[after_idx] in ('\n', '\r', ' '):
                            real_start_idx = start_idx
                            break
                        start_idx = stdout.find(cmd_marker, start_idx + 1)
                    
                    if real_start_idx != -1:
                        # 截取从该命令开始之后的内容
                        content_after = stdout[real_start_idx + len(cmd_marker):]
                        
                        # 找到下一个 (lldb) 提示符，作为当前命令输出的结束
                        end_idx = content_after.find("(lldb)")
                        if end_idx != -1:
                            block = content_after[:end_idx]
                        else:
                            block = content_after
                            
                        # 在限定的 block 中查找地址
                        pattern = rf"Address: {re.escape(module_name)}\[(0x[0-9a-fA-F]+)\].*?Summary: \S*?`{re.escape(symbol)}\b"
                        
                        match = re.search(pattern, block, re.DOTALL)
                        if match:
                            offset = match.group(1)
                            analysis_result += f"Symbol {symbol} offset in {module_name}: {offset}\n"
                
                # 如果提取到了内容，就使用精简版；否则回退到完整 stdout 以免丢失信息
                if final_log:
                    bt_output = final_log + analysis_result
                else:
                    bt_output = stdout + "\n\n" + analysis_result
                    
            except subprocess.TimeoutExpired:
                print("LLDB process timed out during disassemble.")
                proc.kill()
                # bt_output 保持为第一次的
            except Exception as e:
                print(f"Error during disassemble: {e}")
                # bt_output 保持为第一次的
    
    # 如果指定了 log_file，写入 bt_output
    if log_file:
        with open(log_file, 'w') as f:
            f.write(bt_output)
    
    return {"is_crash": is_crash, "crash_in_module": crash_in_module, "bt_output": bt_output, "matched_lines": matched_lines if crash_in_module else []}

def auto_mode():
    fuzz_exec_dir = Path('../fuzz_exec')
    crash_sample_paths = []
    
    # 先获取所有 sample 的路径
    for service_dir in fuzz_exec_dir.iterdir():
        if service_dir.is_dir():
            crashes_dir = service_dir / 'out' / 'crashes'
            if crashes_dir.exists():
                for crash_file in crashes_dir.iterdir():
                    if crash_file.is_file():
                        crash_sample_paths.append(str(crash_file))
    
    # 限制为前5个以测试
    # if len(crash_sample_paths) > 5:
    #     crash_sample_paths = crash_sample_paths[:5]
    
    results = []
    
    # 处理每个 sample
    for path in crash_sample_paths:
        log_file = path + '.log'
        result = check_crash_sample(path, verbose=False, log_file=log_file)
        print(f"is_crash: {result['is_crash']}")
        print(f"crash_in_module: {result['crash_in_module']}")
        if result['crash_in_module']:
            print("matched_lines:")
            for line in result['matched_lines']:
                print(line)
        results.append({
            'path': path,
            'is_crash': result['is_crash'],
            'crash_in_module': result['crash_in_module']
        })
    
    # 最终汇总这些结果
    print("\nFinal Results:")
    print("Service | Crash File | Is Crash | Crash in Module")
    print("--------|------------|----------|----------------")
    for r in results:
        service = Path(r['path']).parent.parent.parent.name
        crash_file = Path(r['path']).name
        print(f"{service} | {crash_file} | {r['is_crash']} | {r['crash_in_module']}")

def main():
    verbose = False
    auto = False
    args = sys.argv[1:]
    
    if '--verbose' in args or '-v' in args:
        verbose = True
        args = [arg for arg in args if arg not in ['--verbose', '-v']]
    
    if '--auto' in args:
        auto = True
        args = [arg for arg in args if arg != '--auto']
    
    if auto:
        auto_mode()
    else:
        if len(args) != 1:
            print("Usage: python crash_check_validation.py [--verbose|-v] [--auto] <crash_sample_path>")
            sys.exit(1)
        
        crash_sample_path = args[0]
        
        crash_path = Path(crash_sample_path)
        if not crash_path.exists():
            print(f"Crash sample not found: {crash_sample_path}")
            sys.exit(1)
        
        result = check_crash_sample(str(crash_path), verbose)
        print(f"is_crash: {result['is_crash']}")
        print(f"crash_in_module: {result['crash_in_module']}")
        if result['crash_in_module']:
            print("matched_lines:")
            for line in result['matched_lines']:
                print(line)
        if verbose and result['bt_output']:
            print("bt_output:")
            print(result['bt_output'])

if __name__ == "__main__":
    main()