# -*- coding: UTF-8 -*-
import json
import subprocess
import os
import shutil
from datetime import datetime
import threading
from pathlib import Path

# 全局路径变量，相对于文件夹llm_function_generator
# SERVICES_DIR = Path("services")
SERVICES_DIR = Path(__file__).parent.parent / "mig_services"
# fuzz 可执行工作区根目录（相对于 llm_function_generator）
FUZZ_EXEC_DIR = Path(__file__).parent.parent / "fuzz_exec"
PATTERN_DIR = Path(__file__).parent / "pattern"
LOG_DIR = Path("log")

# 文件锁保证多线程安全
log_lock = threading.Lock()

def log_message(message):
    """记录日志信息到控制台和文件"""
    now = datetime.now()
    log_msg = f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    
    # 打印到控制台（DEBUG_MODE控制）
    from llm_utils.config import config  # 延迟导入
    if config.DEBUG_MODE:
        print(log_msg)
    
    # 按日期写入log文件夹中的文件
    log_dir = LOG_DIR
    log_dir.mkdir(exist_ok=True)
    date_str = now.strftime('%Y-%m-%d')
    log_file = log_dir / f"log_{date_str}.txt"
    try:
        with log_lock:  # 确保线程安全
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(log_msg + "\n")
    except Exception as e:
        print(f"!! 日志写入失败: {e}")

def decode_unicode_string(s):
    """将字符串中的Unicode转义字符转换为实际中文字符"""
    if not isinstance(s, str):
        return s
        
    try:
        # 处理纯Unicode转义字符串（如"\u4ece"）
        if '\\u' in s and '"' not in s:
            return s.encode('utf-8').decode('unicode_escape')
        
        # 处理JSON格式的Unicode字符串（如""\u4ece\""）
        if '"\\u' in s:
            import ast
            return ast.literal_eval(f'"{s}"')
            
    except Exception as e:
        log_message(f"Unicode解码失败: {e} | 原始字符串: {s}")
    
    return s

def save_json(data, path, indent=2):
    """保存JSON文件"""
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        return True
    except Exception as e:
        log_message(f"保存JSON文件失败: {e}")
        return False

def get_check_result_path(target_service_dir: Path) -> Path:
    """Read the active strategy from functions/record.json and return the check result path."""
    records_file = target_service_dir / "functions" / "record.json"
    if records_file.exists():
        try:
            records_data = load_json(records_file)
            strategy = records_data.get("strategy", "").strip()
            if strategy:
                if strategy == "model_test":
                    m_id = records_data.get("model_id")
                    if m_id:
                        strategy = f"model_test_{m_id}"
                return target_service_dir / f"check_result_{strategy}.json"
        except Exception:
            pass
    return target_service_dir / "check_result.json"

def _ensure_dir(path: Path):
    """确保目录存在。"""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        log_message(f"创建目录失败: {path} | {e}")

def _next_workspace_dir(base_dir: Path, base_name: str) -> Path:
    """为 fuzz_exec 生成下一个工作目录。

    规则：
    - 若 fuzz_exec 下不存在 base_name 目录，则返回 fuzz_exec/base_name
    - 若已存在，则扫描 base_name_\d+ 后缀的目录，取最大值 + 1，返回 fuzz_exec/base_name_{n}
    """
    primary = base_dir / base_name
    if not primary.exists():
        return primary

    # 找到所有 base_name_\d+ 目录
    max_idx = 0
    for child in base_dir.iterdir():
        if not child.is_dir():
            continue
        name = child.name
        if not name.startswith(f"{base_name}_"):
            continue
        suffix = name.split("_")[-1]
        if suffix.isdigit():
            max_idx = max(max_idx, int(suffix))

    return base_dir / f"{base_name}_{max_idx + 1}"

def _parse_hex_address(addr_str: str) -> int:
    """将字符串形式（可能无 0x 前缀）的十六进制地址转换为整数。"""
    try:
        # 去掉可能的 0x/0X 前缀
        s = addr_str.strip()
        if s.lower().startswith("0x"):
            s = s[2:]
        # 某些数据如 "10000AF38" 为纯十六进制
        return int(s, 16)
    except Exception:
        # 如果包含非十六进制字符，尝试直接转为整数
        try:
            return int(addr_str)
        except Exception:
            return 0

def _format_offset_from_address(addr_str: str) -> str:
    """根据地址计算文件内偏移（示例：10003D028 -> 0x3D028）。

    经验规则：取地址的低 20 比特（5 个十六进制字符），以 0x 前缀十六进制字符串返回。
    若解析失败，返回空字符串。
    """
    val = _parse_hex_address(addr_str)
    if val == 0:
        return ""
    
    # Convert VM address to file offset if necessary (assuming 0x100000000 base)
    if val >= 0x100000000:
        val -= 0x100000000
        
    return hex(val)

def _get_program_path_from_summary(service_name: str) -> str:
    """尝试从 launchd_summary.json 获取服务的 program 路径。"""
    summary_path = SERVICES_DIR / "launchd_summary.json"
    if not summary_path.exists():
        return ""
    
    try:
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        services = data.get("services", [])
        for svc in services:
            # 1. 尝试匹配 label
            if svc.get("label") == service_name:
                return svc.get("program", "")
            
            # 2. 尝试匹配 mach_services
            mach_services = svc.get("mach_services", [])
            if service_name in mach_services:
                return svc.get("program", "")
                
    except Exception as e:
        log_message(f"读取 launchd_summary.json 失败: {e}")
        
    return ""

def prepare_fuzz_exec_workspace(service_name: str, index: int = 0) -> Path:
    """基于 SERVICES_DIR/<service_name> 准备 fuzz_exec 工作目录与配置。

    执行步骤：
    1. 从 SERVICES_DIR/<service_name>/mig_information.json 读取程序路径、子系统信息
     2. 计算 fuzz_exec 下的目标工作目录（名称基于 service_name 和 index）：
         - 目录名为 service_name（当 index == 0 时）或 f"{service_name}_{index}"（当 index != 0 时）
         - 若目录已存在，则直接使用；若不存在，则创建该目录
    3. 在目标目录创建 service.json，字段：
       - library_path: mig_information.json.program_path
       - start_function: ""
       - subsystem_num: mig_information.json.subsystem_count
       - dispatch_routines: [ 每个 subsystem.routine.name ]
       - dispatch_routine_offsets: [ 按地址计算得到的偏移字符串，如 0x3D028 ]
       - fuzz.instrument_module: program_path 的文件名

    注意：路径以 llm_function_generator 为工作目录的相对路径计算（与本模块其他函数保持一致）。

    Args:
        service_name (str): 服务名称，例如 "com.apple.FileCoordination"。
        index (int): 工作目录索引，默认为 0。

    Returns:
        Path: 创建/选定的 fuzz_exec/<workspace> 目录绝对路径。
    """
    # 1) 计算/创建工作目录（目录名基于 service_name 和 index）
    workspace_root = FUZZ_EXEC_DIR
    _ensure_dir(workspace_root)
    
    # 根据 index 构造目录名
    service_exec_name = service_name if int(index) == 0 else f"{service_name}_{int(index)}"
    target_dir = workspace_root / service_exec_name
    
    # 如果目录不存在则创建
    if not target_dir.exists():
        _ensure_dir(target_dir)

    # 2) 检查 service.json 是否已存在
    service_json_path = target_dir / "service.json"
    if service_json_path.exists():
        log_message(f"service.json 已存在，跳过生成: {service_json_path}")
        return target_dir.resolve()

    # 3) 读取 mig_information.json
    service_dir = SERVICES_DIR / service_name
    if not service_dir.exists():
         other_dir = SERVICES_DIR.parent / "other_mig_services" / service_name
         if other_dir.exists():
             service_dir = other_dir
    mig_info_path = service_dir / "mig_information.json"
    if not mig_info_path.exists():
        raise FileNotFoundError(f"未找到 mig_information.json: {mig_info_path}")

    try:
        with open(mig_info_path, "r", encoding="utf-8") as f:
            mig_info = json.load(f)
    except Exception as e:
        raise RuntimeError(f"解析 {mig_info_path} 失败: {e}")

    program_path = mig_info.get("program_path", "")
    
    # 如果 mig_information.json 中没有 program_path，尝试从 launchd_summary.json 获取
    if not program_path:
        log_message(f"mig_information.json 中缺少 program_path，尝试从 launchd_summary.json 查找...")
        program_path = _get_program_path_from_summary(service_name)
        if program_path:
            log_message(f"从 launchd_summary.json 找到 program_path: {program_path}")

    subsystem_num = int(mig_info.get("subsystem_count", 0) or 0)
    subsystems = mig_info.get("subsystems", []) or []

    if not program_path:
        raise ValueError("无法找到服务的 program_path (mig_information.json 和 launchd_summary.json 中均未找到)")

    bin_base_name = os.path.basename(program_path)  # 供 fuzz.instrument_module 使用
    if not bin_base_name:
        raise ValueError(f"无法从 program_path 提取文件名: {program_path}")

    # 4) 生成 service.json
    dispatch_routines = []
    dispatch_routine_offsets = []
    subsystem_start_ids = []
    subsystem_end_ids = []

    for sub in subsystems:
        routine = (sub or {}).get("routine", {}) or {}
        name = routine.get("name", "") or ""
        addr = routine.get("address", "") or ""
        start_id = (sub or {}).get("start_id", 0)
        end_id = (sub or {}).get("end_id", 0)

        if name:
            dispatch_routines.append(name)
        else:
            dispatch_routines.append("")
        dispatch_routine_offsets.append(_format_offset_from_address(addr))
        subsystem_start_ids.append(start_id)
        subsystem_end_ids.append(end_id)

    service_json = {
        "library_path": program_path,
        "start_function": "",
        "subsystem_num": subsystem_num,
        "subsystem_start_ids": subsystem_start_ids,
        "subsystem_end_ids": subsystem_end_ids,
        "fuzz": {
            "enabled": True,
            "instrument_module": bin_base_name,
            "iterations": 1000,
            "threads": 5
        },
        "dispatch_routines": dispatch_routines,
        "dispatch_routine_offsets": dispatch_routine_offsets
    }

    try:
        with open(target_dir / "service.json", "w", encoding="utf-8") as f:
            json.dump(service_json, f, indent=2)
    except Exception as e:
        raise RuntimeError(f"写入 service.json 失败: {e}")

    log_message(f"fuzz_exec 工作区已准备就绪: {target_dir}")
    return target_dir.resolve()

def clean_llm_response_for_form_cons(response_data):
    """
    清理LLM响应数据，删除所有思考链和分析字段，用于保存到form_cons.json

    Args:
        response_data (dict): LLM的原始响应数据

    Returns:
        dict: 清理后的数据，移除了所有思维链和分析字段
    """
    if not isinstance(response_data, dict):
        return response_data

    cleaned_data = {}

    for key, value in response_data.items():
        if isinstance(value, dict):
            # 递归清理嵌套字典
            cleaned_value = clean_llm_response_for_form_cons(value)

            # 删除所有思维链和分析字段
            thinking_chain_fields = [
                'descriptor_thinking_chain',
                'constraint_thinking_chain',
                'locate_thinking_chain',
                'constraint_analysis',
                'thinking_chain',
                'analysis_chain'
            ]

            for field in thinking_chain_fields:
                if field in cleaned_value:
                    del cleaned_value[field]

            cleaned_data[key] = cleaned_value
        elif isinstance(value, list):
            # 处理列表中的字典 - 递归清理每个列表项
            cleaned_list = []
            for item in value:
                if isinstance(item, dict):
                    # 递归清理字典项
                    cleaned_item = clean_llm_response_for_form_cons(item)

                    # 删除所有思维链和分析字段
                    thinking_chain_fields = [
                        'descriptor_thinking_chain',
                        'constraint_thinking_chain',
                        'locate_thinking_chain',
                        'constraint_analysis',
                        'thinking_chain',
                        'analysis_chain'
                    ]

                    for field in thinking_chain_fields:
                        if field in cleaned_item:
                            del cleaned_item[field]

                    cleaned_list.append(cleaned_item)
                else:
                    cleaned_list.append(item)

            cleaned_data[key] = cleaned_list
        else:
            cleaned_data[key] = value

    return cleaned_data

def load_json(path):
    """加载JSON文件"""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def compile_proto_file(proto_file, output_dir):
    """
    编译proto文件生成C++代码
    """
    log_message("--- 开始编译proto文件 ---")
    
    try:
        # 检查protoc是否可用
        protoc_paths = [
            "/opt/homebrew/opt/protobuf@21/bin/protoc",
            "/opt/homebrew/bin/protoc",
            "/usr/local/bin/protoc",
            "protoc"
        ]
        
        protoc_cmd = None
        for path in protoc_paths:
            try:
                result = subprocess.run([path, "--version"], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                if result.returncode == 0:
                    protoc_cmd = path
                    log_message(f"找到protoc编译器: {path}")
                    log_message(f"版本信息: {result.stdout.strip()}")
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        if not protoc_cmd:
            log_message("错误：未找到protoc编译器，请安装Protocol Buffers")
            log_message("安装命令: brew install protobuf@21")
            return False
        
        # 确保输出目录存在
        output_dir = Path(output_dir).resolve()  # 获取绝对路径
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # 确保proto文件存在
        proto_file_abs = Path(proto_file).resolve()
        if not proto_file_abs.exists():
            log_message(f"错误：Proto文件不存在: {proto_file_abs}")
            return False
        
        # 设置proto路径，包含normal_proto目录
        # 假设normal_proto目录在项目根目录下
        project_root = Path(__file__).parent.resolve()
        normal_proto_dir = project_root / "normal_proto"
        
        # 执行编译命令，在proto文件所在目录执行
        compile_cmd = [
            protoc_cmd,
            "--cpp_out=.",
            "--proto_path=.",
            f"--proto_path={normal_proto_dir}",  # 添加normal.proto路径
            proto_file_abs.name  # 只使用文件名
        ]
        
        log_message(f"执行编译命令: {' '.join(compile_cmd)}")
        log_message(f"工作目录: {output_dir}")
        log_message(f"Proto文件: {proto_file_abs.name}")
        log_message(f"Normal proto路径: {normal_proto_dir}")
        
        # 在proto文件所在目录执行编译
        result = subprocess.run(
            compile_cmd,
            cwd=output_dir,  # 切换到proto文件所在目录
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            log_message("proto文件编译成功！")
            
            # 检查生成的文件
            generated_files = []
            proto_name = proto_file.stem  # 去掉.proto扩展名
            
            expected_files = [
                output_dir / f"{proto_name}.pb.h",
                output_dir / f"{proto_name}.pb.cc"
            ]
            
            for file_path in expected_files:
                if file_path.exists():
                    generated_files.append(file_path)
                    log_message(f"生成文件: {file_path}")
            
            if generated_files:
                log_message(f"成功生成 {len(generated_files)} 个文件")
                return True
            else:
                log_message("警告：编译成功但未找到预期的生成文件")
                return False
        else:
            log_message("proto文件编译失败！")
            log_message(f"错误输出: {result.stderr}")
            if result.stdout:
                log_message(f"标准输出: {result.stdout}")
            return False
            
    except subprocess.TimeoutExpired:
        log_message("编译超时")
        return False
    except Exception as e:
        log_message(f"编译过程中发生错误: {e}")
        return False


def generate_complete_cpp_file(part1_content, all_message_functions, message_ids):
    """
    生成完整的C++实现文件
    
    Args:
        part1_content: PART1的工具函数内容
        all_message_functions: 所有消息ID的生成函数字典
        message_ids: 消息ID列表
    
    Returns:
        str: 完整的C++文件内容
    """
    cpp_lines = []
    
    # 文件头部
    # cpp_lines.append('#include "generate_message.h"')
    # cpp_lines.append('#include <cstring>')
    # cpp_lines.append('#include <algorithm>')
    # cpp_lines.append('#include <mach/ndr.h>')
    # cpp_lines.append('#include <mach/message.h>')
    # cpp_lines.append('')
    
    # PART1: 工具函数声明和定义
    cpp_lines.append('// ================================================================')
    cpp_lines.append('// PART1: Header file inclusions, tool function declarations and definitions')
    cpp_lines.append('// This part is used to include necessary headers, declare external tool functions or define custom tool functions.')
    cpp_lines.append('// Tool functions will be used in subsequent message construction processes. Special structures can also be defined here.')
    cpp_lines.append('// ================================================================')
    cpp_lines.append('')
    
    # 外部工具函数声明
    # cpp_lines.append('// External tool function declarations - from helpers module')
    # cpp_lines.append('extern std::vector<uint8_t> get_standard_trailer();')
    # cpp_lines.append('extern void generate_header(FuzzedDataProvider& fuzz_data, uint32_t msg_size, uint32_t msg_id, std::vector<uint8_t>& header, bool is_ool);')
    # cpp_lines.append('extern uint32_t choose_one_of(FuzzedDataProvider& fuzz_data, const std::vector<uint32_t>& choices);')
    # cpp_lines.append('')
    
    # 添加PART1内容
    if part1_content.strip():
        cpp_lines.append(part1_content)
        cpp_lines.append('')
    
    # PART2: 各消息ID的生成函数
    cpp_lines.append('// ================================================================')
    cpp_lines.append('// PART2: Message ID-based message construction functions for each part')
    cpp_lines.append('// This part is used to define functions that construct different message content for different message IDs based on form_cons.json.')
    cpp_lines.append('// Including: generate_message_{id} functions that call component generators like generate_header_{id}, generate_descriptor_{id}, etc.')
    cpp_lines.append('// ================================================================')
    cpp_lines.append('')
    
    # 为每个消息ID添加函数
    for msg_id in message_ids:
        if msg_id in all_message_functions:
            cpp_lines.append(f'// Component generation functions for message ID {msg_id}')
            cpp_lines.append('')
            
            # 添加各个组件函数
            for func_name, func_code in all_message_functions[msg_id].items():
                if func_code.strip():
                    cpp_lines.append(func_code)
                    cpp_lines.append('')
    
    # PART3: 主函数
    cpp_lines.append('// ================================================================')
    cpp_lines.append('// PART3: Main function')
    cpp_lines.append('// This part defines the generate_message function that will be called by this file,')
    cpp_lines.append('// responsible for dispatching to message-specific generation functions')
    cpp_lines.append('// ================================================================')
    cpp_lines.append('')
    
    # 主入口函数 - 指定消息ID版本
    cpp_lines.append('// Main entry function - generate complete Mach message')
    cpp_lines.append('void generate_message(')
    cpp_lines.append('    uint32_t msg_id, ')
    cpp_lines.append('    FuzzedDataProvider& fuzz_data, ')
    cpp_lines.append('    std::vector<uint8_t>& mach_msg,')
    cpp_lines.append('    std::vector<std::pair<void*, uint32_t>>& ool_buffers')
    cpp_lines.append(') {')
    cpp_lines.append('    switch (msg_id) {')
    
    # 为每个消息ID添加case
    for msg_id in message_ids:
        cpp_lines.append(f'        case {msg_id}:')
        cpp_lines.append(f'            generate_message_{msg_id}(fuzz_data, mach_msg, ool_buffers);')
        cpp_lines.append('            break;')
    
    cpp_lines.append('        default:')
    cpp_lines.append('            // Unsupported message ID, clear the message buffer')
    cpp_lines.append('            mach_msg.clear();')
    cpp_lines.append('            break;')
    cpp_lines.append('    }')
    cpp_lines.append('}')
    cpp_lines.append('')
    
    # 重载函数 - 随机选择消息ID版本
    cpp_lines.append('// Overloaded function: randomly choose msg_id')
    cpp_lines.append('void generate_message(')
    cpp_lines.append('    FuzzedDataProvider& fuzz_data, ')
    cpp_lines.append('    std::vector<uint8_t>& mach_msg,')
    cpp_lines.append('    std::vector<std::pair<void*, uint32_t>>& ool_buffers')
    cpp_lines.append(') {')
    
    # 构建消息ID列表
    msg_id_list = ', '.join(message_ids)
    cpp_lines.append(f'    std::vector<uint32_t> available_msg_ids = {{{msg_id_list}}};')
    cpp_lines.append('    ')
    cpp_lines.append('    // Randomly choose a message ID')
    cpp_lines.append('    uint32_t msg_id = choose_one_of(fuzz_data, available_msg_ids);')
    cpp_lines.append('    ')
    cpp_lines.append('    // Call original function')
    cpp_lines.append('    generate_message(msg_id, fuzz_data, mach_msg, ool_buffers);')
    cpp_lines.append('}')
    cpp_lines.append('')
    
    # 新增重载函数 - 从提供的msg_ids中选择
    cpp_lines.append('// New overloaded function: choose from provided msg_ids')
    cpp_lines.append('void generate_message(')
    cpp_lines.append('    std::vector<uint32_t>& msg_ids, ')
    cpp_lines.append('    FuzzedDataProvider& fuzz_data, ')
    cpp_lines.append('    std::vector<uint8_t>& mach_msg,')
    cpp_lines.append('    std::vector<std::pair<void*, uint32_t>>& ool_buffers')
    cpp_lines.append(') {')
    cpp_lines.append('    // Randomly choose a message ID from msg_ids')
    cpp_lines.append('    uint32_t msg_id = choose_one_of(fuzz_data, msg_ids);')
    cpp_lines.append('    ')
    cpp_lines.append('    // Call original function')
    cpp_lines.append('    generate_message(msg_id, fuzz_data, mach_msg, ool_buffers);')
    cpp_lines.append('}')
    
    return '\n'.join(cpp_lines)


def combine_generate_code(service_name, use_updated_functions: bool = False):
    """根据缓存整合生成指定服务的generate_message.cc内容。

    Args:
        service_name (str): 服务名称，例如 "com.apple.FileCoordination"。
        use_updated_functions (bool): 是否使用 updated_functions 文件夹，默认 False 使用 functions。

    Returns:
        str | None: 生成的完整C++内容；当发生错误或无缓存时返回None。
    """
    service_dir = FUZZ_EXEC_DIR / service_name
    if not service_dir.exists():
        log_message(f"错误：服务目录 {service_dir} 不存在，无法整合代码")
        return None

    functions_dir = service_dir / ("updated_functions" if use_updated_functions else "functions")
    if not functions_dir.exists():
        log_message(f"错误：函数缓存目录 {functions_dir} 不存在，无法整合代码")
        return None

    part1_file = functions_dir / "part1.json"
    part1_content = ""
    if part1_file.exists():
        try:
            stored_part1 = load_json(part1_file)
            if isinstance(stored_part1, dict):
                part1_content = stored_part1.get("part1_content", "")
            elif isinstance(stored_part1, str):
                part1_content = stored_part1
        except Exception as e:
            log_message(f"读取PART1缓存失败: {e}")

    cache_files = sorted(functions_dir.glob("functions_*.json"))
    if not cache_files:
        if not part1_content.strip():
            log_message(f"警告：未在 {functions_dir} 中找到任何函数缓存，跳过整合")
            return None
        log_message("仅发现PART1缓存，将使用空的消息函数集合")

    all_message_functions = {}
    message_ids = []

    for cache_file in cache_files:
        try:
            cache_data = load_json(cache_file) 
        except Exception as e:
            log_message(f"加载缓存文件 {cache_file} 失败: {e}")
            continue

        if not isinstance(cache_data, dict):
            log_message(f"警告：缓存文件 {cache_file} 格式异常，已跳过")
            continue

        message_funcs = cache_data.get("message_functions", {})
        if not isinstance(message_funcs, dict):
            log_message(f"警告：缓存文件 {cache_file} 缺少 message_functions 字段")
            continue

        for msg_id_key, functions in message_funcs.items():
            if functions is None:
                continue
            msg_id_str = str(msg_id_key)
            if msg_id_str not in message_ids:
                message_ids.append(msg_id_str)
            all_message_functions[msg_id_str] = functions

    if not all_message_functions:
        log_message(f"警告：未在 {functions_dir} 中收集到任何消息函数，跳过整合")
        return None

    # 按数值排序消息ID，保持生成顺序稳定
    try:
        message_ids.sort(key=lambda x: int(x))
    except ValueError:
        message_ids.sort()

    cpp_content = generate_complete_cpp_file(part1_content, all_message_functions, message_ids)

    return cpp_content