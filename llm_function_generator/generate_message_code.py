# -*- coding: UTF-8 -*-
import os
from pathlib import Path
from llm_utils.config import config
from llm_utils.utils import load_json, save_json, log_message, generate_complete_cpp_file, PATTERN_DIR, SERVICES_DIR, FUZZ_EXEC_DIR
import json

import shutil

DEFAULT_PART1_HEADERS = """#include "generate_message.h"
#include <cstring>
#include <algorithm>
#include <mach/ndr.h>
#include <mach/message.h>
#include <mach/mach.h>

extern uint32_t choose_one_of(FuzzedDataProvider& fuzz_data, const std::vector<uint32_t>& choices);
"""

def _load_part1(functions_dir: Path) -> str:
    part1_path = functions_dir / "part1.json"
    if not part1_path.exists():
        return DEFAULT_PART1_HEADERS
    try:
        stored = load_json(part1_path)
        content = ""
        if isinstance(stored, dict):
            content = str(stored.get("part1_content", ""))
        elif isinstance(stored, str):
            content = stored
            
        if not content.strip():
            return DEFAULT_PART1_HEADERS
        return content
    except Exception as exc:
        log_message(f"读取PART1缓存失败: {exc}")
    return DEFAULT_PART1_HEADERS


def _append_part1(functions_dir: Path, snippet: str) -> str:
    addition = (snippet or "").strip()
    current = _load_part1(functions_dir)
    if not addition:
        return current
    if addition in current:
        return current

    if current.strip():
        sep = "" if current.rstrip().endswith("\n\n") else "\n\n"
        merged = f"{current.rstrip()}{sep}{addition}\n"
    else:
        merged = f"{addition}\n"

    part1_path = functions_dir / "part1.json"
    if not save_json({"part1_content": merged}, part1_path):
        log_message(f"警告：写入 PART1 缓存失败：{part1_path}")
        return current
    return merged

def generate_message_code_for_service_by_id(service_name="com.apple.bsd.dirhelper", use_english_prompts=False, use_cache=True, strategy="cot_4step", model_id=None):
    """
    为指定服务按消息ID逐个生成消息生成函数的C++代码
    
    Args:
        service_name: 服务名称，默认为 com.apple.bsd.dirhelper
        use_english_prompts: 是否使用英文提示词，默认为 False (使用中文)
        use_cache: 是否使用缓存，默认为 True。如果为 True，则优先使用已生成的函数实现
        strategy: 生成策略，默认为 "cot_4step"。用于决定约束文件和缓存目录
        model_id: 模型ID，如果 strategy 为 'model_test'，则用于生成后缀和覆盖默认模型
    """
    log_message(f"--- 开始为服务 {service_name} 按消息ID逐个生成消息代码 ---")
    log_message(f"配置参数: use_english_prompts={use_english_prompts}, use_cache={use_cache}, strategy={strategy}")
    
    # 检查服务目录是否存在
    service_dir = SERVICES_DIR / service_name
    if not service_dir.exists():
        other_dir = SERVICES_DIR.parent / "other_mig_services" / service_name
        if other_dir.exists():
            service_dir = other_dir
        else:
            log_message(f"错误：服务目录 {service_dir} 不存在")
            return False

    try:
        # 1. 根据策略确定约束文件
        if strategy == "no_task_dep":
            form_cons_filename = "form_cons_notaskdep.json"
        elif strategy == "no_cot":
            form_cons_filename = "form_cons_no_cot.json"
        elif strategy == "model_test" and model_id:
            form_cons_filename = f"form_cons_{model_id}.json"
        else:
            form_cons_filename = "form_cons.json"
            
        form_cons_file = service_dir / form_cons_filename
        if not form_cons_file.exists():
            log_message(f"错误：约束文件 {form_cons_file} 不存在")
            log_message(f"请先运行生成约束描述文件 (策略: {strategy})")
            return False
        form_cons_raw = load_json(form_cons_file)
        
        constraints_token = 0
        constraints_cost = 0.0
        if "constraints" in form_cons_raw and "summary" in form_cons_raw:
            form_cons = form_cons_raw["constraints"]
            constraints_token = form_cons_raw.get("summary", {}).get("total_tokens", 0)
            constraints_cost = form_cons_raw.get("summary", {}).get("total_cost", 0.0)
        else:
            form_cons = form_cons_raw
            
        log_message(f"成功加载约束文件 {form_cons_filename}，包含 {len(form_cons)} 个消息ID的约束")
        
        # 2. 读取工具函数库文件
        tools_file = Path(__file__).parent.parent / "fuzz_helpers" / "tool_lib.cc"
        if not tools_file.exists():
            log_message(f"错误：工具函数库文件 {tools_file} 不存在")
            return False
        with open(tools_file, 'r', encoding='utf-8') as f:
            tools_content = f.read()
        log_message(f"成功加载工具函数库文件，内容长度: {len(tools_content)} 字符")
        
        # 3. 读取示例实现文件
        pattern_file = PATTERN_DIR / "generate_message.cc"
        if not pattern_file.exists():
            log_message(f"错误：示例实现文件 {pattern_file} 不存在")
            return False
        with open(pattern_file, 'r', encoding='utf-8') as f:
            pattern_content = f.read()
        log_message(f"成功加载示例实现文件，内容长度: {len(pattern_content)} 字符")
        
        # 4. 初始化API客户端
        api_client = config.api_client
        
        # 5. 初始化PART1内容（工具函数部分）
        # 同步缓存目录：mig_services/<service_name>/functions_<strategy> -> fuzz_exec/<service_name>/functions
        dir_suffix = model_id if strategy == "model_test" and model_id else strategy
        mig_functions_dir = service_dir / f"functions_{dir_suffix}"
        
        # 目标fuzz_exec目录
        exec_service_dir = FUZZ_EXEC_DIR / service_name
        exec_service_dir.mkdir(parents=True, exist_ok=True)
        
        exec_functions_dir = exec_service_dir / "functions"
        exec_functions_dir.mkdir(parents=True, exist_ok=True)
        
        # 保存当前策略配置
        
        
        # 清理旧的functions目录，确保不混用不同策略的缓存
        if exec_functions_dir.exists():
            shutil.rmtree(exec_functions_dir)
        exec_functions_dir.mkdir(parents=True, exist_ok=True)
        
        # 保存当前策略配置
        records_file = exec_functions_dir / "record.json"
        try:
            with open(records_file, 'w', encoding='utf-8') as f:
                f.write(strategy)
        except Exception as e:
            log_message(f"保存策略配置出错: {e}")
        
        # 同步逻辑：如果 mig_services 中有缓存，先复制到 fuzz_exec
        if mig_functions_dir.exists():
            log_message(f"同步缓存: {mig_functions_dir.name} -> fuzz_exec/../functions")
            try:
                # 简单起见，按文件复制，避免直接 copytree 可能遇到的目录已存在问题
                for item in mig_functions_dir.iterdir():
                    if item.is_file():
                        shutil.copy2(item, exec_functions_dir / item.name)
            except Exception as e:
                log_message(f"同步缓存出错: {e}")
        
        # 使用 exec_functions_dir 作为主要的工作目录
        functions_dir = exec_functions_dir
        
        current_part1_content = _load_part1(functions_dir)
        
        # 6. 存储所有消息ID的生成函数
        all_message_functions = {}
        function_tokens = 0
        function_cost = 0.0
        
        # 7. 获取所有消息ID
        message_ids = list(form_cons.keys())
        log_message(f"发现 {len(message_ids)} 个消息ID: {message_ids}")
        
        # 8. 逐个处理每个消息ID
        for i, msg_id in enumerate(message_ids):
            log_message(f"处理消息ID {msg_id} ({i+1}/{len(message_ids)})")
            
            # 检查缓存
            functions_file = functions_dir / f"functions_{msg_id}.json"
            
            if use_cache and functions_file.exists():
                log_message(f"发现消息ID {msg_id} 的缓存文件，使用缓存数据")
                try:
                    cached_data = load_json(functions_file)
                    if cached_data and "message_functions" in cached_data:
                        message_funcs = cached_data["message_functions"].get(str(msg_id)) or cached_data["message_functions"].get(msg_id)
                        if message_funcs:
                            all_message_functions[msg_id] = message_funcs
                            log_message(f"成功从缓存加载消息ID {msg_id} 的函数")
                            
                            if "token_usage" in cached_data:
                                function_tokens += cached_data["token_usage"].get("total_tokens", 0)
                                function_cost += cached_data["token_usage"].get("cost", 0.0)
                        else:
                            log_message(f"警告：缓存文件 {functions_file} 中缺少消息ID {msg_id} 的函数数据")
                            continue
                    else:
                        log_message(f"警告：缓存文件 {functions_file} 格式不正确，跳过使用缓存")
                        continue
                except Exception as e:
                    log_message(f"加载缓存文件 {functions_file} 时出错: {e}，跳过使用缓存")
                    continue
                
                # 跳过LLM调用，继续下一个消息ID
                continue
            
            # 获取该消息ID的约束信息
            msg_constraints = {msg_id: form_cons[msg_id]}
            
            # 构建针对单个消息ID的提示
            if use_english_prompts:
                user_prompt = config.USER_MSG_GENERATE_BY_ID_EN.format(
                    service_name=service_name,
                    msg_id=msg_id,
                    msg_constraints=json.dumps(msg_constraints, indent=2, ensure_ascii=False),
                    tools_content=tools_content,
                    pattern_content=pattern_content,
                    current_part1_content=current_part1_content if current_part1_content else "// PART1内容为空，这是第一个消息ID"
                )
                log_message("user prompts loaded in English")
                system_prompt = config.SYSTEM_MSG_GENERATE_BY_ID_EN.format(
                    service_name=service_name, 
                    msg_id=msg_id
                )
                log_message("system prompts loaded in English")
            else:
                user_prompt = config.USER_MSG_GENERATE_BY_ID.format(
                    service_name=service_name,
                    msg_id=msg_id,
                    msg_constraints=json.dumps(msg_constraints, indent=2, ensure_ascii=False),
                    tools_content=tools_content,
                    pattern_content=pattern_content,
                    current_part1_content=current_part1_content if current_part1_content else "// PART1内容为空，这是第一个消息ID"
                )
                system_prompt = config.SYSTEM_MSG_GENERATE_BY_ID.format(
                    service_name=service_name, 
                    msg_id=msg_id
                )
            
            log_message(f"准备发送消息ID {msg_id} 的用户提示长度: {len(user_prompt)} 字符")
            
            # 调用LLM
            response = api_client.call_model(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_format="json_object"
            )
            
            if response and not response.get("is_over"):
                # 统计token消耗
                current_token_usage = response.get("__token_usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cost": 0.0})
                function_tokens += current_token_usage.get("total_tokens", 0)
                function_cost += current_token_usage.get("cost", 0.0)
                
                # 检查响应格式
                required_keys = ["part1_additions", "generate_header_function", 
                               "generate_descriptor_function", "generate_body_function", 
                               "generate_trailer_function", "generate_message_function"]
                
                if all(key in response for key in required_keys):
                    # 更新PART1内容
                    part1_additions = response.get("part1_additions", "")
                    merged_part1 = _append_part1(functions_dir, part1_additions)
                    if merged_part1 != current_part1_content:
                        current_part1_content = merged_part1
                        log_message(f"消息ID {msg_id} 更新了PART1内容，追加长度: {len((part1_additions or '').strip())} 字符")
                    else:
                        log_message(f"消息ID {msg_id} 无需追加新的PART1内容")
                    
                    # 存储该消息ID的生成函数
                    all_message_functions[msg_id] = {
                        "generate_header": response["generate_header_function"],
                        "generate_descriptor": response["generate_descriptor_function"],
                        "generate_body": response["generate_body_function"],
                        "generate_trailer": response["generate_trailer_function"],
                        "generate_message": response["generate_message_function"]
                    }
                    
                    log_message(f"成功生成消息ID {msg_id} 的代码函数")
                    
                    # 保存当前PART1和该消息ID的函数到单独文件
                    functions_data = {
                        "part1_content": current_part1_content,
                        "message_functions": {
                            str(msg_id): all_message_functions[msg_id]
                        },
                        "token_usage": current_token_usage
                    }

                    functions_file = functions_dir / f"functions_{msg_id}.json"
                    save_json(functions_data, functions_file)
                    
                    # 同时保存回 mig_services 以作为持久化备份
                    mig_functions_dir.mkdir(parents=True, exist_ok=True)
                    mig_functions_file = mig_functions_dir / f"functions_{msg_id}.json"
                    save_json(functions_data, mig_functions_file)
                    
                    # 同时更新 mig_services 里的 part1.json
                    mig_part1_file = mig_functions_dir / "part1.json"
                    save_json({"part1_content": current_part1_content}, mig_part1_file)
                    
                    log_message(f"已保存消息ID {msg_id} 的函数数据到: {functions_file} (及备份)")
                    
                else:
                    log_message(f"错误：消息ID {msg_id} 的LLM响应缺少必要字段: {response}")
                    return False
            else:
                log_message(f"错误：消息ID {msg_id} 的LLM调用失败: {response}")
                return False
        
        # 9. 整合所有代码
        log_message("开始整合所有消息ID的代码...")
        
        # 构建完整的C++文件内容
        cpp_content = generate_complete_cpp_file(
            current_part1_content, 
            all_message_functions, 
            message_ids
        )
        
        # 10. 保存生成的C++文件
        # 本次修改移除了生成备份到 mig_services 的逻辑，仅保存到 fuzz_exec
        
        # 覆盖fuzz_exec下的目标文件（使用现有的头文件）
        cpp_file = exec_service_dir / "generate_message.cc"
        with open(cpp_file, 'w', encoding='utf-8') as f:
            f.write(cpp_content)
        log_message(f"成功更新工作区C++文件: {cpp_file}")
        log_message("注意：使用现有的 generate_message.h 头文件")
        
        # 11. 保存record.json文件
        records_data = {
            "strategy": strategy,
            "model_id": model_id if model_id else config.model_id,
            "constraints_token": constraints_token,
            "constraints_cost": constraints_cost,
            "function_token": function_tokens,
            "function_cost": function_cost,
            "total_token": constraints_token + function_tokens,
            "total_cost": constraints_cost + function_cost
        }
        with open(records_file, 'w', encoding='utf-8') as f:
            json.dump(records_data, f, indent=4, ensure_ascii=False)
        log_message(f"成功保存记录文件: {records_file}")
        
        log_message(f"--- 服务 {service_name} 的按消息ID逐个生成代码完毕 ---")
        return True
        
    except Exception as e:
        import traceback
        log_message(f"生成过程中发生错误: {traceback.format_exc()}")
        return False

