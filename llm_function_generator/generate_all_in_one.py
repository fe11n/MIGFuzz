#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
fuzzkit/preprocess_all_in_one.py

自动化预处理脚本，对mig_services中的每个服务执行完整的预处理流程：
1. 生成格式化约束 (generate_form_cons_cot_4step)
2. 准备fuzz执行工作区 (prepare_fuzz_exec_workspace)
3. 生成消息代码 (generate_message_code_for_service_by_id)

"""

import os
import json
import subprocess
import tempfile
import sys
from pathlib import Path
from typing import Dict, List, Tuple
import shutil
import argparse

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from llm_function_generator.init_cons_withllm import generate_form_cons_no_task_dep, generate_form_cons_cot_4step, generate_form_cons_no_cot
from llm_utils.utils import prepare_fuzz_exec_workspace, load_json, save_json, SERVICES_DIR, FUZZ_EXEC_DIR, log_message
from llm_function_generator.generate_message_code import generate_message_code_for_service_by_id

def get_service_names(include_other=False, only_other=False):
    """获取mig_services目录中的所有服务名称，可选包含或仅包含other_mig_services"""
    services_dirs = []
    
    mig_dir = project_root / "mig_services"
    other_dir = project_root / "other_mig_services"

    if only_other:
        # 仅处理 other_mig_services
        if other_dir.exists():
            services_dirs.append(other_dir)
        else:
            log_message(f"other_mig_services目录不存在: {other_dir}")
    else:
        # 处理 mig_services
        if mig_dir.exists():
            services_dirs.append(mig_dir)
        
        # 如果指定包含 other，则追加
        if include_other:
            if other_dir.exists():
                services_dirs.append(other_dir)
            else:
                log_message(f"other_mig_services目录不存在: {other_dir}")

    services = []
    for s_dir in services_dirs:
        if not s_dir.exists():
            continue
        for item in s_dir.iterdir():
            if item.is_dir():
                # 为了区分来源，这里可以不做特殊处理，但后续处理服务时需要知道路径
                # 现有的 logic 假设服务都在 SERVICES_DIR (llm_utils.utils.SERVICES_DIR) = mig_services
                # 这是一个问题。
                services.append(item.name)

    log_message(f"发现 {len(services)} 个服务: {services}")
    return sorted(list(set(services))) # 去重并排序

def process_service(service_name: str, index: int, strategy_name: str = 'cot_4step', language: str = 'en', only_cons: bool = False, model_id: str = None):
    """处理单个服务"""
    log_message(f"开始处理服务: {service_name}")

    # 初始化统计变量
    total_count = 0
    successful_count = 0
    success_rate = 0.0

    use_english = (language == 'en')

    try:
        # 步骤1: 生成格式化约束
        log_message(f"步骤1: 生成格式化约束 (策略: {strategy_name}, 语言: {language}{', 模型: ' + model_id if model_id else ''})")
        
        ok = False
        if strategy_name == 'model_test':
             if not model_id:
                 log_message("使用 model_test 策略必须提供 --model-id 参数")
                 return False
                 
             from llm_utils.config import config
             config.api_client.set_model(model_id)
             
             ok = generate_form_cons_cot_4step(service_name, use_english_prompts=use_english, use_cache=True, model_id=model_id)
        elif strategy_name == 'cot_4step':
             ok = generate_form_cons_cot_4step(service_name, use_english_prompts=use_english, use_cache=True)
        elif strategy_name == 'no_task_dep':
             ok = generate_form_cons_no_task_dep(service_name, use_english_prompts=use_english, use_cache=True)
        elif strategy_name == 'no_cot':
             ok = generate_form_cons_no_cot(service_name, use_english_prompts=use_english, use_cache=True)
        else:
             log_message(f"未知策略: {strategy_name}")
             return False

        if not ok:
            log_message(f"服务 {service_name} 生成格式化约束失败")
            return False

        if only_cons:
            log_message(f"仅生成约束，跳过后续步骤")
            return True

        # 步骤2: 准备fuzz执行工作区
        log_message("步骤2: 准备fuzz执行工作区")
        exec_dir = prepare_fuzz_exec_workspace(service_name, index)
        service_exec_name = service_name if index == 0 else f"{service_name}_{index}"
        log_message(f"fuzz执行工作区路径: {exec_dir}")

        # 步骤3: 生成消息代码
        log_message("步骤3: 生成消息代码")
        code_success = generate_message_code_for_service_by_id(
            service_name=service_name,
            use_english_prompts=use_english,
            strategy=strategy_name,
            model_id=model_id
        )
        if not code_success:
            log_message(f"服务 {service_name} 生成消息代码失败")
            return False

        log_message(f"服务 {service_name} 处理完成")
        return True

    except Exception as e:
        log_message(f"处理服务 {service_name} 时发生错误: {e}")
        import traceback
        log_message(traceback.format_exc())
        return False

def main():
    parser = argparse.ArgumentParser(description='自动化预处理mig_services中的所有服务')
    parser.add_argument('--index', type=int, default=0, help='工作区索引，默认为0')
    parser.add_argument('--services', nargs='*', help='指定要处理的服务名称，不指定则处理所有服务')
    parser.add_argument('--strategy', type=str, default='cot_4step', choices=['no_task_dep', 'cot_4step', 'no_cot', 'model_test'], help='生成约束的策略')
    parser.add_argument('--model-id', type=str, default=None, help='指定的模型ID，当策略为 model_test 时必须提供')
    parser.add_argument('--lang', type=str, default='en', choices=['en', 'zh'], help='提示词语言 (en | zh)')
    parser.add_argument('--only-constraints', action='store_true', help='仅生成约束，不生成代码')
    parser.add_argument('--include-other', action='store_true', help='是否包含other_mig_services目录下的服务')
    parser.add_argument('--only-other', action='store_true', help='仅处理other_mig_services目录下的服务')

    args = parser.parse_args()
    index = args.index
    specified_services = args.services
    strategy = args.strategy
    model_id = args.model_id
    language = args.lang
    only_cons = args.only_constraints
    include_other = args.include_other
    only_other = args.only_other

    log_message("开始自动化预处理流程")
    log_message(f"工作区索引: {index}, 策略: {strategy}, 模型: {model_id}, 语言: {language}, 仅生成约束: {only_cons}, 包含其他: {include_other}, 仅其他: {only_other}")

    # 获取服务列表
    all_services = get_service_names(include_other=include_other, only_other=only_other)
    if specified_services:
        services_to_process = [s for s in specified_services if s in all_services]
        if not services_to_process:
            log_message("指定的服务都不存在")
            return
        log_message(f"将处理指定的服务: {services_to_process}")
    else:
        services_to_process = all_services
        log_message(f"将处理所有 {len(services_to_process)} 个服务")

    # 处理每个服务
    success_count = 0
    for service_name in services_to_process:
        if process_service(service_name, index, strategy_name=strategy, language=language, only_cons=only_cons, model_id=model_id):
            success_count += 1
        log_message("-" * 60)

    log_message(f"预处理流程完成 - 总服务数: {len(services_to_process)}, 成功: {success_count}, 失败: {len(services_to_process) - success_count}")

if __name__ == "__main__":
    main()