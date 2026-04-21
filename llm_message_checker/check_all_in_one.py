#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
fuzzkit/check_all_in_one.py

自动化检查脚本，对fuzz_exec中的每个服务执行消息可达性检查：
1. 检查消息可达性 (check_message_ids)
2. 重新生成失败的消息 (regenerate_failed_messages)

日志记录到 fuzzkit/check.log
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

from llm_utils.utils import load_json, save_json, SERVICES_DIR, FUZZ_EXEC_DIR, log_message
from llm_message_checker.message_checker import check_message_ids, regenerate_failed_messages

# 配置日志
LOG_FILE = Path(__file__).parent / "check.log"

def get_service_names():
    """获取fuzz_exec目录中的所有服务名称"""
    if not FUZZ_EXEC_DIR.exists():
        raise FileNotFoundError(f"fuzz_exec目录不存在: {FUZZ_EXEC_DIR}")

    services = []
    for item in FUZZ_EXEC_DIR.iterdir():
        if item.is_dir():
            services.append(item.name)

    log_message(f"发现 {len(services)} 个服务: {services}")
    return sorted(services)

def process_service(service_name: str, regenerate: bool):
    """处理单个服务"""
    log_message(f"开始处理服务: {service_name}")

    # 初始化统计变量
    total_count = 0
    successful_count = 0
    success_rate = 0.0
    usage_tracker = {"total_tokens": 0, "cost": 0.0}

    try:
        # 准备fuzz执行工作区路径
        # service_name 直接来自 fuzz_exec 目录，是完整的执行目录名
        target_service_dir = FUZZ_EXEC_DIR / service_name
        from llm_utils.utils import get_check_result_path
        check_result_path = get_check_result_path(target_service_dir)

        # 检查目标目录是否存在
        if not target_service_dir.exists():
            log_message(f"服务 {service_name} 的执行目录不存在: {target_service_dir}")
            return False 

        # 步骤1: 检查消息可达性
        log_message("步骤1: 检查消息可达性")

        # 检查 check_result.json 是否存在
        if check_result_path.exists():
            try:
                existing_data = load_json(check_result_path)
                if existing_data.get('checkable') is False:
                    log_message(f"服务 {service_name} 标记为不可检查 (checkable=False)，跳过检查")
                    return False
            except Exception as e:
                log_message(f"读取 check_result.json 失败: {e}")

            check_result = check_message_ids(service_name, service_name, usage_tracker=usage_tracker)
            if check_result == 0:
                functions_dir = target_service_dir / "functions"
                if functions_dir.exists():
                    log_message(f"检查失败，请排查原因")
                # 将编译产生的cost写入
                if check_result_path.exists() and (usage_tracker["total_tokens"] > 0 or usage_tracker["cost"] > 0):
                    try:
                        cr_data = load_json(check_result_path)
                        cr_data["grand_total_tokens"] = cr_data.get("grand_total_tokens", 0) + usage_tracker["total_tokens"]
                        cr_data["grand_total_cost"] = cr_data.get("grand_total_cost", 0.0) + usage_tracker["cost"]
                        if usage_tracker.get("recompile_usages"):
                            cr_data.setdefault("initial_recompile_attempts", []).extend(usage_tracker["recompile_usages"])
                        save_json(cr_data, check_result_path)
                    except: pass
                return False
                # check_result == -1 表示成功，继续
        else:
            # 执行消息可达性检查
            check_result = check_message_ids(service_name, service_name, usage_tracker=usage_tracker)
            if check_result == 0:
                functions_dir = target_service_dir / "functions"
                if functions_dir.exists():
                    log_message(f"检查失败，请排查原因")
                if check_result_path.exists() and (usage_tracker["total_tokens"] > 0 or usage_tracker["cost"] > 0):
                    try:
                        cr_data = load_json(check_result_path)
                        cr_data["grand_total_tokens"] = cr_data.get("grand_total_tokens", 0) + usage_tracker["total_tokens"]
                        cr_data["grand_total_cost"] = cr_data.get("grand_total_cost", 0.0) + usage_tracker["cost"]
                        if usage_tracker.get("recompile_usages"):
                            cr_data.setdefault("initial_recompile_attempts", []).extend(usage_tracker["recompile_usages"])
                        save_json(cr_data, check_result_path)
                    except: pass
                return False
            # check_result == -1 表示成功，继续

        # 步骤2: 检查是否需要执行重新生成
        if regenerate:
            log_message("步骤2: 执行重新生成")
            if check_result_path.exists():
                try:
                    existing_data = load_json(check_result_path)
                    if 'reg_result' not in existing_data:
                        if 'org_result' in existing_data:
                            log_message("正在执行重新生成...")
                            # 执行重新生成
                            regenerate_failed_messages(service_name, service_name, usage_tracker=usage_tracker)
                        else:
                            log_message(f"check_result.json 中缺少 org_result，无法执行重新生成: {check_result_path}")
                    else:
                        log_message("check_result.json 已有 reg_result，跳过重新生成")
                except Exception as e:
                    log_message(f"处理 reg_result 时出错: {e}")
            else:
                log_message(f"check_result.json 不存在，无法检查 reg_result: {check_result_path}")
        else:
            log_message("跳过重新生成")

        # 从check_result.json中读取最终结果
        if check_result_path.exists():
            result_data = load_json(check_result_path)
            
            # 将usage_tracker的额外消耗（如重编译全文件大消耗）加到grand总账
            if usage_tracker["total_tokens"] > 0 or usage_tracker["cost"] > 0:
                result_data["grand_total_tokens"] = result_data.get("grand_total_tokens", 0) + usage_tracker["total_tokens"]
                result_data["grand_total_cost"] = result_data.get("grand_total_cost", 0.0) + usage_tracker["cost"]
                if usage_tracker.get("recompile_usages"):
                    result_data.setdefault("initial_recompile_attempts", []).extend(usage_tracker["recompile_usages"])
                save_json(result_data, check_result_path)

            if 'reg_result' in result_data:
                result = result_data['reg_result']
            elif 'org_result' in result_data:
                result = result_data['org_result']
            else:
                log_message(f"check_result.json 中没有结果数据: {check_result_path}")
                return False

            successful_count = result.get('success_number', 0)
            total_count = result.get('total_number', 0)
            if total_count > 0:
                success_rate = successful_count / total_count * 100

        log_message(f"服务 {service_name} 检查完成 - 消息ID总数: {total_count}, 成功: {successful_count}, 成功率: {success_rate:.2f}%")
        return True

    except Exception as e:
        log_message(f"处理服务 {service_name} 时发生错误: {e}")
        import traceback
        log_message(traceback.format_exc())
        return False

def main():
    parser = argparse.ArgumentParser(description='自动化检查fuzz_exec中的所有服务') 
    parser.add_argument('--services', nargs='*', help='指定要处理的服务名称，不指定则处理所有服务')
    parser.add_argument('--regenerate', action='store_true', help='是否执行重新生成，默认为False')

    args = parser.parse_args()
    specified_services = args.services

    log_message("开始自动化检查流程")

    # 获取服务列表
    all_services = get_service_names()
    if specified_services:
        services_to_process = [s for s in specified_services if s in all_services]
        if not services_to_process:
            log_message("指定的服务都不存在")
            return
        log_message(f"将检查指定的服务: {services_to_process}")
    else:
        services_to_process = all_services
        log_message(f"将检查所有 {len(services_to_process)} 个服务")

    # 处理每个服务
    success_count = 0
    for service_name in services_to_process:
        if process_service(service_name, args.regenerate):
            success_count += 1
        log_message("-" * 60)

    log_message(f"检查流程完成 - 总服务数: {len(services_to_process)}, 成功: {success_count}, 失败: {len(services_to_process) - success_count}")

    # 总结所有服务的检查结果（仅在未指定服务时执行）
    if not specified_services:
        log_message("开始总结所有服务的检查结果")
        all_results = {}
        summary = {
            "total_services": 0,
            "uncheckable_services": 0,
            "compile_failed_services": 0,
            "total_ids": 0,
            "total_org_success": 0,
            "total_reg_success": 0,
            "total_tokens": 0,
            "total_cost": 0.0
        }

        for service_name in services_to_process:
            target_service_dir = FUZZ_EXEC_DIR / service_name
            from llm_utils.utils import get_check_result_path
            check_result_path = get_check_result_path(target_service_dir)

            service_data = {
                "compile_success": False,
                "total_ids": 0,
                "org_success_ids": None,
                "reg_success_ids": None,
                "service_tokens": 0,
                "service_cost": 0.0
            }

            if check_result_path.exists():
                try:
                    data = load_json(check_result_path)
                    
                    # 如果标记为不可检查，则跳过统计
                    if data.get('checkable') is False:
                        summary["uncheckable_services"] += 1
                        continue

                    # 收集大总账 tokens (包括 initial 和 regen)
                    grand_tokens = data.get("grand_total_tokens", 0)
                    grand_cost = data.get("grand_total_cost", 0.0)
                    service_data["service_tokens"] = grand_tokens
                    service_data["service_cost"] = grand_cost
                    summary["total_tokens"] += grand_tokens
                    summary["total_cost"] += grand_cost

                    service_data["compile_success"] = data.get("compile_success", False)

                    if not service_data["compile_success"]:
                        summary["compile_failed_services"] += 1
                    else:
                        # 编译成功，提取结果
                        if "org_result" in data:
                            org = data["org_result"]
                            service_data["total_ids"] = org.get("total_number", 0)
                            service_data["org_success_ids"] = org.get("success_number", 0)
                            summary["total_ids"] += service_data["total_ids"]
                            summary["total_org_success"] += service_data["org_success_ids"]
                        if "reg_result" in data:
                            reg = data["reg_result"]
                            service_data["reg_success_ids"] = reg.get("success_number", 0)
                            summary["total_reg_success"] += service_data["reg_success_ids"]
                            
                            # 累加 reg_result 中独有的 token（如果不包含在 grand 里）
                            reg_tokens = reg.get("total_tokens", 0)
                            reg_cost = reg.get("total_cost", 0.0)
                            # 由于 message_checker 在遇到没有 failed id 的时候直接合并 grand，
                            # 如果此时有 failed，它并不会把 reg 的写入 grand。为了安全稳妥，把这两部分都加上：
                            # 实际上更好的做法是 message_checker 直接写入全局，这里我们简单合并
                            # (我们刚才在 message_checker 里如果进了循环就没更新 grand，所以在检查脚本里补漏)
                            if reg_tokens > 0 and grand_tokens == 0:
                                service_data["service_tokens"] += reg_tokens
                                service_data["service_cost"] += reg_cost
                                summary["total_tokens"] += reg_tokens
                                summary["total_cost"] += reg_cost
                except Exception as e:
                    log_message(f"读取 {check_result_path} 出错: {e}")
            else:
                summary["compile_failed_services"] += 1  # 如果没有 check_result.json，假设编译失败

            summary["total_services"] += 1
            all_results[service_name] = service_data

        # 获取策略后缀
        strategy_suffix = ""
        if services_to_process:
            first_service_dir = FUZZ_EXEC_DIR / services_to_process[0]
            records_file = first_service_dir / "functions" / "record.json"
            if records_file.exists():
                try:
                    records_data = load_json(records_file)
                    strategy = records_data.get("strategy", "").strip()
                    if strategy:
                        if strategy == "model_test":
                            m_id = records_data.get("model_id")
                            if m_id:
                                strategy = f"model_test_{m_id}"
                        strategy_suffix = f"_{strategy}"
                except Exception:
                    pass
                
        # 保存总结结果
        all_check_result_path = Path(__file__).parent / f"all_check_result{strategy_suffix}.json"
        save_json({"services": all_results, "summary": summary}, all_check_result_path)
        log_message(f"总结结果已保存到 {all_check_result_path}")

if __name__ == "__main__":
    main()