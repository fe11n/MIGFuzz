#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
llm_message_checker/message_checker.py

可达性检测模块，提供check_message_ids函数用于检查消息ID的可达性。
"""

import os
import json
import subprocess
import tempfile
import sys
from pathlib import Path
from typing import Dict, List, Tuple
import shutil

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from llm_utils.utils import FUZZ_EXEC_DIR, SERVICES_DIR, log_message
from llm_message_checker.update_generate_code import update_generate_code

def collect_message_ids(service_name: str) -> Tuple[List[int], List[str]]:
    """收集服务对应的 message_id 列表及可用的 JSON 元数据文件。"""
    service_dir = SERVICES_DIR / service_name
    json_file = service_dir / 'mig_functions.json'

    message_ids = set()
    candidates: List[str] = []

    if os.path.exists(json_file):
        candidates.append(str(json_file))
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for subsys in data.get('subsystems', []):
                for func in subsys.get('functions', []):
                    msgid = func.get('message_id')
                    if msgid is not None:
                        message_ids.add(msgid)

    sorted_ids = sorted(message_ids)
    return sorted_ids, candidates

def create_lldb_commands_file(python_script_path):
    commands_file = tempfile.NamedTemporaryFile(mode='w', suffix='.lldb', delete=False)
    commands_file.write(f'command script import "{python_script_path}"\n')
    commands_file.write('start_analysis\n')
    commands_file.write('quit\n')
    commands_file.close()
    return commands_file.name

def compile_checker(service_exec_name, auto_update: bool = True, usage_tracker: dict = None, out_info: dict = None):
    """编译checker程序"""
    checker_exec_dir = project_root / 'llm_message_checker' / 'checker_exec'
    makefile = checker_exec_dir / 'Makefile'
    if not makefile.exists():
        raise FileNotFoundError(f"Makefile not found: {makefile}")

    # 先执行make clean
    clean_command = ['make', '-C', str(checker_exec_dir), 'clean']
    clean_result = subprocess.run(clean_command, capture_output=True, text=True)

    # 然后执行make
    command = ['make', '-C', str(checker_exec_dir)]
    # 使用新的目录命名：service_name 或 service_name_{index}
    target_service_dir = FUZZ_EXEC_DIR / service_exec_name
    # 从 checker_exec_dir 角度计算相对路径
    relative_service_dir = os.path.relpath(target_service_dir, start=checker_exec_dir)
    command.append(f'TARGET_SERVICE_DIR={relative_service_dir}')

    result = subprocess.run(command, capture_output=True, text=True)
    # 写入 compile_success 到 check_result
    from llm_utils.utils import load_json, save_json, get_check_result_path
    check_result_path = get_check_result_path(target_service_dir)
    existing_data = {}
    if check_result_path.exists():
        try:
            existing_data = load_json(check_result_path)
        except Exception:
            pass
    if result.returncode != 0:
        log_message(f"编译失败: {result.stderr}")
        if out_info is not None:
            out_info['first_stderr'] = result.stderr
        
        # 记录编译失败状态，以便 batch_update_compile_failed_services 能识别
        existing_data['compile_success'] = False
        existing_data['compile_fail_reason'] = result.stderr
        save_json(existing_data, check_result_path)

        if auto_update:
            # 编译失败，尝试更新代码并重新编译
            from llm_message_checker.update_compile_code import update_compile_code_for_service
            usages = update_compile_code_for_service(service_name=service_exec_name, use_english_prompts=False)
            if usages and usage_tracker is not None:
                # 若存在专门的编译费率统计池，则合并到数组中
                if 'recompile_usages' in usage_tracker:
                    usage_tracker['recompile_usages'].append(usages)
                else: # fallback for generic tracking
                    usage_tracker['total_tokens'] = usage_tracker.get('total_tokens', 0) + usages.get('total_tokens', 0)
                    usage_tracker['cost'] = usage_tracker.get('cost', 0.0) + usages.get('cost', 0.0)
            
            # 重新执行make clean
            clean_result = subprocess.run(clean_command, capture_output=True, text=True)
            
            # 重新执行make
            result = subprocess.run(command, capture_output=True, text=True)
            
            # 再次检查结果
            if result.returncode != 0:
                existing_data['compile_success'] = False
                existing_data['compile_fail_reason'] = result.stderr
                save_json(existing_data, check_result_path)
                log_message(f"重新编译失败: {result.stderr}")
                return 0  # 失败
            else:
                existing_data['compile_success'] = True
                if 'compile_fail_reason' in existing_data:
                    del existing_data['compile_fail_reason']
                save_json(existing_data, check_result_path)
                log_message(f"重新编译成功")
                return 1  # 成功
        else:
            return 0  # 失败
    else:
        existing_data['compile_success'] = True
        if 'compile_fail_reason' in existing_data:
            del existing_data['compile_fail_reason']
        save_json(existing_data, check_result_path)
        log_message(f"编译成功")
        return 1  # 成功

def find_function_info(message_id: int, json_candidates: List[str]):
    """在提供的JSON文件中查找给定message_id对应的函数信息。"""
    for candidate in json_candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            with open(candidate, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as exc:
            continue

        for subsys in data.get('subsystems', []):
            for func in subsys.get('functions', []):
                if func.get('message_id') == message_id:
                    func_a = func.get('name')
                    func_b = func.get('handle_function_name')
                    return func_a, func_b, candidate

    return None, None, None

def verify_message_id(message_id: int, json_files: List[str]) -> Tuple[str, str, str]:
    """验证 message_id 是否可定位到有效的生成与处理函数。"""
    func_a, func_b, json_path = find_function_info(message_id, json_files)
    if not func_a or not func_b:
        raise ValueError(f"Function info not found for message ID {message_id}")
    return func_a, func_b, json_path

def run_lldb_for_message_ids(message_ids: List[int], service_exec_name: str, json_files: List[str], *, log_mode: str = 'write') -> List[Dict[str, object]]:
    """对给定的 message_id 列表执行 LLDB 测试，并返回测试结果。"""
    results: List[Dict[str, object]] = []
    debug_logs: Dict[str, List[str]] = {}
    write_mode = 'a' if log_mode == 'append' else 'w'

    checker_exec_dir = project_root / 'llm_message_checker' / 'checker_exec'
    target = checker_exec_dir / 'checker'
    python_script_path = project_root / 'llm_message_checker' / 'failtest_forlldb.py'

    for message_id in message_ids:
        try:
            func_a, func_b, json_file = verify_message_id(message_id, json_files)
            target_service_dir = FUZZ_EXEC_DIR / service_exec_name
            folder = target_service_dir
        except ValueError as exc:
            results.append({'id': message_id, 'status': 'failed', 'reason': str(exc)})
            continue

        config_path = project_root / 'llm_message_checker' / 'failtest_forlldb.config'
        with open(config_path, 'w', encoding='utf-8') as cfg:
            cfg.write(f"{func_a} {func_b} {message_id} {service_exec_name}\n")

        lldb_commands_file = create_lldb_commands_file(python_script_path)

        try:
            run_result = subprocess.run(
                ['sudo', 'lldb', '-s', lldb_commands_file, '--', str(target), '-i', str(message_id), '-s', service_exec_name],
                capture_output=True,
                text=True,
                cwd=checker_exec_dir,
                timeout=30  # 30秒超时
            )
            output = run_result.stdout + run_result.stderr

            result_json_path = project_root / 'llm_message_checker' / 'result.json'
            try:
                with open(result_json_path, 'r', encoding='utf-8') as rf:
                    result_data = json.load(rf)
            except Exception as exc:
                result_data = {'success': False, 'error': str(exc)}

            success = result_data.get('success', False)
            trace = result_data.get('trace') if not success else None
            status = 'success' if success else 'failed'

            if success and folder:
                fail_log_dir = folder / 'check_fail_log'
                fail_trace_path = fail_log_dir / f"failtrace_{message_id}.txt"
                if fail_trace_path.exists():
                    fail_trace_path.unlink()

            record: Dict[str, object] = {'id': message_id, 'status': status, 'output': output}
            if not success and trace:
                record['trace'] = trace
            results.append(record)


            if folder:
                if str(folder) not in debug_logs:
                    debug_logs[str(folder)] = []
                log_entry = [f"Message ID {message_id}:", output]
                if not success and trace:
                    log_entry.extend(trace)
                debug_logs[str(folder)].append("\n".join(log_entry) + "\n")

                if not success and trace:
                    fail_log_dir = folder / 'check_fail_log'
                    fail_log_dir.mkdir(exist_ok=True)
                    fail_trace_path = fail_log_dir / f"failtrace_{message_id}.txt"
                    with open(fail_trace_path, 'w', encoding='utf-8') as fail_file:
                        fail_file.write("\n".join(trace))
        except subprocess.TimeoutExpired:
            results.append({'id': message_id, 'status': 'timeout', 'output': 'Timeout after 60 seconds'})
        except Exception as exc:
            results.append({'id': message_id, 'status': 'failed', 'reason': str(exc)})
        finally:
            os.unlink(lldb_commands_file)

    for folder, logs in debug_logs.items():
        debug_path = Path(folder) / 'check_debug.txt'
        with open(debug_path, write_mode, encoding='utf-8') as dbg_file:
            dbg_file.write('\n'.join(logs))
            if write_mode == 'a':
                dbg_file.write('\n')

    return results

def regenerate_failed_messages(service_name: str, service_exec_name: str, max_regeneration_attempts: int = 4, usage_tracker: dict = None) -> List[Dict[str, object]]:
    """对失败的消息进行重新生成

    Args:
        service_name: 服务名称
        service_exec_name: 执行目录名称
        max_regeneration_attempts: 最大重新生成尝试次数
        usage_tracker: 供外部捕获编译花销的字典

    Returns:
        更新后的测试结果列表
    """
    # 读取现有的 check_result.json 获取 org_result
    from llm_utils.utils import load_json, save_json, get_check_result_path
    target_service_dir = FUZZ_EXEC_DIR / service_exec_name
    check_result_path = get_check_result_path(target_service_dir)

    existing_data = {}
    if check_result_path.exists():
        try:
            existing_data = load_json(check_result_path)
        except Exception as e:
            log_message(f"加载 check_result.json 失败: {e}")
            return []

    if 'org_result' not in existing_data:
        log_message(f"check_result.json 中缺少 org_result: {check_result_path}")
        return []

    org_result = existing_data['org_result']
    failed_ids = org_result.get('failed_ids', [])
    successful_ids = org_result.get('successful_ids', [])

    # 初始化 reg_result
    reg_result = {
        'successful_ids': successful_ids.copy(),  # 从org_result复制成功的
        'failed_ids': failed_ids.copy(),  # 初始时所有失败的
        'success_number': len(successful_ids),
        'failed_number': len(failed_ids),
        'total_number': len(successful_ids) + len(failed_ids),
        'total_tokens': 0,
        'total_cost': 0.0,
        'message_costs': {},
        'regenerate_total_tokens': 0,
        'regenerate_total_cost': 0.0,
        'recompile_total_tokens': 0,
        'recompile_total_cost': 0.0
    }
    existing_data['reg_result'] = reg_result

    # 重建 results 列表
    results = []
    for msg_id in successful_ids:
        results.append({'id': msg_id, 'status': 'success'})
    for msg_id in failed_ids:
        results.append({'id': msg_id, 'status': 'failed'})

    # 收集消息ID和JSON文件
    all_message_ids, json_files = collect_message_ids(service_name)

    # 从 fail_log 目录动态获取初始的 failed_ids
    fail_log_dir = target_service_dir / "check_fail_log"
    initial_failed_ids = []
    if fail_log_dir.exists():
        for f in fail_log_dir.glob("failtrace_*.txt"):
            match = f.name.split("failtrace_")[1].split(".txt")[0]
            if match.isdigit():
                initial_failed_ids.append(int(match))
    remaining_failed_ids = sorted(initial_failed_ids)

    if not remaining_failed_ids:
        # 仍然写入 reg_result
        records_path = target_service_dir / "functions" / "record.json"
        grand_tokens = reg_result.get('total_tokens', 0)
        grand_cost = reg_result.get('total_cost', 0.0)
        if records_path.exists():
            try:
                records = load_json(records_path)
                grand_tokens += records.get('total_token', 0)
                grand_cost += records.get('total_cost', 0.0)
            except: pass
        existing_data['grand_total_tokens'] = grand_tokens
        existing_data['grand_total_cost'] = grand_cost
        
        save_json(existing_data, check_result_path)
        return results

    # 预先为当前还没成功的 ID 生成历史记录框架
    for mid in remaining_failed_ids:
        functions_dir = target_service_dir / "functions"
        functions_dir.mkdir(exist_ok=True)
        history_path = functions_dir / f"history_{mid}.json"
        
        # 只在首次执行 regenerate 前创建历史框架，并读取最原始 failtrace
        if not history_path.exists():
            initial_faillog = ""
            ftl = target_service_dir / "check_fail_log" / f"failtrace_{mid}.txt"
            if ftl.exists():
                try:
                    with open(ftl, 'r', encoding='utf-8') as f:
                        initial_faillog = f.read()
                except: pass
            
            save_json({"initial_faillog": initial_faillog, "history": []}, history_path)

    for attempt in range(1, max_regeneration_attempts + 1):
        # 用于存储本轮测试结果
        current_attempt_results = {}
        attempt_tokens = 0
        attempt_cost = 0.0

        for message_id in list(remaining_failed_ids):
            str_id = str(message_id)
            if str_id not in reg_result['message_costs']:
                reg_result['message_costs'][str_id] = {
                    'regenerate_attempts': [],
                    'recompile_attempts': []
                }
            mc_record = reg_result['message_costs'][str_id]

            # 备份当前文件状态
            generate_cc_path = target_service_dir / "generate_message.cc"
            functions_dir = target_service_dir / "functions"
            functions_json_path = functions_dir / f"functions_{message_id}.json"
            part1_json_path = functions_dir / "part1.json"
            
            backup_cc_content = None
            backup_functions_json_content = None
            backup_part1_json_content = None
            
            if generate_cc_path.exists():
                try:
                    with open(generate_cc_path, 'r', encoding='utf-8') as f:
                        backup_cc_content = f.read()
                except Exception as e:
                    log_message(f"备份 generate_message.cc 失败: {e}")

            if functions_json_path.exists():
                try:
                    with open(functions_json_path, 'r', encoding='utf-8') as f:
                        backup_functions_json_content = f.read()
                except Exception as e:
                    log_message(f"备份 functions_{message_id}.json 失败: {e}")

            if part1_json_path.exists():
                try:
                    with open(part1_json_path, 'r', encoding='utf-8') as f:
                        backup_part1_json_content = f.read()
                except Exception as e:
                    log_message(f"备份 part1.json 失败: {e}")

            try:
                log_message(f"Regenerate attempt {attempt} - ID {message_id}")
                usage = update_generate_code(
                    service_name=service_name,
                    message_id=message_id,
                    use_english_prompts=True
                )
                msg_tokens = 0
                msg_cost = 0.0
                if isinstance(usage, dict):
                    msg_tokens = usage.get("total_tokens", 0)
                    msg_cost = usage.get("cost", 0.0)
                    attempt_tokens += msg_tokens
                    attempt_cost += msg_cost

                # 记录单独这一个ID的再生成花费
                mc_record['regenerate_attempts'].append({'tokens': msg_tokens, 'cost': msg_cost})
                
                # 累加到整体的regenerate分类花费
                reg_result['regenerate_total_tokens'] += msg_tokens
                reg_result['regenerate_total_cost'] += msg_cost

                # [修复] 第一时间记录到总账
                reg_result['total_tokens'] += msg_tokens
                reg_result['total_cost'] += msg_cost
                save_json(existing_data, check_result_path)

            except Exception as e:
                log_message(f"更新生成代码失败，消息ID {message_id}: {e}")
                current_attempt_results[message_id] = 'failed'
                continue

            # 获取刚才生成的代码内容，作为历史记录
            generated_response = {}
            if functions_json_path.exists():
                try:
                    f_data = load_json(functions_json_path)
                    generated_response = f_data.get("message_functions", {}).get(str_id, {})
                except: pass

            local_usage_tracker = {'recompile_usages': []}
            compile_out_info = {}
            compile_result = compile_checker(service_exec_name, usage_tracker=local_usage_tracker, out_info=compile_out_info)
            
            # 统计重编译的花销
            recomp_t = 0
            recomp_c = 0.0
            for ru in local_usage_tracker.get('recompile_usages', []):
                rt = ru.get("total_tokens", 0)
                rc = ru.get("cost", 0.0)
                mc_record['recompile_attempts'].append({'tokens': rt, 'cost': rc})
                recomp_t += rt
                recomp_c += rc
                
            if recomp_t > 0 or recomp_c > 0:
                reg_result['recompile_total_tokens'] += recomp_t
                reg_result['recompile_total_cost'] += recomp_c
                reg_result['total_tokens'] += recomp_t
                reg_result['total_cost'] += recomp_c
                
                # 如果是外部传入的 usage_tracker 也要累加
                if usage_tracker is not None:
                    usage_tracker['total_tokens'] = usage_tracker.get('total_tokens', 0) + recomp_t
                    usage_tracker['cost'] = usage_tracker.get('cost', 0.0) + recomp_c

                save_json(existing_data, check_result_path)

            if compile_result == 0:
                log_message(f"编译依然失败，正在还原文件，此ID将在本轮不进行lldb测试 ID {message_id}")
                # 记录这一轮纯纯由于编译失败导致的报错进入历史
                h_path = functions_dir / f"history_{message_id}.json"
                if h_path.exists():
                    try:
                        h_data = load_json(h_path)
                        h_data.setdefault("history", []).append({
                            "attempt": attempt,
                            "response": generated_response,
                            "result_type": "compile_error",
                            "result_content": compile_out_info.get("first_stderr", "Unknown compile error")
                        })
                        save_json(h_data, h_path)
                    except: pass

                # 还原文件
                if backup_cc_content is not None:
                    try:
                        with open(generate_cc_path, 'w', encoding='utf-8') as f:
                            f.write(backup_cc_content)
                    except Exception as e:
                        log_message(f"还原 generate_message.cc 失败: {e}")
                
                if backup_functions_json_content is not None:
                    try:
                        with open(functions_json_path, 'w', encoding='utf-8') as f:
                            f.write(backup_functions_json_content)
                    except Exception as e:
                        log_message(f"还原 functions_{message_id}.json 失败: {e}")
                elif functions_json_path.exists():
                    try:
                        functions_json_path.unlink()
                    except Exception as e:
                        log_message(f"删除新创建的 functions_{message_id}.json 失败: {e}")

                if backup_part1_json_content is not None:
                    try:
                        with open(part1_json_path, 'w', encoding='utf-8') as f:
                            f.write(backup_part1_json_content)
                    except Exception as e:
                        log_message(f"还原 part1.json 失败: {e}")
                
                current_attempt_results[message_id] = 'failed'
                continue

            # 编译成功，尝试同步回策略缓存
            try:
                # 读取策略配置
                records_path = functions_dir / "record.json"
                strategy = None
                if records_path.exists():
                    try:
                        cfg_data = load_json(records_path)
                        strategy = cfg_data.get("strategy")
                    except Exception:
                        pass
                
                if strategy:
                    # 获取mig_services中的缓存目录
                    # SERVICES_DIR import from llm_utils.utils
                    mig_functions_dir = SERVICES_DIR / service_name / f"functions_{strategy}"
                    if not mig_functions_dir.exists():
                        # 尝试 other_mig_services
                        other_service_dir = SERVICES_DIR.parent / "other_mig_services" / service_name
                        if other_service_dir.exists():
                            mig_functions_dir = other_service_dir / f"functions_{strategy}"
                    
                    if mig_functions_dir.exists():
                        # 同步 functions_{message_id}.json
                        if functions_json_path.exists():
                            shutil.copy(functions_json_path, mig_functions_dir / functions_json_path.name)
                            log_message(f"已同步消息ID {message_id} 的函数代码到策略缓存: {strategy}")
                        
                        # 同步 part1.json (如果存在)
                        if part1_json_path.exists():
                            shutil.copy(part1_json_path, mig_functions_dir / "part1.json")
            except Exception as e:
                log_message(f"同步缓存失败: {e}")

            retest_records = run_lldb_for_message_ids([message_id], service_exec_name, json_files, log_mode='append')
            if not retest_records:
                # 没有结果视为失败
                current_attempt_results[message_id] = 'failed'
                continue

            retest_record = retest_records[0]
            status_text = retest_record.get('status', 'failed')
            output_text = retest_record.get('output', '')
            trace = retest_record.get('trace') if status_text != 'success' else None

            # 超时视为失败
            if status_text == 'timeout':
                status_text = 'failed'
                
            # 记录这一轮纯纯由lldb测试导致的 failtrace / 输出日志 进入历史
            h_path = functions_dir / f"history_{message_id}.json"
            if h_path.exists():
                try:
                    h_data = load_json(h_path)
                    res_content = "\n".join(trace) if trace else output_text
                    h_data.setdefault("history", []).append({
                        "attempt": attempt,
                        "response": generated_response,
                        "result_type": getattr(status_text, "lower", lambda: str(status_text))(),
                        "result_content": res_content
                    })
                    save_json(h_data, h_path)
                except: pass

            # 保存本次测试结果
            current_attempt_results[message_id] = status_text

            log_message(f"Regenerated message ID {message_id}: {status_text}")

            # 更新 results 列表（添加或更新记录）
            existing_idx = next((i for i, r in enumerate(results) if r['id'] == message_id), None)
            if existing_idx is not None:
                results[existing_idx] = retest_record
            else:
                results.append(retest_record)

            # 增量更新 reg_result
            if status_text == 'success':
                if message_id not in reg_result['successful_ids']:
                    reg_result['successful_ids'].append(message_id)
                if message_id in reg_result['failed_ids']:
                    reg_result['failed_ids'].remove(message_id)
            else:
                if message_id not in reg_result['failed_ids']:
                    reg_result['failed_ids'].append(message_id)

            # 重新计算统计值
            reg_result['success_number'] = len(reg_result['successful_ids'])
            reg_result['failed_number'] = len(reg_result['failed_ids'])
            reg_result['total_number'] = reg_result['success_number'] + reg_result['failed_number']

            # 增量保存
            save_json(existing_data, check_result_path)

        # 根据本轮结果更新 remaining_failed_ids
        remaining_failed_ids = [
            msg_id for msg_id in remaining_failed_ids 
            if current_attempt_results.get(msg_id, 'failed') == 'failed'
        ]
        
        if not remaining_failed_ids:
            break

    records_path = target_service_dir / "functions" / "record.json"
    grand_tokens = reg_result.get('total_tokens', 0)
    grand_cost = reg_result.get('total_cost', 0.0)
    if records_path.exists():
        try:
            records = load_json(records_path)
            grand_tokens += records.get('total_token', 0)
            grand_cost += records.get('total_cost', 0.0)
        except: pass
    existing_data['grand_total_tokens'] = grand_tokens
    existing_data['grand_total_cost'] = grand_cost
    
    save_json(existing_data, check_result_path)
    return results

def check_message_ids(service_name: str, service_exec_name: str, recompile: bool = True, usage_tracker: dict = None) -> int:
    """检查消息ID的可达性

    Args:
        service_name: 服务名称
        service_exec_name: 执行目录名称
        recompile: 是否重新编译checker，默认为True
        usage_tracker: 供外部捕获编译花销的字典

    Returns: 
        int: -1表示成功，0表示失败
    """
    # 收集消息ID
    all_message_ids, json_files = collect_message_ids(service_name)
    if not all_message_ids:
        return 0

    target_service_dir = FUZZ_EXEC_DIR / service_exec_name
    from llm_utils.utils import get_check_result_path
    check_result_path = get_check_result_path(target_service_dir)

    # 加载现有的 check_result.json
    from llm_utils.utils import load_json, save_json
    existing_data = {}
    if check_result_path.exists():
        try:
            existing_data = load_json(check_result_path)
        except Exception:
            existing_data = {}

    org_result = existing_data.get('org_result', {})
    processed_ids = set(org_result.get('successful_ids', []) + org_result.get('failed_ids', []))

    # 找出未处理的ID
    unprocessed_ids = [mid for mid in all_message_ids if mid not in processed_ids]
    if not unprocessed_ids:
        log_message("All message IDs have been processed.")
        return -1

    # 编译checker
    if recompile:
        compile_result = compile_checker(service_exec_name, usage_tracker=usage_tracker)
        if compile_result == 0:
            return 0
        existing_data['compile_success'] = True
    else:
        existing_data['compile_success'] = True

    # 初始化 org_result 如果不存在
    # 确保 org_result 有必要的键
    if 'successful_ids' not in org_result:
        org_result['successful_ids'] = []
    if 'failed_ids' not in org_result:
        org_result['failed_ids'] = []

    existing_data['org_result'] = org_result

    # 处理每个未处理的ID
    for message_id in unprocessed_ids:
        log_message(f"Checking message ID {message_id}...")
        results = run_lldb_for_message_ids([message_id], service_exec_name, json_files, log_mode='append')
        if results:
            result = results[0]
            status = result.get('status')
            if status == 'success':
                org_result['successful_ids'].append(message_id)
            elif status in ('failed', 'timeout'):
                org_result['failed_ids'].append(message_id)
                if status == 'timeout':
                    log_message(f"Message ID {message_id} timed out")
            log_message(f"Processed message ID {message_id}: {status}")
            # 保存到文件
            save_json(existing_data, check_result_path)
            
    # 重新计算统计值
    org_result['success_number'] = len(org_result['successful_ids'])
    org_result['failed_number'] = len(org_result['failed_ids'])
    org_result['total_number'] = len(all_message_ids)
    
    save_json(existing_data, check_result_path)

    return -1