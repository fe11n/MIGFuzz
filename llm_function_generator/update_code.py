# -*- coding: UTF-8 -*-
"""基于语义约束重写消息生成代码。"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from llm_utils.config import config
from llm_utils.utils import load_json, save_json, log_message, PATTERN_DIR, SERVICES_DIR, FUZZ_EXEC_DIR


def _escape_braces(text: str) -> str:
    """在format模板中安全注入包含花括号的文本。"""
    return text.replace("{", "{{").replace("}", "}}")


def _load_service_messages(service_dir: Path) -> List[Dict[str, Any]]:
    """收集服务中每个消息的处理函数及其参数列表。"""
    mig_path = service_dir / "mig_functions.json"
    if not mig_path.exists():
        raise FileNotFoundError(f"未找到 {mig_path}")

    service_data = load_json(mig_path)
    messages: List[Dict[str, Any]] = []

    for subsystem in service_data.get("subsystems", []):
        for function in subsystem.get("functions", []):
            msg_id = function.get("message_id")
            handle_code = function.get("handle_function_pseudocode", "")
            if msg_id is None or not handle_code:
                continue
            message_entry = {
                "message_id": msg_id,
                "handle_function_name": function.get("handle_function_name", ""),
                "handle_function_pseudocode": handle_code
            }
            messages.append(message_entry)
    return messages


def _load_message_function_map(service_dir: Path) -> Dict[str, str]:
    """构建消息ID到处理函数名称的映射。"""
    mapping: Dict[str, str] = {}
    mig_path = service_dir / "mig_functions.json"
    if not mig_path.exists():
        return mapping

    try:
        service_data = load_json(mig_path)
    except Exception as exc:
        log_message(f"读取 {mig_path} 失败：{exc}")
        return mapping

    for subsystem in service_data.get("subsystems", []):
        for function in subsystem.get("functions", []):
            msg_id = function.get("message_id")
            if msg_id is None:
                continue
            function_name = function.get("handle_function_name") or function.get("function_name") or ""
            if not function_name:
                continue
            mapping[str(msg_id)] = function_name
    return mapping


def regenerate_message_with_semantics(
    service_name: str,
    message_id: str,
    use_english_prompts: bool = False,
) -> bool:
    """根据语义约束逐参数对话并重写指定消息的生成函数，按步骤更新到 updated_functions/{id}.json 缓存。

    改造点：
    1) 提供 functions_{id} 的五个部分（generate_header/descriptor/body/trailer/message）及同目录 part1.json 给LLM，并说明各自作用。
    2) 对该消息的每个参数逐一与LLM对话：
       - 确认该参数由原代码哪些位置生成；
       - 判断是否有工具函数可以生成满足约束的值；
       - 在最小修改前提下更新相应生成代码，保证可直接运行；
       - 立即写回缓存 updated_functions/{id}.json。
    3) 约束来源：parameter_semantics.json 与 parameter_extra_information.json；
       extra_description 需按参数名与序号，从 parameter_extra_information.json 对应条目的 extra_descriptions[index].information 取值。
    """
    log_message(f"--- 开始重写服务 {service_name} 消息ID {message_id} 的生成代码（逐参数） ---")
    service_dir = SERVICES_DIR / service_name
    exec_service_dir = FUZZ_EXEC_DIR / service_name
    exec_service_dir.mkdir(parents=True, exist_ok=True)
    if not service_dir.exists():
        log_message(f"错误：服务目录 {service_dir} 不存在")
        return False

    # 创建 updated_functions 文件夹并复制 functions 的内容
    functions_dir = service_dir / "functions"
    updated_functions_dir = exec_service_dir / "updated_functions"
    if not functions_dir.exists():
        log_message(f"错误：functions 文件夹不存在 {functions_dir}")
        return False
    if updated_functions_dir.exists():
        shutil.rmtree(updated_functions_dir)
    shutil.copytree(functions_dir, updated_functions_dir)
    log_message(f"已复制 functions 到 updated_functions: {updated_functions_dir}")

    # 载入语义文件
    semantics_path = service_dir / "parameter_semantics.json"
    if not semantics_path.exists():
        log_message(f"错误：未找到语义约束文件 {semantics_path}")
        return False
    try:
        semantics_data = load_json(semantics_path)
    except Exception as exc:
        log_message(f"读取语义约束文件失败：{exc}")
        return False

    # 载入额外信息文件
    extra_info_path = service_dir / "parameter_extra_information.json"
    try:
        extra_info_data = load_json(extra_info_path) if extra_info_path.exists() else {"parameters": []}
    except Exception as exc:
        log_message(f"读取额外信息文件失败：{exc}")
        extra_info_data = {"parameters": []}

    # 载入工具说明
    tools_path = Path(__file__).parent.parent / "fuzz_helpers" / "tool_lib.cc"
    if not tools_path.exists():
        log_message(f"错误：工具函数描述文件 {tools_path} 不存在")
        return False
    tools_description = tools_path.read_text(encoding="utf-8")

    # 载入 functions_{id}.json 中的五个部分 + part1.json
    def _load_functions_parts(updated_functions_dir: Path, msg_id: str) -> Optional[Dict[str, Any]]:
        target_file = updated_functions_dir / f"functions_{msg_id}.json"
        if not target_file.exists():
            log_message(f"错误：未找到 {target_file}")
            return None
        try:
            data = load_json(target_file)
        except Exception as exc:
            log_message(f"读取 {target_file} 失败：{exc}")
            return None
        message_funcs = data.get("message_functions", {})
        mf = message_funcs.get(str(msg_id)) or message_funcs.get(int(msg_id))
        if not mf:
            log_message(f"错误：{target_file} 缺少 message_functions[{msg_id}] 条目")
            return None
        part1_inline = ""
        # 从同目录 part1.json 读取
        part1_file = updated_functions_dir / "part1.json"
        try:
            part1_json = load_json(part1_file)
            part1_inline = part1_json.get("part1_content", "")
        except Exception:
            part1_inline = ""
        return {
            "part1_content": part1_inline,
            "generate_header": mf.get("generate_header", ""),
            "generate_descriptor": mf.get("generate_descriptor", ""),
            "generate_body": mf.get("generate_body", ""),
            "generate_trailer": mf.get("generate_trailer", ""),
            "generate_message": mf.get("generate_message", ""),
            "_raw_file": target_file,
            "_raw_data": data,
        }

    def _save_functions_parts(updated_functions_dir: Path, msg_id: str, updates: Dict[str, str], base_snapshot: Optional[Dict[str, Any]] = None) -> bool:
        target_file = updated_functions_dir / f"functions_{msg_id}.json"
        try:
            data = load_json(target_file)
        except Exception as exc:
            log_message(f"读取 {target_file} 失败：{exc}")
            return False
        message_functions = data.setdefault("message_functions", {})
        entry = message_functions.get(str(msg_id)) or message_functions.get(int(msg_id))
        if not entry:
            entry = {}
            message_functions[str(msg_id)] = entry
        # 允许更新五个生成函数；若返回包含 part1_content 也一并更新顶层
        for key in ("generate_header", "generate_descriptor", "generate_body", "generate_trailer", "generate_message"):
            if updates.get(key):
                entry[key] = updates[key]
        if updates.get("part1_content") is not None:
            data["part1_content"] = updates.get("part1_content")
            # 同时更新同文件夹下的 part1.json 文件
            part1_file = updated_functions_dir / "part1.json"
            part1_data = {"part1_content": updates.get("part1_content")}
            if not save_json(part1_data, part1_file):
                log_message(f"警告：更新 {part1_file} 失败")
        # 写回
        if save_json(data, target_file):
            log_message(f"已更新缓存文件 {target_file}")
            return True
        log_message(f"错误：写回缓存文件失败 {target_file}")
        return False

    # 过滤该消息相关的参数，并构建逐参数数据（含 extra_information 对齐）
    def _build_param_list_for_message(sem_data: Dict[str, Any], extra_info: Dict[str, Any], msg_id: str) -> List[Dict[str, Any]]:
        params: List[Dict[str, Any]] = []
        extra_map: Dict[str, List[Dict[str, Any]]] = {}
        for p in extra_info.get("parameters", []) or []:
            name = (p.get("parameter_name") or "").strip()
            if not name:
                continue
            lst = []
            # 为 extra_descriptions 补序号
            for idx, ed in enumerate(p.get("extra_descriptions", []) or [], start=1):
                lst.append({
                    "index": idx,
                    "content": ed.get("content", ""),
                    "information": ed.get("information", ""),
                    "concerned_functions": ed.get("concerned_functions", []),
                })
            extra_map[name] = lst

        target = str(msg_id)
        for item in sem_data.get("parameter_types", []) or []:
            # 判断是否属于该消息
            selected_index: Optional[int] = None
            for mapping in item.get("message_ids", []) or []:
                if isinstance(mapping, dict):
                    for k, v in mapping.items():
                        if str(k) == target:
                            try:
                                selected_index = int(v)
                            except Exception:
                                selected_index = None
                            break
                elif str(mapping) == target:
                    selected_index = 0
                if selected_index is not None:
                    break
            if selected_index is None:
                continue

            # 仅保留与该消息ID相关的 format/semantic 约束
            def _filter_cons(lst: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
                out: List[Dict[str, Any]] = []
                for entry in lst or []:
                    ids = [str(x) for x in (entry.get("ids") or [])]
                    if not ids or target in ids:
                        out.append({
                            "index": entry.get("index"),
                            "content": entry.get("content"),
                        })
                return out

            fmt_cons = _filter_cons(item.get("format_constraints") or [])
            sem_cons = _filter_cons(item.get("semantic_constraints") or [])

            # extra_description 的信息字段来源于 extra_info
            name = item.get("parameter_name", "")
            extras_from_sem = [e for e in (item.get("extra_description") or []) if (not e.get("ids") or target in [str(x) for x in (e.get("ids") or [])])]
            extra_list: List[Dict[str, Any]] = []
            if extras_from_sem:
                for e in extras_from_sem:
                    try:
                        idx = int(e.get("index"))
                    except Exception:
                        idx = None
                    info = ""
                    if idx is not None:
                        for ei in extra_map.get(name, []):
                            if int(ei.get("index", 0)) == idx:
                                info = ei.get("information", "")
                                break
                    if info.strip():  # 只有当information不为空时才添加
                        extra_list.append({
                            "index": idx,
                            "content": e.get("content", ""),
                            "information": info,
                        })
            params.append({
                "index": selected_index,
                "name": name,
                "role": item.get("parameter_role", ""),
                "data_type": item.get("data_type", ""),
                "format_constraints": fmt_cons,
                "semantic_constraints": sem_cons,
                "extra_descriptions": extra_list,
            })
        # 按参数位置排序，确保逐参数顺序稳定
        params.sort(key=lambda x: (x.get("index", 0), x.get("name", "")))
        return params

    # 调用模型：概览上下文
    funcs_snapshot = _load_functions_parts(updated_functions_dir, str(message_id))
    if not funcs_snapshot:
        return False

    # 选择统一提示词
    if use_english_prompts and getattr(config, "SYSTEM_MSG_SEMANTIC_REWRITE_EN", ""):
        system_prompt = getattr(config, "SYSTEM_MSG_SEMANTIC_REWRITE_EN", "")
        user_template = getattr(config, "USER_MSG_SEMANTIC_REWRITE_EN", "") or getattr(
            config, "USER_MSG_SEMANTIC_REWRITE", ""
        )
    else:
        system_prompt = getattr(config, "SYSTEM_MSG_SEMANTIC_REWRITE", "") or getattr(
            config, "SYSTEM_MSG_SEMANTIC_REWRITE_EN", ""
        )
        user_template = getattr(config, "USER_MSG_SEMANTIC_REWRITE", "") or getattr(
            config, "USER_MSG_SEMANTIC_REWRITE_EN", ""
        )

    if not system_prompt or not user_template:
        log_message("错误：缺少逐参数重写提示词，请检查 prompts/second_cons 配置")
        return False

    api_client = config.api_client

    # 逐参数对话
    params_for_msg = _build_param_list_for_message(semantics_data, extra_info_data, str(message_id))
    if not params_for_msg:
        log_message("警告：该消息未匹配到任何参数，终止")
        return False

    success_any = False
    for idx, p in enumerate(params_for_msg, start=1):
        user_param = user_template.format(
            service_name=service_name,
            message_id=message_id,
            current_function_code=_escape_braces(funcs_snapshot.get("generate_message", "")),
            parameter=_escape_braces(json.dumps(p, ensure_ascii=False, indent=2)),
            tools_intro=_escape_braces(tools_description),
            parameter_index=idx,
        )
        resp = api_client.call_model(system_prompt=system_prompt, user_prompt=user_param, response_format="json_object")
        if not isinstance(resp, dict):
            log_message(f"警告：参数 index={p.get('index')} 响应无效，跳过：{resp}")
            continue

        # 期望返回 { updated_functions: {generate_body: "...", ...}, analysis: {...}, notes: [] }
        updated_funcs: Dict[str, str] = {}
        uf = resp.get("updated_functions")
        if isinstance(uf, dict):
            for key in ("generate_header", "generate_descriptor", "generate_body", "generate_trailer", "generate_message", "part1_content"):
                val = uf.get(key)
                if isinstance(val, str) and val.strip():
                    updated_funcs[key] = val

        if not updated_funcs:
            log_message(f"提示：参数 index={p.get('index')} 未返回可用的代码更新")
            continue

        # 立即写回缓存并刷新本地快照，供下一参数继续在最新代码基础上迭代
        if not _save_functions_parts(updated_functions_dir, str(message_id), updated_funcs, base_snapshot=funcs_snapshot):
            log_message("错误：写回缓存失败，终止")
            return False

        # 刷新快照
        funcs_snapshot = _load_functions_parts(updated_functions_dir, str(message_id)) or funcs_snapshot
        success_any = True

        # 同时保存一次该参数的响应记录
        output_dir = exec_service_dir / "semantic_rewrites"
        output_dir.mkdir(exist_ok=True)
        out_path = output_dir / f"message_{message_id}_param_{p.get('index')}.json"
        try:
            save_json({"parameter": p, "response": resp}, out_path)
        except Exception:
            pass

    if not success_any:
        log_message("警告：没有任何参数产生代码更新")
        return False

    log_message(f"--- 服务 {service_name} 消息 {message_id} 的逐参数重写完成 ---")
    return True


def regenerate_all_message_with_semantics(
    service_name: str,
    use_english_prompts: bool = False,
) -> bool:
    """对指定服务的所有消息ID执行逐参数重写。

    Args:
        service_name: 目标服务名称。
        use_english_prompts: 是否使用英文提示词。
        update_cpp: 是否直接覆盖 generate_message.cc。
    """
    log_message(f"--- 开始对服务 {service_name} 的所有消息执行逐参数重写 ---")
    service_dir = SERVICES_DIR / service_name
    exec_service_dir = FUZZ_EXEC_DIR / service_name
    exec_service_dir.mkdir(parents=True, exist_ok=True)
    if not service_dir.exists():
        log_message(f"错误：服务目录 {service_dir} 不存在")
        return False

    # 获取所有消息ID
    try:
        messages = _load_service_messages(service_dir)
        message_ids = [str(msg["message_id"]) for msg in messages]
        if not message_ids:
            log_message("错误：未找到任何消息ID")
            return False
    except Exception as exc:
        log_message(f"加载消息ID失败：{exc}")
        return False

    log_message(f"找到 {len(message_ids)} 个消息ID: {', '.join(message_ids)}")

    success_count = 0
    for msg_id in message_ids:
        log_message(f"处理消息ID: {msg_id}")
        if regenerate_message_with_semantics(
            service_name=service_name,
            message_id=msg_id,
            use_english_prompts=use_english_prompts,
        ):
            success_count += 1
        else:
            log_message(f"警告：消息ID {msg_id} 重写失败，继续下一个")

    log_message(f"--- 服务 {service_name} 的所有消息重写完成，成功 {success_count}/{len(message_ids)} ---")
    
    # 合并 updated_functions 到 generate_message.cc
    from llm_utils.utils import combine_generate_code
    cpp_content = combine_generate_code(service_name, use_updated_functions=True)
    if cpp_content:
        cpp_file = exec_service_dir / "generate_message.cc"
        try:
            cpp_file.write_text(cpp_content, encoding="utf-8")
            log_message(f"已生成并保存 C++ 文件: {cpp_file}")
        except Exception as e:
            log_message(f"保存 C++ 文件失败: {e}")
    else:
        log_message("警告：未能生成 C++ 内容")
    
    return success_count == len(message_ids)