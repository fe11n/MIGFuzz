# -*- coding: UTF-8 -*-
"""辅助生成参数语义约束以及基于语义的消息生成代码重写。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import time

from llm_utils.config import config
from llm_utils.utils import load_json, save_json, log_message, SERVICES_DIR


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


def _find_parameter_type(parameter_types: List[Dict[str, Any]], type_name: str) -> Optional[Dict[str, Any]]:
    """根据参数类型名称查找已存在的语义定义。"""
    for entry in parameter_types:
        if entry.get("parameter_name") == type_name:
            return entry
    return None


def _add_message_mapping(parameter_entry: Dict[str, Any], message_id: str, parameter_index: int) -> None:
    """在参数类型条目中追加消息ID与参数位置的映射。"""
    try:
        index_value = int(parameter_index)
    except (TypeError, ValueError):
        log_message(f"警告：无法解析参数位置 {parameter_index}，跳过映射更新")
        return

    message_id_str = str(message_id)
    message_ids: List[Dict[str, Any]] = parameter_entry.setdefault("message_ids", [])
    for mapping in message_ids:
        if isinstance(mapping, dict) and message_id_str in mapping:
            mapping[message_id_str] = index_value
            return
    message_ids.append({message_id_str: index_value})


def _unique_preserve(sequence: List[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for item in sequence:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _ensure_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]

def _wrap_with_message_id(value: Any, message_id: str) -> Any:
    if not value:
        return value
    if isinstance(value, list):
        return [_wrap_with_message_id(item, message_id) for item in value]
    if isinstance(value, dict):
        return value
    return {message_id: value}


def _looks_like_message_id(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    if not text:
        return False
    return text.isdigit()


def _normalize_index_list(raw_indices: Any) -> List[int]:
    if raw_indices is None:
        return []
    if isinstance(raw_indices, (list, tuple, set)):
        candidates = raw_indices
    else:
        candidates = [raw_indices]

    normalized: List[int] = []
    for item in candidates:
        if item is None:
            continue
        try:
            normalized.append(int(item))
        except (TypeError, ValueError):
            continue
    return normalized


def _attach_message_id_to_constraints(
    constraints: Optional[List[Dict[str, Any]]], target_indices: List[int], message_id: str
) -> None:
    if not constraints or not target_indices:
        return

    index_set = {idx for idx in target_indices}
    message_id_str = str(message_id)

    for item in constraints:
        try:
            item_index = int(item.get("index"))
        except (TypeError, ValueError):
            continue
        if item_index not in index_set:
            continue

        ids_value = item.get("ids")
        if isinstance(ids_value, list):
            item["ids"] = _unique_preserve(ids_value + [message_id_str])
        elif ids_value is None:
            item["ids"] = [message_id_str]
        else:
            item["ids"] = _unique_preserve([str(ids_value), message_id_str])


def _prepare_new_constraint_entries(
    raw_value: Any, message_id: str, *, is_extra: bool = False
) -> List[Dict[str, Any]]:
    if raw_value is None:
        return []

    if isinstance(raw_value, (list, tuple)):
        candidates = raw_value
    else:
        candidates = [raw_value]

    prepared: List[Dict[str, Any]] = []
    message_id_str = str(message_id)

    for candidate in candidates:
        if candidate is None:
            continue
        if isinstance(candidate, dict):
            entry = dict(candidate)
            ids_value = entry.get("ids")
            if isinstance(ids_value, (list, tuple)):
                ids_list = list(ids_value)
            elif ids_value is None:
                ids_list = []
            else:
                ids_list = [ids_value]
            ids_list.append(message_id_str)
            entry["ids"] = _unique_preserve([str(identifier).strip() for identifier in ids_list if str(identifier).strip()])
            prepared.append(entry)
            continue

        content = str(candidate).strip()
        if not content:
            continue
        entry = {
            "content": content,
            "ids": [message_id_str],
        }
        prepared.append(entry)

    return prepared


def _standardize_constraints(raw_value: Any, *, is_extra: bool = False) -> List[Dict[str, Any]]:
    """将约束统一为 [{"index": 1, "content": "...", "ids": []}] 形式的字典列表。"""

    collected: List[Dict[str, Any]] = []

    def _append(content: Any, ids: Optional[List[Any]]) -> None:
        if content is None:
            return
        content_str = str(content).strip()
        if not content_str:
            return
        id_list: List[str] = []
        if ids:
            for identifier in ids:
                if identifier is None:
                    continue
                identifier_str = str(identifier).strip()
                if identifier_str:
                    id_list.append(identifier_str)
        entry: Dict[str, Any] = {
            "content": content_str,
            "ids": _unique_preserve(id_list),
        }
        collected.append(entry)

    def _process(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, (list, tuple)):
            for element in value:
                _process(element)
            return
        if isinstance(value, dict):
            if "content" in value:
                ids_value = value.get("ids", [])
                if isinstance(ids_value, (list, tuple)):
                    ids_list = list(ids_value)
                elif ids_value is None:
                    ids_list = []
                else:
                    ids_list = [ids_value]
                _append(value.get("content"), ids_list)
                return
            if "all" in value and len(value) == 1:
                _append(value.get("all"), [])
                return
            for key, val in value.items():
                if key in {"index", "ids", "collected_info"}:
                    continue
                ids_list = [key] if _looks_like_message_id(key) else []
                if isinstance(val, (dict, list, tuple)):
                    _append(json.dumps(val, ensure_ascii=False), ids_list)
                else:
                    _append(val, ids_list)
            return
        _append(value, [])

    _process(raw_value)

    if not collected:
        return []

    merged: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for entry in collected:
        content = entry.get("content")
        if not content:
            continue
        if content in merged:
            merged_entry = merged[content]
            merged_entry["ids"] = _unique_preserve(merged_entry.get("ids", []) + entry.get("ids", []))
        else:
            merged_entry = {
                "content": content,
                "ids": entry.get("ids", []),
            }
            merged[content] = merged_entry
            order.append(content)

    standardized: List[Dict[str, Any]] = []
    for index, content in enumerate(order, start=1):
        merged_entry = merged[content]
        item: Dict[str, Any] = {
            "index": index,
            "content": merged_entry["content"],
            "ids": _unique_preserve(merged_entry.get("ids", [])),
        }
        standardized.append(item)
    return standardized


def _merge_constraints(
    existing: Optional[List[Dict[str, Any]]], additions: Optional[List[Dict[str, Any]]], *, is_extra: bool = False
) -> List[Dict[str, Any]]:
    base = _standardize_constraints(existing, is_extra=is_extra)
    extra = _standardize_constraints(additions, is_extra=is_extra)

    if not base and not extra:
        return []

    combined: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    for entry in base:
        content = entry.get("content")
        if not content:
            continue
        combined[content] = {
            "content": content,
            "ids": entry.get("ids", []),
        }
        order.append(content)

    for entry in extra:
        content = entry.get("content")
        if not content:
            continue
        if content in combined:
            combined_entry = combined[content]
            combined_entry["ids"] = _unique_preserve(combined_entry.get("ids", []) + entry.get("ids", []))
        else:
            combined_entry = {
                "content": content,
                "ids": entry.get("ids", []),
            }
            combined[content] = combined_entry
            order.append(content)

    merged_list: List[Dict[str, Any]] = []
    for index, content in enumerate(order, start=1):
        combined_entry = combined[content]
        item: Dict[str, Any] = {
            "index": index,
            "content": combined_entry["content"],
            "ids": _unique_preserve(combined_entry.get("ids", [])),
        }
        merged_list.append(item)
    return merged_list


def _extract_semantic_type_name(param_info: Dict[str, Any]) -> str:
    """尽可能从参数信息中提取语义类型名称。"""

    if not isinstance(param_info, dict):
        return ""

    candidate_keys = (
        "semantic_type",
        "matched_parameter_type",
        "matched_type",
        "parameter_type",
        "type_name",
        "semanticType",
    )
    for key in candidate_keys:
        value = param_info.get(key)
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped
    return ""


def _standardize_parameter_type_entry(raw_entry: Dict[str, Any]) -> Dict[str, Any]:
    """确保参数类型条目字段格式统一。"""
    parameter_name = (raw_entry.get("parameter_name") or "").strip()
    parameter_role = (raw_entry.get("parameter_role") or "").strip()
    data_type = (raw_entry.get("data_type") or raw_entry.get("type") or "").strip()
    format_constraints = _standardize_constraints(raw_entry.get("format_constraints"))
    semantic_constraints = _standardize_constraints(raw_entry.get("semantic_constraints"))
    extra_source = raw_entry.get("extra_description")
    extra_description = _standardize_constraints(extra_source, is_extra=True)

    normalized_message_ids: List[Dict[str, int]] = []
    seen_keys = set()
    for mapping in raw_entry.get("message_ids", []) or []:
        normalized_mapping: Dict[str, int] = {}
        if isinstance(mapping, dict):
            for key, value in mapping.items():
                try:
                    normalized_mapping[str(key)] = int(value)
                except (TypeError, ValueError):
                    continue
        elif mapping is not None:
            normalized_mapping[str(mapping)] = 0

        if normalized_mapping:
            key_signature = tuple(sorted(normalized_mapping.items()))
            if key_signature not in seen_keys:
                normalized_message_ids.append(normalized_mapping)
                seen_keys.add(key_signature)

    return {
        "parameter_name": parameter_name,
        "parameter_role": parameter_role,
        "data_type": data_type,
        "format_constraints": format_constraints,
        "semantic_constraints": semantic_constraints,
        "extra_description": extra_description,
        "message_ids": normalized_message_ids,
    }


def _standardize_parameter_types_list(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """批量标准化参数类型列表。"""
    return [_standardize_parameter_type_entry(entry) for entry in entries]


def generate_extra_information(service_dir: Path, semantics_data: Dict[str, Any]) -> bool:
    """根据语义文件生成额外信息说明。"""
    try:
        mapping = _load_message_function_map(service_dir)
        parameters_output: List[Dict[str, Any]] = []

        for parameter in semantics_data.get("parameter_types", []):
            extra_list = parameter.get("extra_description") or []
            if not extra_list:
                continue

            extra_entries: List[Dict[str, Any]] = []
            for extra_entry in extra_list:
                content = str(extra_entry.get("content") or "").strip()
                if not content:
                    continue
                raw_ids = extra_entry.get("ids")
                if isinstance(raw_ids, list):
                    id_candidates = raw_ids
                elif raw_ids is None:
                    id_candidates = []
                else:
                    id_candidates = [raw_ids]
                concerned: List[str] = []
                for identifier in id_candidates:
                    function_name = mapping.get(str(identifier))
                    if function_name:
                        if function_name not in concerned:
                            concerned.append(function_name)
                extra_entries.append(
                    {
                        "content": content,
                        "concerned_functions": concerned,
                        "information": "",
                    }
                )

            if not extra_entries:
                continue

            parameters_output.append(
                {
                    "parameter_name": parameter.get("parameter_name", ""),
                    "parameter_role": parameter.get("parameter_role", ""),
                    "data_type": parameter.get("data_type", ""),
                    "extra_descriptions": extra_entries,
                }
            )

        payload = {
            "service_name": semantics_data.get("service_name") or service_dir.name,
            "parameters": parameters_output,
        }

        output_path = service_dir / "parameter_extra_information.json"
        if save_json(payload, output_path):
            log_message(f"额外信息已保存至 {output_path}")
            return True

        log_message(f"警告：保存额外信息文件 {output_path} 失败")
        return False
    except Exception as exc:
        log_message(f"生成额外信息文件时发生异常：{exc}")
        return False


def generate_parameter_semantics(
    service_name: str,
    use_english_prompts: bool = False,
    use_cache: bool = True,
) -> bool:
    """逐条调用LLM归并参数语义，并产出最终 `parameter_semantics.json`。

    Args:
        service_name: 目标服务名称。
        use_english_prompts: 是否使用英文提示词。
        use_cache: 若为 True，则优先复用缓存结果，命中缓存时跳过模型调用。
    """
    log_message(f"--- 开始为服务 {service_name} 生成参数语义约束（逐消息分析） ---")
    service_dir = SERVICES_DIR / service_name
    if not service_dir.exists():
        log_message(f"错误：服务目录 {service_dir} 不存在")
        return False

    try:
        message_entries = _load_service_messages(service_dir)
        if not message_entries:
            log_message("错误：未找到任何有效的消息处理函数信息")
            return False

        message_entries.sort(key=lambda item: item.get("message_id", 0))

        cache_dir = service_dir / "parameter_semantics_cache"
        cache_dir.mkdir(exist_ok=True)

        if use_english_prompts and config.SYSTEM_MSG_PARAM_SEMANTICS_EN:
            system_prompt = config.SYSTEM_MSG_PARAM_SEMANTICS_EN
            user_template = config.USER_MSG_PARAM_SEMANTICS_EN or config.USER_MSG_PARAM_SEMANTICS
        else:
            system_prompt = config.SYSTEM_MSG_PARAM_SEMANTICS or config.SYSTEM_MSG_PARAM_SEMANTICS_EN
            user_template = config.USER_MSG_PARAM_SEMANTICS

        if not system_prompt or not user_template:
            log_message("错误：缺少参数语义提示词，请检查 prompts/second_cons 配置")
            return False

        api_client = config.api_client

        aggregated: Dict[str, Any] = {
            "service_name": service_name,
            "parameter_types": [],
            "notes": [],
        }

        last_message_id: Optional[str] = None

        for entry in message_entries:
            message_id = entry.get("message_id")
            message_id_str = str(message_id)
            last_message_id = message_id_str

            aggregated["parameter_types"] = _standardize_parameter_types_list(aggregated.get("parameter_types", []))
            cache_file = cache_dir / f"message_{message_id_str}.json"
            parameters_response: Optional[List[Dict[str, Any]]] = None
            response_notes: Any = None
            response_from_cache = False

            if use_cache and cache_file.exists():
                cached_payload = load_json(cache_file)
                if isinstance(cached_payload, dict):
                    cached_parameters = cached_payload.get("parameters")
                    if isinstance(cached_parameters, list):
                        parameters_response = cached_parameters
                        response_notes = cached_payload.get("notes")
                        response_from_cache = True
                        log_message(f"消息 {message_id_str} 命中缓存，跳过模型调用")
                    else:
                        log_message(f"警告：缓存 {cache_file} 缺少有效的参数列表，将重新调用模型")
                else:
                    log_message(f"警告：缓存 {cache_file} 内容异常，将重新调用模型")

            if parameters_response is None:
                current_types_json = json.dumps(aggregated["parameter_types"], indent=2, ensure_ascii=False)
                message_payload = {
                    "message_id": message_id_str,
                    "handle_function_name": entry.get("handle_function_name"),
                    "handle_function_pseudocode": entry.get("handle_function_pseudocode"),
                }
                message_payload_json = json.dumps(message_payload, indent=2, ensure_ascii=False)

                user_prompt = user_template.format(
                    service_name=service_name,
                    current_parameter_types=_escape_braces(current_types_json),
                    message_payload=_escape_braces(message_payload_json),
                )

                log_message(f"调用LLM分析消息 {message_id_str} 的参数语义...")
                time.sleep(5)  # 添加延迟以避免速率限制
                response = api_client.call_model(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_format="json_object",
                )

                if isinstance(response, list):
                    parameters_response = response
                elif isinstance(response, dict):
                    candidate = response.get("parameters")
                    if isinstance(candidate, list):
                        parameters_response = candidate
                    else:
                        log_message(f"错误：LLM 响应缺少有效的参数数组（消息 {message_id_str}）：{response}")
                        return False
                    if isinstance(response.get("notes"), list):
                        response_notes = response["notes"]
                else:
                    log_message(f"错误：LLM 返回无效响应（消息 {message_id_str}）：{response}")
                    return False

            if parameters_response is None:
                log_message(f"错误：未获取到消息 {message_id_str} 的参数分析结果")
                return False

            matched_counter = 0
            new_counter = 0

            for param_info in parameters_response:
                if not isinstance(param_info, dict):
                    log_message(f"警告：消息 {message_id_str} 的参数响应存在非字典条目，已忽略：{param_info}")
                    continue

                try:
                    param_index = int(param_info.get("index"))
                except (TypeError, ValueError):
                    log_message(f"警告：消息 {message_id_str} 的参数缺少有效 index，已忽略：{param_info}")
                    continue

                param_name = str(param_info.get("name") or "").strip()
                is_matched = bool(param_info.get("is_matched"))
                semantic_type_name = _extract_semantic_type_name(param_info)
                data_type_name = str(param_info.get("type") or "").strip()
                if is_matched and not semantic_type_name and param_name:
                    fallback_entry = _find_parameter_type(aggregated["parameter_types"], param_name)
                    if fallback_entry:
                        semantic_type_name = fallback_entry.get("parameter_name", "")

                if is_matched:
                    if not semantic_type_name:
                        log_message(
                            f"警告：消息 {message_id_str} 的参数 {param_index} 标记为匹配但缺少语义类型信息，已忽略")
                        continue
                    existing_entry = _find_parameter_type(aggregated["parameter_types"], semantic_type_name)
                    if not existing_entry:
                        log_message(
                            f"警告：消息 {message_id_str} 指定的已有类型 '{semantic_type_name}' 未在聚合结果中找到，已忽略")
                        continue
                    _add_message_mapping(existing_entry, message_id_str, param_index)
                    if data_type_name and not existing_entry.get("data_type"):
                        existing_entry["data_type"] = data_type_name

                    matched_format = _normalize_index_list(param_info.get("matched_format_constraints"))
                    if matched_format:
                        _attach_message_id_to_constraints(
                            existing_entry.get("format_constraints"), matched_format, message_id_str
                        )

                    matched_semantic = _normalize_index_list(param_info.get("matched_semantic_constraints"))
                    if matched_semantic:
                        _attach_message_id_to_constraints(
                            existing_entry.get("semantic_constraints"), matched_semantic, message_id_str
                        )

                    matched_extra = _normalize_index_list(param_info.get("matched_extra_description"))
                    if matched_extra:
                        _attach_message_id_to_constraints(
                            existing_entry.get("extra_description"), matched_extra, message_id_str
                        )

                    new_format_raw = param_info.get("new_format_constraints")
                    new_format_entries = _prepare_new_constraint_entries(
                        new_format_raw, message_id_str
                    )
                    if new_format_entries:
                        existing_entry["format_constraints"] = _merge_constraints(
                            existing_entry.get("format_constraints"), new_format_entries
                        )

                    new_semantic_raw = param_info.get("new_semantic_constraints")
                    new_semantic_entries = _prepare_new_constraint_entries(
                        new_semantic_raw, message_id_str
                    )
                    if new_semantic_entries:
                        existing_entry["semantic_constraints"] = _merge_constraints(
                            existing_entry.get("semantic_constraints"), new_semantic_entries
                        )

                    new_extra_raw = param_info.get("new_extra_description")
                    new_extra_entries = _prepare_new_constraint_entries(
                        new_extra_raw, message_id_str, is_extra=True
                    )
                    if new_extra_entries:
                        existing_entry["extra_description"] = _merge_constraints(
                            existing_entry.get("extra_description"), new_extra_entries, is_extra=True
                        )

                    matched_counter += 1
                    continue

                candidate_type_name = semantic_type_name or param_name
                if not candidate_type_name:
                    log_message(
                        f"警告：消息 {message_id_str} 的参数 {param_index} 缺少可用的语义类型名称，已忽略")
                    continue

                parameter_role = str(param_info.get("parameter_role") or param_info.get("role") or "").strip()
                if not parameter_role:
                    log_message(
                        f"警告：消息 {message_id_str} 的参数 {param_index} 缺少 parameter_role 描述，已尽力继续")
                if not data_type_name:
                    log_message(
                        f"警告：消息 {message_id_str} 的参数 {param_index} 缺少数据类型描述，已尽力继续")

                extra_details = param_info.get("extra_description")

                raw_entry = {
                    "parameter_name": candidate_type_name,
                    "parameter_role": parameter_role,
                    "data_type": data_type_name,
                    "format_constraints": _wrap_with_message_id(param_info.get("format_constraints"), message_id_str),
                    "semantic_constraints": _wrap_with_message_id(
                        param_info.get("semantic_constraints"), message_id_str
                    ),
                    "extra_description": _wrap_with_message_id(extra_details, message_id_str),
                    "message_ids": [{message_id_str: param_index}],
                }
                standardized = _standardize_parameter_type_entry(raw_entry)
                if not standardized.get("parameter_name"):
                    log_message(f"警告：消息 {message_id_str} 的新参数类型缺少名称，已忽略")
                    continue

                existing_entry = _find_parameter_type(aggregated["parameter_types"], standardized["parameter_name"])
                if existing_entry:
                    log_message(
                        f"提示：参数类型 '{standardized['parameter_name']}' 已存在，将合并约束并追加消息映射")
                    for mapping in standardized.get("message_ids", []):
                        for key, value in mapping.items():
                            _add_message_mapping(existing_entry, key, value)
                    if standardized.get("parameter_role") and not existing_entry.get("parameter_role"):
                        existing_entry["parameter_role"] = standardized["parameter_role"]
                    if standardized.get("data_type") and not existing_entry.get("data_type"):
                        existing_entry["data_type"] = standardized["data_type"]
                    if standardized.get("format_constraints"):
                        existing_entry["format_constraints"] = _merge_constraints(
                            existing_entry.get("format_constraints"),
                            standardized.get("format_constraints"),
                        )
                    if standardized.get("semantic_constraints"):
                        existing_entry["semantic_constraints"] = _merge_constraints(
                            existing_entry.get("semantic_constraints"),
                            standardized.get("semantic_constraints"),
                        )
                    if standardized.get("extra_description"):
                        existing_entry["extra_description"] = _merge_constraints(
                            existing_entry.get("extra_description"),
                            standardized.get("extra_description"),
                            is_extra=True,
                        )
                else:
                    aggregated["parameter_types"].append(standardized)
                new_counter += 1

            aggregated["parameter_types"] = _standardize_parameter_types_list(aggregated["parameter_types"])

            if isinstance(response_notes, list):
                aggregated["notes"] = response_notes

            cache_payload = {
                "message_id": message_id_str,
                "parameters": parameters_response,
                "notes": aggregated.get("notes", []),
                "parameter_types": aggregated["parameter_types"],
            }
            cache_file = cache_dir / f"message_{message_id_str}.json"
            if not save_json(cache_payload, cache_file):
                log_message(f"警告：缓存写入失败 {cache_file}")
            log_message(
                f"消息 {message_id_str} 处理完成：匹配已有 {matched_counter} 项，新增 {new_counter} 项"
                + ("（使用缓存）" if response_from_cache else "")
            )

        if last_message_id is None:
            log_message("错误：未处理任何消息，无法生成参数语义约束")
            return False

        aggregated["service_name"] = service_name
        aggregated["parameter_types"] = _standardize_parameter_types_list(aggregated["parameter_types"])
        aggregated["notes"] = _unique_preserve(_ensure_list(aggregated.get("notes")))

        output_path = service_dir / "parameter_semantics.json"
        if save_json(aggregated, output_path):
            log_message(
                f"参数语义约束已保存至 {output_path} （来源于消息 {last_message_id} 的最新分析结果）")
            if not generate_extra_information(service_dir, aggregated):
                log_message("警告：生成 parameter_extra_information.json 时出现问题")
            log_message(f"--- 服务 {service_name} 的参数语义分析完成，共处理 {len(message_entries)} 个消息 ---")
            return True

        log_message(f"错误：保存文件 {output_path} 失败")
        return False
    except Exception as exc:
        log_message(f"生成参数语义约束时发生异常：{exc}")
        return False


def _load_cached_generate_message(service_dir: Path, message_id: str) -> Optional[str]:
    """从缓存函数文件中加载 generate_message_{id} 定义。"""
    functions_dir = service_dir / "functions"
    if not functions_dir.exists():
        return None

    candidate = functions_dir / f"functions_{message_id}.json"
    if not candidate.exists():
        return None

    try:
        cached = load_json(candidate)
    except Exception as exc:
        log_message(f"读取缓存 {candidate} 失败：{exc}")
        return None

    message_funcs = cached.get("message_functions", {})
    entry = message_funcs.get(str(message_id)) or message_funcs.get(int(message_id))
    if not entry:
        return None
    return entry.get("generate_message")


def _collect_parameter_constraints(semantics: Dict[str, Any], message_id: str) -> List[Dict[str, Any]]:
    """筛选出与指定消息ID相关的参数语义约束。"""
    relevant: List[Dict[str, Any]] = []
    target = str(message_id)
    for item in semantics.get("parameter_types", []):
        for mapping in item.get("message_ids", []) or []:
            if isinstance(mapping, dict):
                if target in {str(k) for k in mapping.keys()}:
                    relevant.append(item)
                    break
            else:
                if str(mapping) == target:
                    relevant.append(item)
                    break
    return relevant


def main() -> None:
    parser = argparse.ArgumentParser(description="生成参数语义约束并按语义重写消息代码")
    subparsers = parser.add_subparsers(dest="command")

    parser_semantics = subparsers.add_parser("param", help="生成参数语义约束")
    parser_semantics.add_argument("service", help="服务名称，例如 com.apple.bsd.dirhelper")
    parser_semantics.add_argument("--english", action="store_true", help="使用英文提示词")
    parser_semantics.add_argument("--no-cache", action="store_true", help="忽略缓存，强制调用模型")


    parser_test_extra = subparsers.add_parser("test-extra", help="测试指定服务的额外信息生成")
    parser_test_extra.add_argument(
        "--service",
        default="com.apple.FileCoordination",
        help="目标服务名称，默认 com.apple.FileCoordination",
    )
    parser_test_extra.add_argument(
        "--semantics",
        type=Path,
        help="语义约束文件路径，默认读取服务目录下的 parameter_semantics.json",
    )

    args = parser.parse_args()

    if args.command == "param":
        success = generate_parameter_semantics(
            service_name=args.service,
            use_english_prompts=args.english,
            use_cache=not args.no_cache,
        )
        if not success:
            exit(1)
        return

    if args.command == "test-extra":
        target_service = args.service
        service_dir = SERVICES_DIR / target_service
        if not service_dir.exists():
            log_message(f"错误：服务目录 {service_dir} 不存在")
            exit(1)
        semantics_file = args.semantics or (service_dir / "parameter_semantics.json")
        if not semantics_file.exists():
            log_message(f"错误：未找到语义约束文件 {semantics_file}")
            exit(1)
        try:
            semantics_payload = load_json(semantics_file)
        except Exception as exc:
            log_message(f"读取语义约束文件失败：{exc}")
            exit(1)
        if not generate_extra_information(service_dir, semantics_payload):
            exit(1)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
