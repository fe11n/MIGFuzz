# -*- coding: UTF-8 -*-
"""根据调试信息更新指定服务的消息生成代码。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Optional

from llm_utils.config import config
from llm_utils.utils import (
    combine_generate_code,
    load_json,
    log_message,
    save_json,
    SERVICES_DIR,
    FUZZ_EXEC_DIR
)

MessageFunctions = Dict[str, str]


def _load_part1(functions_dir: Path) -> str:
    """Load shared PART1 content for a service."""
    part1_path = functions_dir / "part1.json"
    if not part1_path.exists():
        return ""
    try:
        stored = load_json(part1_path)
    except Exception as exc:
        log_message(f"读取PART1缓存失败: {exc}")
        return ""

    if isinstance(stored, dict):
        return str(stored.get("part1_content", ""))
    if isinstance(stored, str):
        return stored
    return ""


def _update_part1(functions_dir: Path, new_content: str) -> str:
    """Update PART1 content with new content."""
    content = (new_content or "").strip()
    if not content:
        return _load_part1(functions_dir)

    part1_path = functions_dir / "part1.json"
    payload = {"part1_content": content + "\n"}
    if not save_json(payload, part1_path):
        log_message(f"警告：写入 PART1 缓存失败：{part1_path}")
        return _load_part1(functions_dir)
    return content + "\n"


def _load_failtrace(service_dir: Path, message_id: str) -> str:
    """Load failtrace log."""
    failtrace_path = service_dir / "check_fail_log" / f"failtrace_{message_id}.txt"
    if failtrace_path.exists():
        try:
            content = failtrace_path.read_text(encoding="utf-8")
            # 保留文件末尾的内容，避免过长日志扰乱提示
            if len(content) > 12000:
                return content[-12000:]
            return content
        except Exception as exc:
            log_message(f"读取 failtrace 失败: {exc}")
    return ""


def _escape_braces(text: str) -> str:
    """在格式化之前转义花括号，避免 str.format 抛错。"""
    return text.replace("{", "{{").replace("}", "}}")


def _format_message_functions(msg_id: str, functions: MessageFunctions, part1_content: str) -> str:
    """将现有的消息生成函数拼接成便于阅读的文本。"""
    ordered_keys = [
        "generate_header",
        "generate_descriptor",
        "generate_body",
        "generate_trailer",
        "generate_message",
    ]

    parts = []
    if part1_content.strip():
        parts.append("// PART1 (headers and tooling)")
        parts.append(part1_content.strip())

    for key in ordered_keys:
        code = functions.get(key, "") if functions else ""
        if code.strip():
            parts.append(f"// {key} for message {msg_id}")
            parts.append(code.strip())

    remaining_keys = [k for k in functions.keys() if k not in ordered_keys]
    for key in remaining_keys:
        code = functions[key]
        if code.strip():
            parts.append(f"// {key} (additional)")
            parts.append(code.strip())

    return "\n\n".join(parts)


def _load_generate_tools() -> str:
    """加载生成工具函数说明文件。"""
    tools_file = Path(__file__).parent.parent / "fuzz_helpers" / "tool_lib.cc"
    if not tools_file.exists():
        log_message(f"警告：未找到 tool_lib.cc: {tools_file}")
        return ""
    try:
        return tools_file.read_text(encoding="utf-8")
    except Exception as exc:
        log_message(f"读取 tool_lib.cc 失败: {exc}")
        return ""


def update_generate_code(
    service_name: str,
    message_id: int,
    use_english_prompts: bool = False,

) -> dict:
    """调用大模型更新指定消息 ID 的生成代码。"""
    service_dir = SERVICES_DIR / service_name
    exec_service_dir = FUZZ_EXEC_DIR / service_name
    exec_service_dir.mkdir(parents=True, exist_ok=True)
    if not service_dir.exists():
        log_message(f"错误：服务目录 {service_dir} 不存在")
        return {}

    message_id_str = str(message_id)

    form_cons_file = service_dir / "form_cons.json"
    if not form_cons_file.exists():
        log_message(f"错误：未找到 form_cons.json：{form_cons_file}")
        return {}
    form_cons = load_json(form_cons_file)
    if message_id_str not in form_cons:
        log_message(f"错误：form_cons.json 中缺少消息 ID {message_id_str} 的约束信息")
        return {}
    message_constraints = form_cons[message_id_str]

    functions_dir = exec_service_dir / "functions"
    functions_dir.mkdir(exist_ok=True)
    functions_file = functions_dir / f"functions_{message_id_str}.json"
    if functions_file.exists():
        cached_data = load_json(functions_file)
        message_functions = cached_data.get("message_functions", {}).get(message_id_str)
    else:
        cached_data = {}
        message_functions = None

    part1_content = _load_part1(functions_dir)
    if not message_functions:
        log_message(f"错误：缓存文件 {functions_file} 中缺少消息 ID {message_id_str} 的函数内容")
        return {}

    h_path = functions_dir / f"history_{message_id_str}.json"
    history_text = ""
    if h_path.exists():
        try:
            h_data = load_json(h_path)
            history_text = "[最初始的 faillog 日志]:\n" + h_data.get("initial_faillog", "") + "\n\n"
            for r in h_data.get("history", []):
                history_text += f"=========== 第 {r.get('attempt', '?')} 轮重新生成记录 ===========\n"
                history_text += "[当时系统采用的生成代码版本]:\n"
                for k, v in r.get("response", {}).items():
                    if isinstance(v, str) and v.strip():
                        history_text += f"// {k}\n{v}\n"
                
                rtype = r.get("result_type", "")
                if rtype == "compile_error":
                    history_text += "\n[该代码编译失败，编译报错如下]:\n"
                else:
                    history_text += "\n[该代码check失败，failtrace如下]:\n"
                
                content = r.get("result_content", "")
                if len(content) > 12000:
                    content = content[-12000:]
                history_text += content + "\n\n"
        except: pass

    failtrace_text = _load_failtrace(exec_service_dir, message_id_str)

    original_code_text = _format_message_functions(message_id_str, message_functions, part1_content)
    constraints_text = json.dumps(message_constraints, ensure_ascii=False, indent=2)

    generate_tools_text = _load_generate_tools()

    template_values = {
        "service_name": service_name,
        "message_id": message_id_str,
        "message_constraints": _escape_braces(constraints_text),
        "original_generate_code": _escape_braces(original_code_text),
        "generate_tools": _escape_braces(generate_tools_text),
        "history_result": _escape_braces(history_text.strip() or "(无历史记录)"),
        "failtrace": _escape_braces(failtrace_text.strip() or "(无 faillog)"),
    }

    if use_english_prompts:
        system_prompt = config.SYSTEM_MSG_UPDATE_BY_ID_EN
        user_prompt_template = config.USER_MSG_UPDATE_BY_ID_EN
    else:
        system_prompt = config.SYSTEM_MSG_UPDATE_BY_ID
        user_prompt_template = config.USER_MSG_UPDATE_BY_ID

    if not system_prompt or not user_prompt_template:
        log_message("错误：未找到 update_code 对应的提示词，请确认 prompts 已配置")
        return {}

    user_prompt = user_prompt_template.format(**template_values)

    api_client = config.api_client
    response = api_client.call_model(system_prompt=system_prompt, user_prompt=user_prompt, response_format="json_object")

    updated_part1 = response.get("part1_content", "")
    if updated_part1.strip():
        merged_part1 = _update_part1(functions_dir, updated_part1)
    else:
        merged_part1 = _load_part1(functions_dir)

    updated_functions = message_functions.copy() if message_functions else {}
    for func_key in [
        "generate_header",
        "generate_descriptor",
        "generate_body",
        "generate_trailer",
        "generate_message",
    ]:
        if func_key in response:
            updated_functions[func_key] = response[func_key]

    new_cache = {
        "part1_content": merged_part1,
        "message_functions": {
            message_id_str: updated_functions
        }
    }
    if not save_json(new_cache, functions_file):
        log_message(f"错误：写入更新后的缓存文件失败：{functions_file}")
        return {}

    log_message(f"已更新 {functions_file}，模型说明：{response.get('notes', '').strip()}")

    if updated_part1.strip() and merged_part1.strip():
        log_message("PART1 工具函数已更新并写入 part1.json。")

    cpp_content = combine_generate_code(service_name)
    if cpp_content is None:
        log_message("警告：整合 generate_message.cc 时发生问题")
    else:
        cpp_file = exec_service_dir / "generate_message.cc"
        try:
            cpp_file.write_text(cpp_content, encoding="utf-8")
            log_message(f"已重新生成服务的 generate_message.cc: {cpp_file}")
        except Exception as e:
            log_message(f"写入 generate_message.cc 失败: {e}")

    return response.get("__token_usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cost": 0.0})


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="根据调试信息更新消息构造代码")
    parser.add_argument("service", help="服务名称，例如 com.apple.FileCoordination")
    parser.add_argument("message_id", type=int, help="消息 ID，例如 867800")
    parser.add_argument(
        "--english",
        action="store_true",
        help="使用英文提示词与模型交互"
    )

    args = parser.parse_args(argv)

    update_generate_code(
        service_name=args.service,
        message_id=args.message_id,
        use_english_prompts=args.english,
    )

if __name__ == "__main__":
    main()
