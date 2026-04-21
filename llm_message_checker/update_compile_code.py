# -*- coding: UTF-8 -*-
"""根据编译失败信息更新指定服务的消息生成代码。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Optional

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

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


def _escape_braces(text: str) -> str:
    """在格式化之前转义花括号，避免 str.format 抛错。"""
    return text.replace("{", "{{").replace("}", "}}")


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


def _load_check_fail_reason(service_name: str) -> str:
    """从 check_result.json 中加载编译失败原因。"""
    check_result_path = FUZZ_EXEC_DIR / service_name / "check_result.json"
    if not check_result_path.exists():
        log_message(f"警告：未找到 check_result.json: {check_result_path}")
        return ""
    try:
        data = load_json(check_result_path)
        return data.get("compile_fail_reason", "")
    except Exception as exc:
        log_message(f"读取 check_result.json 失败: {exc}")
        return ""


def update_compile_code_for_service(
    service_name: str,
    use_english_prompts: bool = False,
) -> Optional[dict]:
    """调用大模型根据编译失败信息一次性更新整个服务的消息生成代码。"""
    service_dir = SERVICES_DIR / service_name
    exec_service_dir = FUZZ_EXEC_DIR / service_name
    if not service_dir.exists():
        log_message(f"错误：服务目录 {service_dir} 不存在")
        return None

    # 加载整个 generate_message.cc 文件
    cpp_file = exec_service_dir / "generate_message.cc"
    if not cpp_file.exists():
        log_message(f"错误：generate_message.cc 文件不存在: {cpp_file}")
        return None

    try:
        generate_message_cc = cpp_file.read_text(encoding="utf-8")
    except Exception as e:
        log_message(f"读取 generate_message.cc 失败: {e}")
        return None

    generate_tools_text = _load_generate_tools()
    check_fail_reason = _load_check_fail_reason(service_name)

    template_values = {
        "service_name": service_name,
        "generate_message_cc": _escape_braces(generate_message_cc),
        "generate_tools": _escape_braces(generate_tools_text),
        "check_fail_reason": _escape_braces(check_fail_reason.strip() or "(无编译失败原因)"),
    }

    if use_english_prompts:
        system_prompt = config.SYSTEM_MSG_UPDATE_COMPILE_BY_ID_EN
        user_prompt_template = config.USER_MSG_UPDATE_COMPILE_BY_ID_EN
    else:
        system_prompt = config.SYSTEM_MSG_UPDATE_COMPILE_BY_ID
        user_prompt_template = config.USER_MSG_UPDATE_COMPILE_BY_ID

    if not system_prompt or not user_prompt_template:
        log_message("错误：未找到 update_code 对应的提示词，请确认 prompts 已配置")
        return None

    user_prompt = user_prompt_template.format(**template_values)

    api_client = config.api_client
    response = api_client.call_model(system_prompt=system_prompt, user_prompt=user_prompt, response_format="json_object")

    usage = response.get("__token_usage", {})

    # 解析响应，response 应该是 { "part1_content": "...", "updates": { "message_id": { ... }, ... } }
    if not isinstance(response, dict):
        log_message("错误：模型响应不是字典格式")
        return usage

    functions_dir = exec_service_dir / "functions"
    functions_dir.mkdir(exist_ok=True)

    # 处理 part1_content
    updated_part1 = response.get("part1_content", "")
    if updated_part1.strip():
        merged_part1 = _update_part1(functions_dir, updated_part1)
        log_message("PART1 工具函数已更新并写入 part1.json。")
    else:
        merged_part1 = _load_part1(functions_dir)

    # 处理每个消息ID的更新
    updates = response.get("updates", {})
    if not isinstance(updates, dict):
        log_message("错误：updates 不是字典格式")
        return

    for message_id_str, update_data in updates.items():
        if not isinstance(update_data, dict):
            log_message(f"警告：消息ID {message_id_str} 的更新不是字典格式")
            continue

        functions_file = functions_dir / f"functions_{message_id_str}.json"
        if functions_file.exists():
            cached_data = load_json(functions_file)
            message_functions = cached_data.get("message_functions", {}).get(message_id_str)
        else:
            cached_data = {}
            message_functions = None

        if not message_functions:
            log_message(f"警告：缓存文件 {functions_file} 中缺少消息 ID {message_id_str} 的函数内容")
            continue

        updated_functions = message_functions.copy() if message_functions else {}
        for func_key in [
            "generate_header",
            "generate_descriptor",
            "generate_body",
            "generate_trailer",
            "generate_message",
        ]:
            if func_key in update_data:
                updated_functions[func_key] = update_data[func_key]

        new_cache = {
            "part1_content": merged_part1,
            "message_functions": {
                message_id_str: updated_functions
            }
        }
        if not save_json(new_cache, functions_file):
            log_message(f"错误：写入更新后的缓存文件失败：{functions_file}")
            continue

        log_message(f"已更新 {functions_file}，模型说明：{update_data.get('notes', '').strip()}")

    # 重新生成整个 generate_message.cc
    cpp_content = combine_generate_code(service_name)
    if cpp_content is None:
        log_message("警告：整合 generate_message.cc 时发生问题")
    else:
        try:
            cpp_file.write_text(cpp_content, encoding="utf-8")
            log_message(f"已重新生成服务的 generate_message.cc: {cpp_file}")
        except Exception as e:
            log_message(f"写入 generate_message.cc 失败: {e}")
            
    return usage


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="根据编译失败信息更新消息构造代码")
    parser.add_argument("service", nargs='?', help="服务名称，例如 com.apple.FileCoordination")
    parser.add_argument(
        "--english",
        action="store_true",
        help="使用英文提示词与模型交互"
    )

    args = parser.parse_args(argv)

    if args.service:
        # 处理指定服务的编译失败
        update_compile_code_for_service(service_name=args.service, use_english_prompts=args.english)
    else:
        # 这个脚本不再负责批量处理整个目录，这里只提示用户
        log_message("请提供需要处理的服务名称，例如: python3 update_compile_code.py com.apple.FileCoordination")

if __name__ == "__main__":
    main()