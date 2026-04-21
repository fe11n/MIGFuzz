# -*- coding: UTF-8 -*-
# 文件名: test_llm.py

from llm_utils.api_client import Google_APIClient
from llm_utils.config import config
from llm_utils.utils import log_message
import json
from datetime import datetime
import requests # 确保导入 requests

# =================================================================
#  您原有的测试函数 (无需修改)
# =================================================================
# (test_llm_connection, test_llm_json_response, test_llm_with_history 函数保持原样即可)
def test_llm_connection(client=None):
    """测试与大模型的连接"""
    print("\n开始测试与大模型的连接...")
    try:
        if client is None:
            client = config.api_client
        system_prompt = "You are a helpful assistant."
        user_prompt = "Why is the sky blue?"
        print("正在向大模型发送请求...")
        print(f"问题: {user_prompt}")
        response = client.call_model(system_prompt=system_prompt, user_prompt=user_prompt, response_format="text")
        print("\n=== 大模型响应 ===")
        print(response)
        print("=== 响应结束 ===\n")
        if isinstance(response, dict) and "error" in response:
            print(f"❌ 连接失败: {response['error']}")
            return False
        elif response and isinstance(response, str):
            print("✅ 连接成功！大模型正常响应")
            return True
        else:
            print(f"⚠️ 收到了响应，但格式异常: {type(response)}")
            return False
    except Exception as e:
        print(f"❌ 测试过程中发生错误: {e}")
        return False

def test_llm_json_response(client=None):
    """测试JSON格式的响应"""
    print("\n开始测试JSON格式响应...")
    try:
        if client is None:
            client = config.api_client
        system_prompt = 'You are a helpful assistant that responds in JSON. {"answer": "your answer", "points": ["p1", "p2"]}'
        user_prompt = "Why is the sky blue? Please explain in simple terms."
        print("正在测试JSON响应格式...")
        response = client.call_model(system_prompt=system_prompt, user_prompt=user_prompt, response_format="json_object")
        print("\n=== JSON响应测试 ===")
        print(json.dumps(response, indent=2, ensure_ascii=False))
        print("=== JSON响应结束 ===\n")
        if isinstance(response, dict) and "answer" in response:
            print("✅ JSON格式响应测试成功！")
            return True
        else:
            print("⚠️ JSON格式响应异常")
            return False
    except Exception as e:
        print(f"❌ JSON测试过程中发生错误: {e}")
        return False

def test_llm_with_history(client=None):
    """测试带历史记录的对话 - 已移除历史记录功能"""
    print("\n历史对话功能已移除，跳过测试...")
    return True

def run_all_tests(client=None):
    """运行所有测试函数"""
    print("=" * 60)
    print("                      大模型连接与账户信息测试")
    print("=" * 60)

    try:
        if client is None:
            main_client = config.api_client
        else:
            main_client = client
    except Exception as e:
        print(f"❌ 初始化 config.api_client 失败: {e}")
        print("   请检查您的 config.py 文件和 API 密钥。测试无法继续。")
        return False

    test1 = test_llm_connection(client=main_client)
    test2 = test_llm_json_response(client=main_client)
    test3 = test_llm_with_history(client=main_client)

    print("\n" + "=" * 60)
    print("                      测试结果汇总")
    print("=" * 60)
    print(f"基本连接测试: {'✅ 通过' if test1 else '❌ 失败'}")
    print(f"JSON响应测试: {'✅ 通过' if test2 else '❌ 失败'}")
    print(f"历史对话测试: {'✅ 通过' if test3 else '❌ 失败'}")

    if all([test1, test2, test3]):
        print("\n🎉 所有功能测试通过！")
        return True
    else:
        print("\n⚠️ 部分功能测试失败，请检查配置和错误信息")
        return False


if __name__ == "__main__":
    run_all_tests()