# -*- coding: UTF-8 -*-
import httpx
from openai import OpenAI
# from llm_utils.config import config  # 延迟导入以避免循环导入
from llm_utils.utils import log_message, decode_unicode_string, load_json
import json
from abc import ABC, abstractmethod

class LLMClient(ABC):
    """LLM客户端抽象基类"""

    @abstractmethod
    def call_model(self, system_prompt, user_prompt, response_format="json_object", stream=False):
        """调用大模型API"""
        pass

    @abstractmethod
    def parse_response(self, response_content, response_format="json_object"):
        """解析大模型响应内容"""
        pass

    def _decode_response(self, response_data):
        """递归解码响应中的Unicode字符串，兼容列表与字典。"""

        def _decode(value):
            if isinstance(value, str):
                return decode_unicode_string(value)
            if isinstance(value, list):
                return [_decode(item) for item in value]
            if isinstance(value, dict):
                return {str(key): _decode(item) for key, item in value.items()}
            return value

        return _decode(response_data)

class APIClient(LLMClient):
    """OpenAI API 客户端 直接使用openai库"""

    API_KEY = ""
    BASE_URL = ""
    MODEL = "claude-sonnet-4-5-20250929"
    MAX_TOKENS = 32768

    '''
    MODEL LIST:
    claude-opus-4-5-20251101
    claude-sonnet-4-5-20250929
    gpt-5
    gemini-2.5-pro
    '''

    def __init__(self):
        super().__init__()
        self.client = OpenAI(
            api_key=self.API_KEY,
            base_url=self.BASE_URL
        )

    def get_client(self):
        """
        返回底层的 OpenAI 客户端实例。
        这个方法让外部函数可以安全地访问 client 对象，以调用其他功能。
        """
        return self.client

    def set_model(self, model_id):
        """动态设置当前使用的模型ID"""
        self.MODEL = model_id
        log_message(f"模型已更新为: {self.MODEL}")

    def parse_response(self, response_content, response_format="json_object"):
        """解析大模型响应内容"""
        # 解码Unicode字符串
        if response_format == "json_object":
            try:
                # 首先尝试直接解析
                response_data = json.loads(response_content)
                return self._decode_response(response_data)
            except json.JSONDecodeError:
                # 如果直接解析失败，尝试提取JSON内容
                try:
                    # 检查是否包含```json代码块
                    if "```json" in response_content and "```" in response_content:
                        # 提取```json和```之间的内容
                        json_start = response_content.find("```json") + 7
                        json_end = response_content.find("```", json_start)
                        if json_end > json_start:
                            response_content = response_content[json_start:json_end].strip()
                    
                    # 如果没有```json标记，尝试查找JSON对象
                    elif "{" in response_content and "}" in response_content:
                        start_idx = response_content.find("{")
                        end_idx = response_content.rfind("}")
                        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                            response_content = response_content[start_idx:end_idx + 1]
                    
                    response_data = json.loads(response_content)
                    return self._decode_response(response_data)
                except json.JSONDecodeError as e:
                    log_message(f"解析模型响应内容JSON失败: {e}")
                    log_message(f"响应内容: {response_content[:500]}...")
                    return {
                        "is_over": True,
                        "error": f"Invalid JSON in model response: {str(e)}"
                    }
        return response_content

    def call_model(self, system_prompt, user_prompt, response_format="json_object", stream=False):
        """调用大模型API（支持流式与非流式）直接使用OpenAI客户端"""
        log_message(f"\\n--- 正在向大模型发送{'流式' if stream else ''}请求 ---")

        try:
            # 检测是否为Claude模型
            is_claude = "claude" in self.MODEL.lower()

            # 构建消息
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]

            # 构建请求参数
            request_params = {
                "model": self.MODEL,
                "messages": messages,
                "temperature": 0.0,
                "max_completion_tokens": self.MAX_TOKENS
            }

            # 对于Claude模型，不使用response_format参数
            if not is_claude and response_format:
                request_params["response_format"] = {"type": response_format}

            if stream:
                request_params["stream"] = True
                request_params["stream_options"] = {"include_usage": True}

            # 调用API
            response = self.client.chat.completions.create(**request_params)

            full_content = ""
            p_tokens, c_tokens, t_tokens = 0, 0, 0

            if stream:
                for chunk in response:
                    if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                        full_content += chunk.choices[0].delta.content
                    
                    if hasattr(chunk, "usage") and chunk.usage:
                        if chunk.usage.total_tokens > 0:
                            p_tokens = getattr(chunk.usage, "prompt_tokens", 0)
                            c_tokens = getattr(chunk.usage, "completion_tokens", 0)
                            t_tokens = getattr(chunk.usage, "total_tokens", 0)
                
                log_message(f"流式响应完成，总长度: {len(full_content)}")
                if 'chunk' in locals() and chunk.choices:
                    log_message(f"结束原因：{chunk.choices[0].finish_reason}")
            else:
                full_content = response.choices[0].message.content
                if hasattr(response, "usage") and response.usage:
                    p_tokens = getattr(response.usage, "prompt_tokens", 0)
                    c_tokens = getattr(response.usage, "completion_tokens", 0)
                    t_tokens = getattr(response.usage, "total_tokens", 0)

            # 费率表：美元/百万token
            import os
            rates_file = os.path.join(os.path.dirname(__file__), "llm_rates.json")
            try:
                rates = load_json(rates_file)
                if not rates:
                    rates = {}
            except Exception:
                rates = {}
            
            rate_p, rate_c = 5.0, 15.0 # 默认价格
            for k, rv in rates.items():
                if k in self.MODEL.lower():
                    # 兼容之前可能只存一个tuple的情况
                    if isinstance(rv, (list, tuple)) and len(rv) >= 2:
                        rate_p, rate_c = rv[0], rv[1]
                    break
            cost = (p_tokens / 1e6) * rate_p + (c_tokens / 1e6) * rate_c

            self.last_token_usage = {
                "prompt_tokens": p_tokens,
                "completion_tokens": c_tokens,
                "total_tokens": t_tokens,
                "cost": cost
            }
            log_message(f"模型调用完成 (Token: Input={p_tokens}, Output={c_tokens}, Total={t_tokens}, Cost=${cost:.6f})")

            # 使用抽象方法解析响应
            parsed = self.parse_response(full_content, response_format)
            if isinstance(parsed, dict) and "error" not in parsed:
                parsed["__token_usage"] = self.last_token_usage
            return parsed

        except Exception as e:
            log_message(f"调用模型API时发生错误: {e}")
            return {
                "is_over": True,
                "error": str(e)
            }

    def call_model_streaming(self, system_prompt, user_prompt, response_format="json_object"):
        """【兼容保留】调用大模型API（流式响应）"""
        return self.call_model(system_prompt, user_prompt, response_format, stream=True)


