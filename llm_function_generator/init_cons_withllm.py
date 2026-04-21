# -*- coding: UTF-8 -*-
import os
import json
from pathlib import Path
from llm_utils.config import config
from llm_utils.utils import load_json, save_json, log_message, clean_llm_response_for_form_cons, PATTERN_DIR, SERVICES_DIR
from abc import ABC, abstractmethod

# 缓存辅助函数
def _load_cached_constraint(constraints_dir: Path, message_id: str, prefix: str = "form_cons") -> dict:
    """
    从缓存加载指定消息ID的约束描述
    
    Args:
        constraints_dir: 缓存目录
        message_id: 消息ID字符串
        prefix: 缓存文件前缀，默认为"form_cons"
        
    Returns:
        dict: 缓存的约束数据，如果不存在或无效则返回空dict
    """
    cache_file = constraints_dir / f"{prefix}_{message_id}.json"
    if not cache_file.exists():
        return {}
    
    try:
        cached_data = load_json(cache_file)
        if not isinstance(cached_data, dict):
            log_message(f"警告：缓存文件 {cache_file} 格式无效")
            return {}
        
        # 检查必要字段
        # 注意：不再强制检查form_constraint字段，因为不同的策略可能存储不同的结构
        # 但我们仍然期望基本的message_id匹配
        
        # 验证消息ID匹配
        if str(cached_data.get("message_id")) != str(message_id):
            log_message(f"警告：缓存文件 {cache_file} 消息ID不匹配")
            return {}
        
        # 尝试获取约束数据，优先查找form_constraint
        form_constraint = cached_data.get("form_constraint")
        
        # 如果没有form_constraint，尝试直接返回除metadata外的所有数据
        if not form_constraint:
            # 对于某些策略，整个JSON可能就是约束数据（或者包含在其他字段中）
            # 这里做一个兼容性处理：如果存在stageX字段，则认为是一个CoT结果
            if any(k.startswith("stage") for k in cached_data.keys()):
                return cached_data
                
            # 或者如果是简化的JSON输出模式
            if "header_constraints" in cached_data or "body_constraints" in cached_data:
                return cached_data
                
            log_message(f"警告：缓存文件 {cache_file} 结构无法识别")
            return {}
        
        if not isinstance(form_constraint, dict):
            log_message(f"警告：缓存文件 {cache_file} 的form_constraint字段无效")
            return {}
        
        if "__token_usage" not in form_constraint:
            form_constraint["__token_usage"] = cached_data.get("token_usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cost": 0.0})
        log_message(f"成功从缓存加载消息ID {message_id} 的约束数据")
        return form_constraint
        
    except Exception as exc:
        log_message(f"读取缓存文件 {cache_file} 失败: {exc}")
        return {}


def _save_constraint_to_cache(constraints_dir: Path, message_id: str, form_constraint: dict, prefix: str = "form_cons") -> bool:
    """
    将约束描述保存到缓存文件
    
    Args:
        constraints_dir: 缓存目录
        message_id: 消息ID字符串
        form_constraint: 约束描述数据
        prefix: 缓存文件前缀，默认为"form_cons"
        
    Returns:
        bool: 保存成功返回True
    """
    from datetime import datetime
    
    cache_file = constraints_dir / f"{prefix}_{message_id}.json"
    
    # 构造缓存payload
    # 如果form_constraint本身已经包含message_id，我们就不再包装它，或者我们统一包装
    # 为了保持一致性，我们总是包装一层，但对于直接返回结果的策略，我们需要小心处理
    
    token_usage = form_constraint.pop("__token_usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cost": 0.0})
    if "__token_usage" not in form_constraint:
        form_constraint["__token_usage"] = token_usage
        
    cache_payload = {
        "message_id": message_id,
        "form_constraint": form_constraint,
        "token_usage": token_usage,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # 对于CoT策略，如果result已经是完整的分析结果，我们可能想要把它们展平或者保留原样
    # 这里我们保持统一的 {message_id, form_constraint, ...} 结构
    # 但在读取时会做兼容处理
    
    # 如果form_constraint确实是一个简单的dict（没有嵌套太深），我们可以直接保存
    # 但如果它是CoT的一系列stage，保存为form_constraint字段也是合理的
    
    success = save_json(cache_payload, cache_file)
    if success:
        log_message(f"已保存消息ID {message_id} 的约束到缓存: {cache_file}")
    else:
        log_message(f"警告：保存缓存文件失败: {cache_file}")
    
    return success


def _get_cache_stats(constraints_dir: Path, prefix: str = "form_cons") -> dict:
    """
    获取缓存统计信息
    
    Args:
        constraints_dir: 缓存目录
        prefix: 缓存文件前缀，默认为"form_cons"
        
    Returns:
        dict: 包含缓存统计信息的字典
    """
    if not constraints_dir.exists():
        return {"total_cache_files": 0, "valid_cache_files": 0, "invalid_cache_files": 0}
    
    cache_files = list(constraints_dir.glob(f"{prefix}_*.json"))
    total_files = len(cache_files)
    valid_files = 0
    invalid_files = 0
    
    for cache_file in cache_files:
        try:
            cached_data = load_json(cache_file)
            if isinstance(cached_data, dict) and "message_id" in cached_data:
                valid_files += 1
            else:
                invalid_files += 1
        except Exception:
            invalid_files += 1
    
    return {
        "total_cache_files": total_files,
        "valid_cache_files": valid_files,
        "invalid_cache_files": invalid_files
    }


class FormConsGenerationStrategy(ABC):
    """
    表单约束生成的策略基类
    """
    
    def __init__(self, use_english_prompts: bool = False):
        self.use_english_prompts = use_english_prompts
        self.api_client = config.api_client
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """获取系统提示词"""
        pass
    
    @abstractmethod
    def get_user_prompt_template(self) -> str:
        """获取用户提示词模板"""
        pass
    
    @abstractmethod
    def should_process_function(self, function: dict) -> bool:
        """判断是否应该处理这个函数"""
        pass
    
    @abstractmethod
    def call_llm_and_process_response(self, message_id: int, function_name: str, 
                                    pseudocode: str, handle_function_pseudocode: str, 
                                    service_name: str) -> dict:
        """调用LLM并处理响应"""
        pass
    
    def prepare_additional_data(self) -> dict:
        """准备额外的上下文数据（可选）"""
        return {}
        
    def get_output_filename(self) -> str:
        """获取输出文件名"""
        return "form_cons.json"

    def get_cache_prefix(self) -> str:
        """获取缓存文件前缀"""
        return "form_cons"

    def get_cache_dir_name(self) -> str:
        """获取缓存目录名"""
        return "constraints"



class BasicFormConsStrategy(FormConsGenerationStrategy):
    """基本表单约束生成策略"""
    
    def get_system_prompt(self) -> str:
        return config.SYSTEM_MSG_FORM_CONS_EN if self.use_english_prompts else config.SYSTEM_MSG_FORM_CONS
    
    def get_user_prompt_template(self) -> str:
        return config.USER_MSG_SINGLE_MESSAGE_FULL_EN if self.use_english_prompts else config.USER_MSG_SINGLE_MESSAGE_FULL
    
    def should_process_function(self, function: dict) -> bool:
        return function.get("message_id") is not None and function.get("pseudocode")
    
    def call_llm_and_process_response(self, message_id: int, function_name: str, 
                                    pseudocode: str, handle_function_pseudocode: str, 
                                    service_name: str) -> dict:
        # 基本策略使用包含处理函数的完整模板
        template = self.get_user_prompt_template()
        single_message_prompt = template.format(
            message_id=message_id,
            function_name=function_name,
            pseudocode=pseudocode,
            handle_function_pseudocode=handle_function_pseudocode
        )
        
        # 调用LLM
        response = self.api_client.call_model_with_history(
            system_prompt=self.get_system_prompt(),
            user_prompt=single_message_prompt,
            response_format="json_object"
        )
        
        return self._parse_response(response, message_id)
    
    def _parse_response(self, response, message_id):
        """解析LLM响应"""
        if not response or not isinstance(response, dict):
            return {}
        
        message_id_str = str(message_id)
        
        # 尝试不同的键格式
        if message_id_str in response:
            return response[message_id_str]
        elif message_id in response:
            return response[message_id]
        elif "total_size" in response and "is_ool" in response:
            return response
        
        return {}


class OneshotFormConsStrategy(FormConsGenerationStrategy):
    """Oneshot表单约束生成策略"""
    
    def __init__(self, use_english_prompts: bool = False):
        super().__init__(use_english_prompts)
        self.example_data = self._load_example_data()
    
    def _load_example_data(self) -> tuple:
        """加载示例数据"""
        sample_mig_file = Path("services/sample/mig_functions.json")
        sample_cons_file = Path("services/sample/form_cons.json")
        
        sample_mig_data = load_json(sample_mig_file) if sample_mig_file.exists() else {}
        sample_cons_data = load_json(sample_cons_file) if sample_cons_file.exists() else {}
        
        return sample_mig_data, sample_cons_data
    
    def get_system_prompt(self) -> str:
        system_prompt = config.SYSTEM_MSG_STRICT_CONS_ONESHOT_EN if self.use_english_prompts else config.SYSTEM_MSG_STRICT_CONS_ONESHOT
        
        # 添加示例数据
        sample_mig_data, sample_cons_data = self.example_data
        if sample_mig_data and sample_cons_data:
            example_mig_functions = json.dumps(sample_mig_data, indent=2, ensure_ascii=False)
            example_form_cons = json.dumps(sample_cons_data, indent=2, ensure_ascii=False)
            
            if self.use_english_prompts:
                system_prompt += "\n\n**Example MIG function data:**\n```json\n" + example_mig_functions + "\n```\n\n**Example generated strict constraint descriptions:**\n```json\n" + example_form_cons + "\n```"
            else:
                system_prompt += "\n\n**示例MIG函数数据：**\n```json\n" + example_mig_functions + "\n```\n\n**示例生成的严格约束描述：**\n```json\n" + example_form_cons + "\n```"
        
        return system_prompt
    
    def get_user_prompt_template(self) -> str:
        return config.USER_MSG_STRICT_CONS_ONESHOT_EN if self.use_english_prompts else config.USER_MSG_STRICT_CONS_ONESHOT
    
    def should_process_function(self, function: dict) -> bool:
        return (function.get("message_id") is not None and 
                function.get("pseudocode") and 
                function.get("handle_function_pseudocode"))
    
    def call_llm_and_process_response(self, message_id: int, function_name: str, 
                                    pseudocode: str, handle_function_pseudocode: str, 
                                    service_name: str) -> dict:
        user_prompt = self.get_user_prompt_template().format(
            service_name=service_name,
            message_id=message_id,
            function_name=function_name,
            pseudocode=pseudocode,
            handle_function_pseudocode=handle_function_pseudocode
        )
        
        response = self.api_client.call_model(
            system_prompt=self.get_system_prompt(),
            user_prompt=user_prompt,
            response_format="json_object"
        )
        
        return self._parse_response(response, message_id)
    
    def _parse_response(self, response, message_id):
        """解析LLM响应"""
        if not response or not isinstance(response, dict):
            return {}
        
        message_id_str = str(message_id)
        
        # 尝试不同的键格式
        if message_id_str in response:
            return response[message_id_str]
        elif message_id in response:
            return response[message_id]
        elif "header" in response and "body" in response:
            return response
        
        return {}


class TwostageFormConsStrategy(FormConsGenerationStrategy):
    """两阶段表单约束生成策略"""
    
    def get_system_prompt(self) -> str:
        # 两阶段策略不需要系统提示词，在各阶段单独定义
        return ""
    
    def get_user_prompt_template(self) -> str:
        # 两阶段策略不需要用户提示词模板，在各阶段单独定义
        return ""
    
    def should_process_function(self, function: dict) -> bool:
        return (function.get("message_id") is not None and 
                function.get("pseudocode") and 
                function.get("handle_function_pseudocode"))
    
    def call_llm_and_process_response(self, message_id: int, function_name: str, 
                                    pseudocode: str, handle_function_pseudocode: str, 
                                    service_name: str) -> dict:
        # 第一阶段：分析header和descriptor
        stage1_result = self._call_stage1(message_id, function_name, pseudocode)
        if not stage1_result:
            return {}
        
        # 计算body偏移量
        body_offset = self._calculate_body_offset(stage1_result)
        
        # 第二阶段：分析body和trailer
        stage2_result = self._call_stage2(message_id, function_name, pseudocode, 
                                        handle_function_pseudocode, body_offset, stage1_result)
        if not stage2_result:
            return {}
        
        # 整合结果
        return self._merge_results(stage1_result, stage2_result)
    
    def _call_stage1(self, message_id, function_name, pseudocode):
        """第一阶段调用"""
        system_prompt = config.SYSTEM_MSG_STRICT_CONS_STAGE1_EN if self.use_english_prompts else config.SYSTEM_MSG_STRICT_CONS_STAGE1
        user_template = config.USER_MSG_STRICT_CONS_STAGE1_EN if self.use_english_prompts else config.USER_MSG_STRICT_CONS_STAGE1
        
        user_prompt = user_template.format(
            message_id=message_id,
            function_name=function_name,
            pseudocode=pseudocode
        )
        
        response = self.api_client.call_model(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format="json_object"
        )
        
        if not response or not isinstance(response, dict):
            return {}
        
        # 提取结果
        message_id_str = str(message_id)
        if message_id_str in response:
            return response[message_id_str]
        elif message_id in response:
            return response[message_id]
        elif "header" in response and "descriptor_section" in response:
            return response
        
        return {}
    
    def _calculate_body_offset(self, stage1_result):
        """计算body起始偏移"""
        body_offset = 24  # header固定24字节
        
        descriptor_section = stage1_result.get("descriptor_section", {})
        if descriptor_section and descriptor_section.get("offset") not in ["不存在", "does_not_exist"]:
            descriptor_size = descriptor_section.get("size", 0)
            if isinstance(descriptor_size, (int, float)):
                body_offset += descriptor_size
        
        return body_offset
    
    def _call_stage2(self, message_id, function_name, pseudocode, handle_function_pseudocode, body_offset, stage1_result):
        """第二阶段调用"""
        system_prompt = config.SYSTEM_MSG_STRICT_CONS_STAGE2_EN if self.use_english_prompts else config.SYSTEM_MSG_STRICT_CONS_STAGE2
        user_template = config.USER_MSG_STRICT_CONS_STAGE2_EN if self.use_english_prompts else config.USER_MSG_STRICT_CONS_STAGE2
        
        stage1_variables = stage1_result.get("variables", {})
        stage1_variables_str = json.dumps(stage1_variables, indent=2, ensure_ascii=False) if stage1_variables else "无"
        
        user_prompt = user_template.format(
            message_id=message_id,
            function_name=function_name,
            pseudocode=pseudocode,
            handle_function_pseudocode=handle_function_pseudocode,
            body_offset=body_offset,
            stage1_variables=stage1_variables_str
        )
        
        response = self.api_client.call_model(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format="json_object"
        )
        
        if not response or not isinstance(response, dict):
            return {}
        
        # 提取结果
        message_id_str = str(message_id)
        if message_id_str in response:
            return response[message_id_str]
        elif message_id in response:
            return response[message_id]
        elif "body" in response and "trailer" in response:
            return response
        
        return {}
    
    def _merge_results(self, stage1_result, stage2_result):
        """整合两阶段结果"""
        final_result = {
            "total_size": stage1_result.get("total_size", "待定"),
            "is_ool": stage1_result.get("is_ool", False),
            "header": stage1_result.get("header", {}),
            "descriptor_section": stage1_result.get("descriptor_section", {}),
            "body": stage2_result.get("body", {}),
            "trailer": stage2_result.get("trailer", {})
        }
        
        # 整合variables字段
        stage1_vars = stage1_result.get("variables", {})
        stage2_vars = stage2_result.get("variables", {})
        
        if stage2_vars:
            final_result["variables"] = stage2_vars
        elif stage1_vars:
            final_result["variables"] = stage1_vars
        
        return final_result


class NoTaskDepFormConsStrategy(FormConsGenerationStrategy):
    """思维链表单约束生成策略"""
    
    def __init__(self, use_english_prompts: bool = False):
        super().__init__(use_english_prompts)
        self.example_content = self._load_example_content()
    
    def _load_example_content(self) -> tuple:
        """加载示例内容"""
        pattern_dir = PATTERN_DIR
        des_example_file = pattern_dir / "form_cons_notaskdep_des.json"
        nodes_example_file = pattern_dir / "form_cons_notaskdep_nodes.json"
        
        des_content = ""
        if des_example_file.exists():
            try:
                with open(des_example_file, 'r', encoding='utf-8') as f:
                    des_content = f.read().strip()
            except Exception as e:
                log_message(f"警告：加载描述符示例文件失败: {e}")
        
        nodes_content = ""
        if nodes_example_file.exists():
            try:
                with open(nodes_example_file, 'r', encoding='utf-8') as f:
                    nodes_content = f.read().strip()
            except Exception as e:
                log_message(f"警告：加载无描述符示例文件失败: {e}")
        
        return des_content, nodes_content
    
    def get_output_filename(self) -> str:
        return "form_cons_notaskdep.json"
    
    def get_cache_prefix(self) -> str:
        return "form_cons_notaskdep"
    
    def get_cache_dir_name(self) -> str:
        return "constraints_notaskdep"
    
    def get_system_prompt(self) -> str:
        system_prompt = config.SYSTEM_MSG_NO_TASKDEP_CONS_EN if self.use_english_prompts else config.SYSTEM_MSG_NO_TASKDEP_CONS
        
        # 添加示例
        des_content, nodes_content = self.example_content
        if self.use_english_prompts:
            if des_content:
                system_prompt += "\n\n**Example with descriptors:**\n```json\n" + des_content + "\n```"
            if nodes_content:
                system_prompt += "\n\n**Example without descriptors:**\n```json\n" + nodes_content + "\n```"
        else:
            if des_content:
                system_prompt += "\n\n**含描述符示例：**\n```json\n" + des_content + "\n```"
            if nodes_content:
                system_prompt += "\n\n**不含描述符示例：**\n```json\n" + nodes_content + "\n```"
        
        return system_prompt
    
    def get_user_prompt_template(self) -> str:
        return config.USER_MSG_NO_TASKDEP_CONS_EN if self.use_english_prompts else config.USER_MSG_NO_TASKDEP_CONS
    
    def should_process_function(self, function: dict) -> bool:
        return (function.get("message_id") is not None and 
                function.get("pseudocode"))
    
    def call_llm_and_process_response(self, message_id: int, function_name: str, 
                                    pseudocode: str, handle_function_pseudocode: str, 
                                    service_name: str) -> dict:
        user_prompt = self.get_user_prompt_template().format(
            service_name=service_name,
            message_id=message_id,
            function_name=function_name,
            pseudocode=pseudocode,
            handle_function_pseudocode=handle_function_pseudocode
        )
        
        # response = self.api_client.call_model(
        #     system_prompt=self.get_system_prompt(),
        #     user_prompt=user_prompt,
        #     response_format="json_object"
        # )

        response = self.api_client.call_model_streaming(
            system_prompt=self.get_system_prompt(),
            user_prompt=user_prompt,
            response_format="json_object"
        )
        
        return self._parse_response(response, message_id)
    
    def _parse_response(self, response, message_id):
        """解析LLM响应"""
        if isinstance(response, dict) and "error" in response:
            return {}
        
        if not response or not isinstance(response, dict):
            return {}
        
        # 尝试剥离外层的message_id（如果存在）
        message_id_str = str(message_id)
        if message_id_str in response and isinstance(response[message_id_str], dict):
            # 检查剥离后的内容是否看起来像有效数据
            inner_data = response[message_id_str]
            if ("header_constraints" in inner_data or 
                "body_constraints" in inner_data or
                "variable_identification" in inner_data):
                response = inner_data
        
        # LLM现在直接返回分析结果，不再包含message_id包装
        # 对于非4步CoT策略，也可能返回stage字段
        if (("variable_identification" in response and 
             "structure_location" in response and 
             "constraint_extraction" in response) or
            ("stage1_variable_identification" in response or 
             "stage2_header_analysis" in response or 
             "stage3_structure_location" in response or 
             "stage4_constraint_extraction" in response) or
            ("header_constraints" in response and
             "body_constraints" in response)):
            return response
        
        return {}
    
class NoCotFormConsStrategy(FormConsGenerationStrategy):
    """无思维链表单约束生成策略"""

    def __init__(self, use_english_prompts: bool = False):
        super().__init__(use_english_prompts)
        self.example_content = self._load_example_content()
    
    def _load_example_content(self) -> tuple:
        """加载示例内容"""
        pattern_dir = PATTERN_DIR
        des_example_file = pattern_dir / "form_cons_no_cot_des.json"
        nodes_example_file = pattern_dir / "form_cons_no_cot_nodes.json"
        
        des_content = ""
        if des_example_file.exists():
            try:
                with open(des_example_file, 'r', encoding='utf-8') as f:
                    des_content = f.read().strip()
            except Exception as e:
                log_message(f"警告：加载描述符示例文件失败: {e}")
        
        nodes_content = ""
        if nodes_example_file.exists():
            try:
                with open(nodes_example_file, 'r', encoding='utf-8') as f:
                    nodes_content = f.read().strip()
            except Exception as e:
                log_message(f"警告：加载无描述符示例文件失败: {e}")
        
        return des_content, nodes_content
    
    def get_output_filename(self) -> str:
        return "form_cons_no_cot.json"
    
    def get_cache_prefix(self) -> str:
        return "form_cons_no_cot"
    
    def get_cache_dir_name(self) -> str:
        return "constraints_no_cot"
    
    def get_system_prompt(self) -> str:
        system_prompt = config.SYSTEM_MSG_NO_COT_CONS_EN if self.use_english_prompts else config.SYSTEM_MSG_NO_COT_CONS

        # 添加示例
        des_content, nodes_content = self.example_content
        if self.use_english_prompts:
            if des_content:
                system_prompt += "\n\n**Example with descriptors:**\n```json\n" + des_content + "\n```"
            if nodes_content:
                system_prompt += "\n\n**Example without descriptors:**\n```json\n" + nodes_content + "\n```"
        else:
            if des_content:
                system_prompt += "\n\n**含描述符示例：**\n```json\n" + des_content + "\n```"
            if nodes_content:
                system_prompt += "\n\n**不含描述符示例：**\n```json\n" + nodes_content + "\n```"
        
        return system_prompt
    
    def get_user_prompt_template(self) -> str:
        return config.USER_MSG_NO_COT_CONS_EN if self.use_english_prompts else config.USER_MSG_NO_COT_CONS
    
    def should_process_function(self, function: dict) -> bool:
        return (function.get("message_id") is not None and 
                function.get("pseudocode") is not None and
                function.get("handle_function_pseudocode") is not None)
    
    def call_llm_and_process_response(self, message_id: int, function_name: str, 
                                    pseudocode: str, handle_function_pseudocode: str, 
                                    service_name: str) -> dict:
        user_prompt = self.get_user_prompt_template().format(
            service_name=service_name,
            message_id=message_id,
            function_name=function_name,
            pseudocode=pseudocode,
            handle_function_pseudocode=handle_function_pseudocode
        )
        
        response = self.api_client.call_model_streaming(
            system_prompt=self.get_system_prompt(),
            user_prompt=user_prompt,
            response_format="json_object"
        )
        
        return self._parse_response(response, message_id)
    
    def _parse_response(self, response, message_id):
        """解析LLM响应"""
        if isinstance(response, dict) and "error" in response:
            return {}
        
        if not response or not isinstance(response, dict):
            return {}
        
        # 尝试剥离外层的message_id（如果存在）
        message_id_str = str(message_id)
        if message_id_str in response and isinstance(response[message_id_str], dict):
            response = response[message_id_str]
        
        # 检查是否包含预期的字段
        if ("stage1_variable_identification" in response or 
             "stage2_header_analysis" in response or 
             "stage3_structure_location" in response or 
             "stage4_constraint_extraction" in response):
            return response
            
        return {}

def generate_form_cons_base(service_name: str, strategy: FormConsGenerationStrategy, use_cache: bool = True) -> bool:
    """
    通用的表单约束生成函数
    
    Args:
        service_name: 服务名称
        strategy: 生成策略
        use_cache: 是否使用缓存
        
    Returns:
        bool: 成功返回True
    """
    log_message(f"--- 开始为服务 {service_name} 生成结构化约束描述文件 ---")
    log_message(f"配置参数: use_cache={use_cache}")
    
    try:
        # 检查服务目录和必要文件
        service_dir = SERVICES_DIR / service_name
        if not service_dir.exists():
            # 尝试查找other_mig_services
            other_dir = SERVICES_DIR.parent / "other_mig_services" / service_name
            if other_dir.exists():
                service_dir = other_dir
        
        mig_functions_file = service_dir / "mig_functions.json"
        
        if not mig_functions_file.exists():
            log_message(f"错误：MIG函数文件不存在 '{mig_functions_file}'")
            return False
        
        # 加载数据
        service_data = load_json(mig_functions_file)
        if not service_data:
            log_message("错误：无法加载MIG函数数据文件")
            return False
        
        log_message(f"正在处理服务: {service_name}")
        
        # 初始化缓存相关变量
        constraints_dir = service_dir / strategy.get_cache_dir_name()
        constraints_dir.mkdir(exist_ok=True)
        log_message(f"缓存目录: {constraints_dir}")
        
        all_constraints = {}
        cache_hits = 0
        cache_misses = 0
        
        # 遍历所有子系统
        for subsystem in service_data.get("subsystems", []):
            for function in subsystem.get("functions", []):
                message_id = function.get("message_id")
                pseudocode = function.get("pseudocode")
                handle_function_pseudocode = function.get("handle_function_pseudocode", "")
                function_name = function.get("name", "")
                
                if not strategy.should_process_function(function):
                    if message_id is not None:
                        if not pseudocode:
                            log_message(f"跳过 Message ID: {message_id}，缺少主函数伪代码")
                        elif not handle_function_pseudocode:
                            log_message(f"跳过 Message ID: {message_id}，缺少处理函数伪代码")
                    continue
                
                message_id_str = str(message_id)
                
                # 检查缓存
                if use_cache:
                    cached_constraint = _load_cached_constraint(constraints_dir, message_id_str, prefix=strategy.get_cache_prefix())
                    if cached_constraint:
                        all_constraints[message_id_str] = cached_constraint
                        cache_hits += 1
                        log_message(f"使用缓存的约束: Message ID {message_id}")
                        continue
                
                cache_misses += 1
                log_message(f"正在处理 Message ID: {message_id}")
                
                # 调用策略生成约束
                constraint = strategy.call_llm_and_process_response(
                    message_id, function_name, pseudocode, handle_function_pseudocode, service_name
                )
                
                if constraint:
                    # 保存约束
                    all_constraints[message_id_str] = constraint
                    log_message(f"成功生成 Message ID {message_id} 的约束描述")
                    
                    # 保存到缓存
                    _save_constraint_to_cache(constraints_dir, message_id_str, constraint, prefix=strategy.get_cache_prefix())
                else:
                    log_message(f"错误：Message ID {message_id} 生成约束失败")
        
        # 输出缓存统计信息
        total_processed = cache_hits + cache_misses
        if total_processed > 0:
            hit_rate = (cache_hits / total_processed) * 100
            log_message(f"缓存统计: 总处理 {total_processed} 个消息ID，缓存命中 {cache_hits} 个，缓存未命中 {cache_misses} 个，命中率 {hit_rate:.1f}%")
        
        # 获取缓存目录统计
        cache_stats = _get_cache_stats(constraints_dir, prefix=strategy.get_cache_prefix())
        log_message(f"缓存文件统计: 总缓存文件 {cache_stats['total_cache_files']} 个，有效 {cache_stats['valid_cache_files']} 个，无效 {cache_stats['invalid_cache_files']} 个")
        
        # 保存结果
        output_file = service_dir / strategy.get_output_filename()
        
        # 汇总所有token和金额
        total_tokens_all = 0
        total_cost_all = 0.0
        
        for msg_id, cons in all_constraints.items():
            if isinstance(cons, dict) and "__token_usage" in cons:
                usage = cons.get("__token_usage", {})
                total_tokens_all += usage.get("total_tokens", 0)
                total_cost_all += usage.get("cost", 0.0)
            elif isinstance(cons, dict) and "token_usage" in cons:
                usage = cons.get("token_usage", {})
                total_tokens_all += usage.get("total_tokens", 0)
                total_cost_all += usage.get("cost", 0.0)
                
        # 对于CoT策略，需要清理思维链内容
        if isinstance(strategy, NoTaskDepFormConsStrategy) or isinstance(strategy, CotFormCons4StepStrategy):
            cleaned_constraints = clean_llm_response_for_form_cons(all_constraints)
            
            final_data = {
                "constraints": cleaned_constraints,
                "summary": {
                    "total_tokens": total_tokens_all,
                    "total_cost": total_cost_all
                }
            }
            success = save_json(final_data, output_file)
            if success:
                log_message(f"清理后CoT约束描述文件已保存到: {output_file}")
            else:
                log_message(f"错误：保存清理后CoT约束描述文件失败 {output_file}")
                return False
        else:
            final_data = {
                "constraints": all_constraints,
                "summary": {
                    "total_tokens": total_tokens_all,
                    "total_cost": total_cost_all
                }
            }
            success = save_json(final_data, output_file)
            if not success:
                log_message(f"错误：保存约束描述文件失败 {output_file}")
                return False
        
        log_message(f"--- 服务 {service_name} 约束描述生成完毕，共生成 {len(all_constraints)} 个约束描述 ---")
        return True
        
    except Exception as e:
        log_message(f"错误：生成过程中发生异常: {e}")
        return False

# TODO 把APIClient作为参数传入

# 重构后的接口函数

def generate_form_cons(service_name, include_handle_function=False, keep_conversation_history=True, use_english_prompts=False, use_cache=True):
    """
    为指定服务生成结构化约束描述文件 form_cons.json
    采用分多次询问大模型的方式，然后整合结果
    
    Args:
        service_name (str): 服务名称，如 "com.apple.bsd.dirhelper"
        include_handle_function (bool): 是否包含处理函数伪代码，默认为False
        keep_conversation_history (bool): 是否保持对话历史，默认为True
        use_english_prompts (bool): 是否使用英文提示词，默认为False（使用中文）
        use_cache (bool): 是否使用缓存，默认为True
        
    Returns:
        bool: 成功返回True，失败返回False
    """
    # 注意：include_handle_function和keep_conversation_history参数为了向后兼容而保留
    # 但在新的实现中，这些参数的影响已经整合到策略中
    strategy = BasicFormConsStrategy(use_english_prompts=use_english_prompts)
    return generate_form_cons_base(service_name, strategy, use_cache=use_cache)


def generate_form_cons_oneshot(service_name, use_english_prompts=False, use_cache=True):
    """
    使用oneshot示例学习模式为指定服务生成严格的结构化约束描述文件 form_cons.json
    使用services/sample的mig_functions.json和form_cons.json作为示例，让LLM学习后逐个消息ID生成约束
    
    Args:
        service_name (str): 服务名称，如 "com.apple.bsd.dirhelper"
        use_english_prompts (bool): 是否使用英文提示词，默认为False（使用中文）
        use_cache (bool): 是否使用缓存，默认为True
        
    Returns:
        bool: 成功返回True，失败返回False
    """
    strategy = OneshotFormConsStrategy(use_english_prompts=use_english_prompts)
    return generate_form_cons_base(service_name, strategy, use_cache=use_cache)


def generate_form_cons_twostage(service_name, use_english_prompts=False, use_cache=True):
    """
    使用两阶段分析模式为指定服务生成严格的结构化约束描述文件 form_cons.json
    1. 第一阶段：基于主函数伪代码生成header和descriptor约束
    2. 第二阶段：基于处理函数伪代码生成body和trailer约束，并完善msg_size
    
    Args:
        service_name (str): 服务名称，如 "com.apple.bsd.dirhelper"
        use_english_prompts (bool): 是否使用英文提示词，默认为False（使用中文）
        use_cache (bool): 是否使用缓存，默认为True
        
    Returns:
        bool: 成功返回True，失败返回False
    """
    strategy = TwostageFormConsStrategy(use_english_prompts=use_english_prompts)
    return generate_form_cons_base(service_name, strategy, use_cache=use_cache)


def generate_form_cons_no_task_dep(service_name, use_english_prompts=False, use_cache=True):
    """
    使用思维链(Chain of Thought)分析模式为指定服务生成结构化约束描述文件 form_cons.json
    采用深度分析的思维链方法，系统性地分析变量识别、结构定位和约束提取
    
    Args:
        service_name (str): 服务名称，如 "com.apple.bsd.dirhelper"
        use_english_prompts (bool): 是否使用英文提示词，默认为False（使用中文）
        use_cache (bool): 是否读取/写入缓存，默认为True
        
    Returns:
        bool: 成功返回True，失败返回False
    """
    strategy = NoTaskDepFormConsStrategy(use_english_prompts=use_english_prompts)
    return generate_form_cons_base(service_name, strategy, use_cache=use_cache)


class CotFormCons4StepStrategy(FormConsGenerationStrategy):
    """4步思维链表单约束生成策略 - 增量分析避免超时"""
    
    def __init__(self, use_english_prompts: bool = False):
        super().__init__(use_english_prompts)
        self.example_content = self._load_example_content()
    
    def _load_example_content(self) -> tuple:
        """加载示例内容"""
        pattern_dir = PATTERN_DIR
        des_example_file = pattern_dir / "form_cons_cot_des.json"
        nodes_example_file = pattern_dir / "form_cons_cot_nodes.json"
        
        des_content = ""
        if des_example_file.exists():
            try:
                with open(des_example_file, 'r', encoding='utf-8') as f:
                    des_content = f.read().strip()
            except Exception as e:
                log_message(f"警告：加载描述符示例文件失败: {e}")
        
        nodes_content = ""
        if nodes_example_file.exists():
            try:
                with open(nodes_example_file, 'r', encoding='utf-8') as f:
                    nodes_content = f.read().strip()
            except Exception as e:
                log_message(f"警告：加载无描述符示例文件失败: {e}")
        
        return des_content, nodes_content
    
    def get_system_prompt(self, step: int) -> str:
        """根据步骤获取系统提示词"""
        base_prompt = config.SYSTEM_MSG_COT_CONS_EN if self.use_english_prompts else config.SYSTEM_MSG_COT_CONS
        
        # 根据步骤调整系统提示词
        if self.use_english_prompts:
            step_instructions = {
                1: "\n\n**Step 1: Variable Identification**\nFocus ONLY on identifying and analyzing the variables used in the message structure. Do not analyze structure location or constraints yet.",
                2: "\n\n**Step 2: Header Analysis**\nBased on the variable identification from Step 1, analyze the message header structure and field positioning.",
                3: "\n\n**Step 3: Structure Positioning**\nBased on previous analysis, determine the exact positioning and layout of data structures within the message.",
                4: "\n\n**Step 4: Constraint Extraction**\nBased on all previous analysis, extract the final constraints and validation rules."
            }
        else:
            step_instructions = {
                1: "\n\n**第一步：变量识别**\n仅专注于识别和分析消息结构中使用的变量。暂时不要分析结构位置或约束。",
                2: "\n\n**第二步：头部分析**\n基于第一步的变量识别结果，分析消息头结构和字段定位。",
                3: "\n\n**第三步：结构定位**\n基于之前的分析，确定数据结构在消息中的确切位置和布局。",
                4: "\n\n**第四步：约束提取**\n基于所有之前的分析，提取最终的约束和验证规则。"
            }
        
        system_prompt = base_prompt + step_instructions.get(step, "")
        
        # 添加示例（仅在最后一步）
        if step == 4:
            des_content, nodes_content = self.example_content
            if self.use_english_prompts:
                if des_content:
                    system_prompt += "\n\n**Example with descriptors:**\n```json\n" + des_content + "\n```"
                if nodes_content:
                    system_prompt += "\n\n**Example without descriptors:**\n```json\n" + nodes_content + "\n```"
            else:
                if des_content:
                    system_prompt += "\n\n**含描述符示例：**\n```json\n" + des_content + "\n```"
                if nodes_content:
                    system_prompt += "\n\n**不含描述符示例：**\n```json\n" + nodes_content + "\n```"
        
        return system_prompt
    
    def get_user_prompt_template(self, step: int) -> str:
        """根据步骤获取用户提示词模板"""
        base_template = config.USER_MSG_COT_CONS_EN if self.use_english_prompts else config.USER_MSG_COT_CONS
        
        # 为不同步骤调整提示词，支持对话历史
        if self.use_english_prompts:
            step_adjustments = {
                1: "\n\n**Task: Step 1 - Variable Identification Only**\nAnalyze the provided pseudocode and identify all variables used in the message structure. Focus on:\n- Variable names and types\n- How variables are declared and used\n- Relationships between variables\n\nProvide your analysis in JSON format with ONLY the stage1_variable_identification field.",
                2: "\n\n**Task: Step 2 - Header Analysis**\nBased on the variable identification from Step 1:\n{step1_result}\n\nNow analyze the message header structure and field positioning.\n\nProvide your analysis in JSON format with ONLY the stage2_header_analysis field.",
                3: "\n\n**Task: Step 3 - Structure Positioning**\nBased on previous analysis:\n{step1_result}\n{step2_result}\n\nDetermine the exact positioning and layout of data structures.\n\nProvide your analysis in JSON format with ONLY the stage3_structure_location field.",
                4: "\n\n**Task: Step 4 - Final Constraint Extraction**\nBased on all previous analysis:\n{step1_result}\n{step2_result}\n{step3_result}\n\nExtract the final constraints and validation rules.\n\nProvide complete analysis in the standard format with ONLY the stage4_constraint_extraction field."
            }
        else:
            step_adjustments = {
                1: "\n\n**任务：第一步 - 仅变量识别**\n分析提供的伪代码，识别消息结构中使用的所有变量。请以只包含stage1_variable_identification部分内容的JSON格式提供分析。",
                2: "\n\n**任务：第二步 - 头部分析**\n基于第一步的变量识别结果：\n{step1_result}\n\n现在分析消息头结构和字段定位。\n\n请以只包含stage2_header_analysis字段的JSON格式提供分析。",
                3: "\n\n**任务：第三步 - 结构定位**\n基于之前的分析：\n{step1_result}\n{step2_result}\n\n确定数据结构的确切位置和布局。\n\n请以只包含stage3_structure_location字段的JSON格式提供分析。",
                4: "\n\n**任务：第四步 - 最终约束提取**\n基于所有之前的分析：\n{step1_result}\n{step2_result}\n{step3_result}\n\n提取最终的约束和验证规则。\n\n请以只包含stage4_constraint_extraction字段的标准格式提供完整分析。"
            }
        
        return base_template + step_adjustments.get(step, "")
        # return base_template
    
    def should_process_function(self, function: dict) -> bool:
        return (function.get("message_id") is not None and 
                function.get("pseudocode"))
    
    def call_llm_and_process_response(self, message_id: int, function_name: str, 
                                    pseudocode: str, handle_function_pseudocode: str, 
                                    service_name: str) -> dict:
        """执行4步增量分析，使用对话历史机制"""
        log_message(f"开始4步思维链对话历史分析: Message ID {message_id}")
        
        step_results = {}
        conversation_history = []
        total_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cost": 0.0}

        def _add_usage(response):
            if "__token_usage" in response:
                total_usage["prompt_tokens"] += response["__token_usage"].get("prompt_tokens", 0)
                total_usage["completion_tokens"] += response["__token_usage"].get("completion_tokens", 0)
                total_usage["total_tokens"] += response["__token_usage"].get("total_tokens", 0)
                total_usage["cost"] += response["__token_usage"].get("cost", 0.0)
            step_results.update(response)
        
        # 使用固定的系统提示词（第一步的系统提示词）
        system_prompt = self.get_system_prompt(1)
        
        # 步骤1: 变量识别
        log_message(f"步骤1: 变量识别 - Message ID {message_id}")
        step1_success = False
        for attempt in range(3):  # 最多重试3次
            step1_prompt = self.get_user_prompt_template(1).format(
                service_name=service_name,
                message_id=message_id,
                function_name=function_name,
                pseudocode=pseudocode,
                handle_function_pseudocode=handle_function_pseudocode
            )
            
            step1_response = self.api_client.call_model_streaming(
                system_prompt=system_prompt,
                user_prompt=step1_prompt,
                response_format="json_object"
            )
            
            if isinstance(step1_response, dict) and "error" not in step1_response and "stage1_variable_identification" in step1_response:
                _add_usage(step1_response)
                step1_result = json.dumps(step1_response.get("stage1_variable_identification", {}), ensure_ascii=False, indent=2)
                conversation_history.append(f"**Step 1 Result:**\n{step1_result}")
                step1_success = True
                log_message(f"步骤1成功 - Message ID {message_id}")
                break
            else:
                log_message(f"步骤1失败 (尝试 {attempt + 1}/3) - Message ID {message_id}")
        
        if not step1_success:
            log_message(f"步骤1失败3次，跳过 Message ID {message_id}")
            return {}
        
        # 步骤2: 头部分析
        log_message(f"步骤2: 头部分析 - Message ID {message_id}")
        step2_success = False
        for attempt in range(3):  # 最多重试3次
            step2_prompt = self.get_user_prompt_template(2).format(
                service_name=service_name,
                message_id=message_id,
                function_name=function_name,
                pseudocode=pseudocode,
                handle_function_pseudocode=handle_function_pseudocode,
                step1_result="\n".join(conversation_history)
            )
            
            step2_response = self.api_client.call_model_streaming(
                system_prompt=system_prompt,
                user_prompt=step2_prompt,
                response_format="json_object"
            )
            
            if isinstance(step2_response, dict) and "error" not in step2_response and "stage2_header_analysis" in step2_response:
                _add_usage(step2_response)
                step2_result = json.dumps(step2_response.get("stage2_header_analysis", {}), ensure_ascii=False, indent=2)
                conversation_history.append(f"**Step 2 Result:**\n{step2_result}")
                step2_success = True
                log_message(f"步骤2成功 - Message ID {message_id}")
                break
            else:
                log_message(f"步骤2失败 (尝试 {attempt + 1}/3) - Message ID {message_id}")
        
        if not step2_success:
            log_message(f"步骤2失败3次，跳过 Message ID {message_id}")
            return {}
        
        # 步骤3: 结构定位
        log_message(f"步骤3: 结构定位 - Message ID {message_id}")
        step3_success = False
        for attempt in range(3):  # 最多重试3次
            step3_prompt = self.get_user_prompt_template(3).format(
                service_name=service_name,
                message_id=message_id,
                function_name=function_name,
                pseudocode=pseudocode,
                handle_function_pseudocode=handle_function_pseudocode,
                step1_result=conversation_history[0],
                step2_result=conversation_history[1]
            )
            
            step3_response = self.api_client.call_model_streaming(
                system_prompt=system_prompt,
                user_prompt=step3_prompt,
                response_format="json_object"
            )
            
            if isinstance(step3_response, dict) and "error" not in step3_response and "stage3_structure_location" in step3_response:
                _add_usage(step3_response)
                step3_result = json.dumps(step3_response.get("stage3_structure_location", {}), ensure_ascii=False, indent=2)
                conversation_history.append(f"**Step 3 Result:**\n{step3_result}")
                step3_success = True
                log_message(f"步骤3成功 - Message ID {message_id}")
                break
            else:
                log_message(f"步骤3失败 (尝试 {attempt + 1}/3) - Message ID {message_id}")
        
        if not step3_success:
            log_message(f"步骤3失败3次，跳过 Message ID {message_id}")
            return {}
        
        # 步骤4: 约束提取
        log_message(f"步骤4: 约束提取 - Message ID {message_id}")
        step4_success = False
        for attempt in range(3):  # 最多重试3次
            step4_prompt = self.get_user_prompt_template(4).format(
                service_name=service_name,
                message_id=message_id,
                function_name=function_name,
                pseudocode=pseudocode,
                handle_function_pseudocode=handle_function_pseudocode,
                step1_result=conversation_history[0],
                step2_result=conversation_history[1],
                step3_result=conversation_history[2]
            )
            
            step4_response = self.api_client.call_model_streaming(
                system_prompt=system_prompt,
                user_prompt=step4_prompt,
                response_format="json_object"
            )
            
            if isinstance(step4_response, dict) and "error" not in step4_response and "stage4_constraint_extraction" in step4_response:
                _add_usage(step4_response)
                step4_success = True
                log_message(f"步骤4成功 - Message ID {message_id}")
                break
            else:
                log_message(f"步骤4失败 (尝试 {attempt + 1}/3) - Message ID {message_id}")
        
        if not step4_success:
            log_message(f"步骤4失败3次，跳过 Message ID {message_id}")
            return {}
        
        log_message(f"4步思维链对话历史分析完成: Message ID {message_id}")
        step_results["__token_usage"] = total_usage
        return self._parse_response(step_results, message_id)
    
    def _parse_response(self, response, message_id):
        """解析LLM响应"""
        if isinstance(response, dict) and "error" in response:
            return {}
        
        if not response or not isinstance(response, dict):
            return {}
        
        # 对于4步策略，直接返回包含所有阶段的完整结果
        # LLM现在直接返回分析结果，不再包含message_id包装
        if ("stage1_variable_identification" in response or 
            "stage2_header_analysis" in response or 
            "stage3_structure_location" in response or 
            "stage4_constraint_extraction" in response):
            # 返回完整的响应，包含所有阶段的结果
            return response
        
        return {}


def generate_form_cons_cot_4step(service_name, use_english_prompts=False, use_cache=True, model_id=None):
    """
    使用4步思维链(Chain of Thought)分析模式为指定服务生成结构化约束描述文件 form_cons.json
    将分析分解为4个增量步骤，避免单次LLM调用超时：
    1. 变量识别 (Variable Identification)
    2. 头部分析 (Header Analysis)  
    3. 结构定位 (Structure Positioning)
    4. 约束提取 (Constraint Extraction)
    
    Args:
        service_name (str): 服务名称，如 "com.apple.bsd.dirhelper"
        use_english_prompts (bool): 是否使用英文提示词，默认为False（使用中文）
        use_cache (bool): 是否读取/写入缓存，默认为True
        model_id (str): 如果提供，将使用该模型ID作为输出文件的后缀
        
    Returns:
        bool: 成功返回True，失败返回False
    """
    if model_id:
        strategy = ModelTestFormConsStrategy(model_id, use_english_prompts=use_english_prompts)
    else:
        strategy = CotFormCons4StepStrategy(use_english_prompts=use_english_prompts)
    return generate_form_cons_base(service_name, strategy, use_cache=use_cache)

def generate_form_cons_no_cot(service_name, use_english_prompts=False, use_cache=True):
    """
    使用无思维链(No Chain of Thought)模式为指定服务生成结构化约束描述文件
    使用与CoT一致的4阶段Prompt结构，但剥离所有思维链工具和推理步骤要求，直接输出JSON结果。
    
    Args:
        service_name (str): 服务名称
        use_english_prompts (bool): 是否使用英文提示词
        use_cache (bool): 是否使用缓存
        
    Returns:
        bool: 成功返回True
    """
    strategy = NoCotFormConsStrategy(use_english_prompts=use_english_prompts)
    return generate_form_cons_base(service_name, strategy, use_cache=use_cache)

class ModelTestFormConsStrategy(CotFormCons4StepStrategy):
    """用于测试不同模型的策略，继承自4步思维链策略，但动态调整输出文件名。"""
    
    def __init__(self, model_id: str, use_english_prompts: bool = False):
        super().__init__(use_english_prompts)
        self.model_id = model_id
        
    def get_output_filename(self) -> str:
        return f"form_cons_{self.model_id}.json"
        
    def get_cache_prefix(self) -> str:
        return f"form_cons_{self.model_id}"
        
    def get_cache_dir_name(self) -> str:
        return f"constraints_{self.model_id}"

