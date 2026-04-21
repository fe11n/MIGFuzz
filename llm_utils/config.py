# -*- coding: UTF-8 -*-
from pathlib import Path
import os

# --- 全局配置 ---
class Config:
    MAX_ITERATIONS = 10
    DEBUG_MODE = True
    REQUEST_TIMEOUT = 180.0
    IDA_TIMEOUT = 30  # IDA分析超时时间（秒）
    
    def __init__(self):
        """构造函数：从llm_utils/prompts文件夹中的txt文件加载对应的提示词"""
        self.prompts_dir = Path(__file__).parent / "prompts"
        self._load_all_prompts()
        self._api_client = None
    
    @property
    def api_client(self):
        """延迟初始化API客户端"""
        if self._api_client is None:
            self._init_api_client()
        return self._api_client
    
    def _init_api_client(self):
        """延迟初始化API客户端，避免循环导入"""
        try:
            import llm_utils.api_client as api_client
            self._api_client = api_client.APIClient() #使用APIClient
        except ImportError as e:
            print(f"Warning: Failed to import API clients: {e}")
            self._api_client = None
        except Exception as e:
            print(f"Warning: Failed to initialize API client: {e}")
            import traceback
            traceback.print_exc()
            self._api_client = None
    
    def _load_prompt_file(self, filepath):
        """加载单个提示词文件"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read().strip()
        except FileNotFoundError:
            print(f"Warning: Prompt file not found: {filepath}")
            return ""
        except Exception as e:
            print(f"Error loading prompt file {filepath}: {e}")
            return ""
    
    def _load_all_prompts(self):
        """加载所有提示词文件"""
        # form_cons 相关提示词
        form_cons_dir = self.prompts_dir / "form_cons"
        self.SYSTEM_MSG_FORM_CONS = self._load_prompt_file(form_cons_dir / "system_msg_form_cons.txt")
        self.USER_MSG_SINGLE_MESSAGE_FULL = self._load_prompt_file(form_cons_dir / "user_msg_single_message_full.txt")
        self.USER_MSG_SINGLE_MESSAGE = self._load_prompt_file(form_cons_dir / "user_msg_single_message.txt")
        
        # English versions
        self.SYSTEM_MSG_FORM_CONS_EN = self._load_prompt_file(form_cons_dir / "system_msg_form_cons_en.txt")
        self.USER_MSG_SINGLE_MESSAGE_FULL_EN = self._load_prompt_file(form_cons_dir / "user_msg_single_message_full_en.txt")
        self.USER_MSG_SINGLE_MESSAGE_EN = self._load_prompt_file(form_cons_dir / "user_msg_single_message_en.txt")
        
        # generate_code 相关提示词
        generate_code_dir = self.prompts_dir / "generate_code"
        self.SYSTEM_MSG_GENERATE_BY_ID = self._load_prompt_file(generate_code_dir / "system_msg_generate_by_id.txt")
        self.USER_MSG_GENERATE_BY_ID = self._load_prompt_file(generate_code_dir / "user_msg_generate_by_id.txt")
        
        # English versions
        self.SYSTEM_MSG_GENERATE_BY_ID_EN = self._load_prompt_file(generate_code_dir / "system_msg_generate_by_id_en.txt")
        self.USER_MSG_GENERATE_BY_ID_EN = self._load_prompt_file(generate_code_dir / "user_msg_generate_by_id_en.txt")

        # update_code_compile 相关提示词
        update_code_compile_dir = self.prompts_dir / "update_code_compile"
        self.SYSTEM_MSG_UPDATE_COMPILE_BY_ID = self._load_prompt_file(update_code_compile_dir / "system_msg_update_by_id.txt")
        self.USER_MSG_UPDATE_COMPILE_BY_ID = self._load_prompt_file(update_code_compile_dir / "user_msg_update_by_id.txt")
        
        # English versions
        self.SYSTEM_MSG_UPDATE_COMPILE_BY_ID_EN = self._load_prompt_file(update_code_compile_dir / "system_msg_update_by_id_en.txt")
        self.USER_MSG_UPDATE_COMPILE_BY_ID_EN = self._load_prompt_file(update_code_compile_dir / "user_msg_update_by_id_en.txt")
            
        # update_code 相关提示词
        update_code_dir = self.prompts_dir / "update_code"
        self.SYSTEM_MSG_UPDATE_BY_ID = self._load_prompt_file(update_code_dir / "system_msg_update_by_id.txt")
        self.USER_MSG_UPDATE_BY_ID = self._load_prompt_file(update_code_dir / "user_msg_update_by_id.txt")
        
        # English versions
        self.SYSTEM_MSG_UPDATE_BY_ID_EN = self._load_prompt_file(update_code_dir / "system_msg_update_by_id_en.txt")
        self.USER_MSG_UPDATE_BY_ID_EN = self._load_prompt_file(update_code_dir / "user_msg_update_by_id_en.txt")
            
        # strict_cons 相关提示词
        strict_cons_dir = self.prompts_dir / "strict_cons"
        self.SYSTEM_MSG_STRICT_CONS_STAGE1 = self._load_prompt_file(strict_cons_dir / "system_msg_strict_cons_stage1.txt")
        self.USER_MSG_STRICT_CONS_STAGE1 = self._load_prompt_file(strict_cons_dir / "user_msg_strict_cons_stage1.txt")
        self.SYSTEM_MSG_STRICT_CONS_STAGE2 = self._load_prompt_file(strict_cons_dir / "system_msg_strict_cons_stage2.txt")
        self.USER_MSG_STRICT_CONS_STAGE2 = self._load_prompt_file(strict_cons_dir / "user_msg_strict_cons_stage2.txt")
        
        # English versions
        self.SYSTEM_MSG_STRICT_CONS_STAGE1_EN = self._load_prompt_file(strict_cons_dir / "system_msg_strict_cons_stage1_en.txt")
        self.USER_MSG_STRICT_CONS_STAGE1_EN = self._load_prompt_file(strict_cons_dir / "user_msg_strict_cons_stage1_en.txt")
        self.SYSTEM_MSG_STRICT_CONS_STAGE2_EN = self._load_prompt_file(strict_cons_dir / "system_msg_strict_cons_stage2_en.txt")
        self.USER_MSG_STRICT_CONS_STAGE2_EN = self._load_prompt_file(strict_cons_dir / "user_msg_strict_cons_stage2_en.txt")
        
        # Oneshot versions
        self.SYSTEM_MSG_STRICT_CONS_ONESHOT = self._load_prompt_file(strict_cons_dir / "system_msg_strict_cons_oneshot.txt")
        self.USER_MSG_STRICT_CONS_ONESHOT = self._load_prompt_file(strict_cons_dir / "user_msg_strict_cons_oneshot.txt")
        self.SYSTEM_MSG_STRICT_CONS_ONESHOT_EN = self._load_prompt_file(strict_cons_dir / "system_msg_strict_cons_oneshot_en.txt")
        self.USER_MSG_STRICT_CONS_ONESHOT_EN = self._load_prompt_file(strict_cons_dir / "user_msg_strict_cons_oneshot_en.txt")
        
        # cot_cons 相关提示词 (Chain of Thought)
        cot_cons_dir = self.prompts_dir / "cot_cons"
        self.SYSTEM_MSG_COT_CONS = self._load_prompt_file(cot_cons_dir / "system_prompt_zh.txt")
        self.USER_MSG_COT_CONS = self._load_prompt_file(cot_cons_dir / "user_prompt_zh.txt")
        
        # English versions
        self.SYSTEM_MSG_COT_CONS_EN = self._load_prompt_file(cot_cons_dir / "system_prompt_en.txt")
        self.USER_MSG_COT_CONS_EN = self._load_prompt_file(cot_cons_dir / "user_prompt_en.txt")

        # no_taskdep_cons (Ablation Study)
        no_taskdep_cons_dir = self.prompts_dir / "no_taskdep_cons"
        self.SYSTEM_MSG_NO_TASKDEP_CONS_EN = self._load_prompt_file(no_taskdep_cons_dir / "system_prompt_en.txt")
        self.USER_MSG_NO_TASKDEP_CONS_EN = self._load_prompt_file(no_taskdep_cons_dir / "user_prompt_en.txt")
        
        self.SYSTEM_MSG_NO_TASKDEP_CONS = self._load_prompt_file(no_taskdep_cons_dir / "system_prompt_zh.txt")
        self.USER_MSG_NO_TASKDEP_CONS = self._load_prompt_file(no_taskdep_cons_dir / "user_prompt_zh.txt")

        # no_cot_cons (Ablation Study)
        no_cot_cons_dir = self.prompts_dir / "no_cot_cons"
        self.SYSTEM_MSG_NO_COT_CONS_EN = self._load_prompt_file(no_cot_cons_dir / "system_prompt_en.txt")
        self.USER_MSG_NO_COT_CONS_EN = self._load_prompt_file(no_cot_cons_dir / "user_prompt_en.txt")
        
        self.SYSTEM_MSG_NO_COT_CONS = self._load_prompt_file(no_cot_cons_dir / "system_prompt_zh.txt")
        self.USER_MSG_NO_COT_CONS = self._load_prompt_file(no_cot_cons_dir / "user_prompt_zh.txt")

        # second_cons 相关提示词（参数语义与生成重写）
        second_cons_dir = self.prompts_dir / "second_cons"
        self.SYSTEM_MSG_PARAM_SEMANTICS = self._load_prompt_file(second_cons_dir / "system_msg_param_semantics.txt")
        self.USER_MSG_PARAM_SEMANTICS = self._load_prompt_file(second_cons_dir / "user_msg_param_semantics.txt")
        self.SYSTEM_MSG_PARAM_SEMANTICS_EN = self._load_prompt_file(second_cons_dir / "system_msg_param_semantics_en.txt")
        self.USER_MSG_PARAM_SEMANTICS_EN = self._load_prompt_file(second_cons_dir / "user_msg_param_semantics_en.txt")

        self.SYSTEM_MSG_SEMANTIC_REWRITE = self._load_prompt_file(second_cons_dir / "system_msg_semantic_rewrite.txt")
        self.USER_MSG_SEMANTIC_REWRITE = self._load_prompt_file(second_cons_dir / "user_msg_semantic_rewrite.txt")
        self.SYSTEM_MSG_SEMANTIC_REWRITE_EN = self._load_prompt_file(second_cons_dir / "system_msg_semantic_rewrite_en.txt")
        self.USER_MSG_SEMANTIC_REWRITE_EN = self._load_prompt_file(second_cons_dir / "user_msg_semantic_rewrite_en.txt")

# 延迟创建config实例，避免循环导入
def _get_config():
    """获取配置实例（延迟初始化）"""
    if not hasattr(_get_config, '_config_instance'):
        _get_config._config_instance = Config()
    return _get_config._config_instance

config = _get_config()
