#!/usr/bin/env python3
"""
extract_service_info.py

从 macOS launchd.plist 提取服务信息并生成 JSON 格式的摘要文件。

生成 launchd_summary.txt 格式的 JSON 文件。
"""

import plistlib
import json
import os
import subprocess
import sys
import shutil
from datetime import datetime

def copy_binaries_to_folder(json_file_path, services_list):
    """复制所有program对应的二进制文件到binaries/{服务label}/文件夹"""
    try:
        # 从JSON文件路径推导出binaries基础目录
        # json_file_path 应该是: .../SystemResource/macOS-X.Y/launchd_summary.json 
        # binaries目录应该是: .../SystemResource/macOS-X.Y/binaries/
        json_dir = os.path.dirname(os.path.abspath(json_file_path))
        binaries_base_dir = os.path.join(json_dir, 'binaries')

        # 创建binaries基础文件夹
        os.makedirs(binaries_base_dir, exist_ok=True)

        copied_count = 0

        for service in services_list:
            program_path = service.get('program', '').strip()
            label = service.get('label', '').strip()

            if program_path and os.path.isfile(program_path) and label:
                # 获取文件名
                filename = os.path.basename(program_path)

                # 创建以label命名的子文件夹
                label_dir = os.path.join(binaries_base_dir, label)
                os.makedirs(label_dir, exist_ok=True)

                # 目标文件路径
                dest_path = os.path.join(label_dir, filename)

                # 检查目标文件是否已存在
                if os.path.exists(dest_path):
                    continue  # 如果文件已存在，跳过复制

                try:
                    # 复制文件
                    shutil.copy2(program_path, dest_path)
                    copied_count += 1
                except Exception as e:
                    pass  # 静默失败

    except Exception as e:
        pass

def get_macos_version():
    """获取 macOS 版本信息"""
    try:
        result = subprocess.run(['sw_vers'], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            version_info = {}
            for line in lines:
                # sw_vers 使用制表符分隔
                if '\t\t' in line:
                    key, value = line.split('\t\t', 1)
                    version_info[key.strip()] = value.strip()
            return version_info
        else:
            # 备用方法：使用 system_profiler
            result2 = subprocess.run(['system_profiler', 'SPSoftwareDataType'], capture_output=True, text=True)
            if result2.returncode == 0:
                lines = result2.stdout.split('\n')
                for line in lines:
                    if 'System Version:' in line:
                        return {"System Version": line.split('System Version:')[1].strip()}
            return {"error": "无法获取版本信息"}
    except Exception as e:
        return {"error": str(e)}

def parse_plist_file(file_path):
    """解析单个 plist 文件并返回服务信息"""
    try:
        with open(file_path, 'rb') as f:
            config = plistlib.load(f)
        
        label = config.get('Label', '')
        if not label:
            # 如果没有 Label，使用文件名（不含扩展名）
            label = os.path.splitext(os.path.basename(file_path))[0]

        service_info = {
            "label": label,
            "path": file_path,
            "mach_services": {},
            "program": config.get('Program', ''),
            "program_arguments": config.get('ProgramArguments', []),
            "disabled": config.get('Disabled', False),
            "enable_transactions": config.get('EnableTransactions', False),
            "posix_spawn_type": config.get('POSIXSpawnType', ''),
            "run_at_load": config.get('RunAtLoad', False),
            "keep_alive": config.get('KeepAlive', False)
        }

        # 提取 MachServices
        mach_services = config.get('MachServices', {})
        if mach_services:
            service_info["mach_services"] = mach_services
            
        return service_info
    except Exception as e:
        return None

def scan_additional_directories():
    """扫描其他服务目录"""
    directories = [
        '/System/Library/LaunchAgents',
        '/Library/LaunchDaemons',
        '/Library/LaunchAgents',
        os.path.expanduser('~/Library/LaunchAgents')
    ]
    
    services = []
    for d in directories:
        if not os.path.exists(d):
            continue
            
        for root, _, files in os.walk(d):
            for file in files:
                if file.endswith('.plist'):
                    full_path = os.path.join(root, file)
                    service = parse_plist_file(full_path)
                    if service:
                        services.append(service)
    return services

def extract_service_info():
    """提取 launchd.plist 中的服务信息"""
    plist_path = '/System/Library/xpc/launchd.plist'

    try:
        # 读取 plist 文件
        with open(plist_path, 'rb') as f:
            plist_data = plistlib.load(f)

        # 提取 LaunchDaemons 信息
        launchd_summary = {
            "metadata": {
                "source_file": plist_path,
                "generated_at": datetime.now().isoformat(),
                "generator": "extract_service_info.py"
            },
            "statistics": {},
            "services": []
        }

        # 用于去重的集合 (使用 Label)
        seen_labels = set()

        if 'LaunchDaemons' in plist_data:
            launch_daemons = plist_data['LaunchDaemons']

            # 提取每个服务的信息
            sorted_daemons = sorted(launch_daemons.items(), key=lambda x: x[1].get('Label', ''))

            for path, config in sorted_daemons:
                label = config.get('Label', 'Unknown')
                seen_labels.add(label)

                service_info = {
                    "label": label,
                    "path": path,
                    "mach_services": {},
                    "program": config.get('Program', ''),
                    "program_arguments": config.get('ProgramArguments', []),
                    "disabled": config.get('Disabled', False),
                    "enable_transactions": config.get('EnableTransactions', False),
                    "posix_spawn_type": config.get('POSIXSpawnType', ''),
                    "run_at_load": config.get('RunAtLoad', False),
                    "keep_alive": config.get('KeepAlive', False)
                }

                # 提取 MachServices
                mach_services = config.get('MachServices', {})
                if mach_services:
                    service_info["mach_services"] = mach_services

                launchd_summary["services"].append(service_info)

        # 扫描其他目录并合并
        additional_services = scan_additional_directories()
        for service in additional_services:
            if service['label'] not in seen_labels:
                launchd_summary["services"].append(service)
                seen_labels.add(service['label'])

        # 更新统计信息
        total_daemons = len(launchd_summary["services"])
        total_mach_services = 0
        daemons_with_mach = 0

        for service in launchd_summary["services"]:
            mach_services = service.get('mach_services', {})
            if mach_services:
                total_mach_services += len(mach_services)
                daemons_with_mach += 1

        launchd_summary["statistics"] = {
            "total_daemons": total_daemons,
            "total_mach_services": total_mach_services,
            "daemons_with_mach_services": daemons_with_mach,
            "average_mach_services_per_daemon": total_mach_services / total_daemons if total_daemons > 0 else 0
        }

        return launchd_summary

    except Exception as e:
        return None

def save_json_summary(summary_data, output_file="launchd_summary.json"):
    """保存摘要为 JSON 文件，包含元数据"""
    try:
        # 获取 macOS 版本
        macos_version = get_macos_version()
        
        # 获取统计信息
        stats = summary_data.get('statistics', {})
        
        # 构建元数据
        metadata = {
            "macos_version": macos_version,
            "total_launchdaemons": stats.get('total_daemons', 0),
            "total_machservices": stats.get('total_mach_services', 0),
            "daemons_with_machservices": stats.get('daemons_with_mach_services', 0),
            "generated_at": datetime.now().isoformat(),
            "generator": "extract_service_info.py"
        }
        
        # 转换服务数据
        services_list = []
        
        for i, service in enumerate(summary_data.get('services', []), 1):
            # 获取程序路径
            program = service.get('program', '')
            if not program and service.get('program_arguments'):
                program = service.get('program_arguments', [])[0]
            
            # 获取参数
            arguments = []
            if service.get('program_arguments') and len(service.get('program_arguments', [])) > 1:
                arguments = service.get('program_arguments', [])[1:]
            
            service_entry = {
                "label": service.get('label', ''),
                "path": service.get('path', ''),
                "mach_services": list(service.get('mach_services', {}).keys()) if service.get('mach_services') else [],
                "program": program,
                "arguments": arguments
            }
            services_list.append(service_entry)
        
        # 构建最终 JSON 结构
        final_data = {
            "metadata": metadata,
            "services": services_list
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_data, f, indent=2, ensure_ascii=False)

        file_size = os.path.getsize(output_file)

        # 复制二进制文件到binaries文件夹
        copy_binaries_to_folder(output_file, services_list)

    except Exception as e:
        pass

def main():
    # 处理命令行参数
    output_file = "launchd_summary.json"
    if len(sys.argv) > 1:
        output_file = sys.argv[1]

    # 提取服务信息
    summary = extract_service_info()

    if summary:
        # 保存为 JSON 格式
        save_json_summary(summary, output_file)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()