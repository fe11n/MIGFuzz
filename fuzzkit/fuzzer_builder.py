#!/usr/bin/env python3

import json
import os
import sys
import shutil
import subprocess
import argparse
import inquirer
from pathlib import Path
from typing import Dict, List, Optional

class ServiceManager:
    """服务发现和管理"""

    def __init__(self, services_dir: str = "fuzz_exec"):
        self.services_dir = Path(services_dir)
        self.services = {}
        self.discover_services()

    def discover_services(self, specific_dir: Optional[str] = None):
        """
        自动发现所有服务。
        如果提供了 specific_dir，则只发现该服务。
        """
        self.services = {}
        if not self.services_dir.exists():
            print(f"Error: Services directory '{self.services_dir}' not found")
            return

        dirs_to_scan = [self.services_dir / specific_dir] if specific_dir else self.services_dir.iterdir()

        for service_path in dirs_to_scan:
            if not service_path.is_dir():
                continue

            config_file = service_path / "service.json"
            if not config_file.exists():
                # print(f"Warning: No service.json found in {service_path}")
                continue

            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    dir_name = service_path.name
                    self.services[dir_name] = {
                        'path': service_path,
                        'config': config
                    }
            except Exception as e:
                print(f"Error loading {config_file}: {e}")

    def list_services(self):
        """列出所有服务"""
        print("\n=== Available Services ===")
        for name, info in self.services.items():
            config = info['config']
            fuzz_config = config.get('fuzz', {})
            enabled = "✓" if fuzz_config.get('enabled') else "✗"
            print(f"{enabled} {name:<25} Path: {info['path']}")

    def get_service(self, name: str) -> Optional[Dict]:
        """获取指定服务"""
        return self.services.get(name)

    def get_enabled_services(self) -> List[str]:
        """获取所有启用的服务"""
        return [name for name, info in self.services.items()
                if info['config'].get('fuzz', {}).get('enabled', False)]


def interactive_select(service_mgr: ServiceManager) -> Optional[str]:
    """交互式选择服务"""
    services = list(service_mgr.services.keys())
    if not services:
        print("No services found.")
        return None

    questions = [
        inquirer.List('service',
                      message="Select a service to build and fuzz",
                      choices=services,
                      ),
    ]
    answers = inquirer.prompt(questions)
    return answers['service']


class BuildManager:
    """构建管理器"""

    def __init__(self, service_manager: ServiceManager):
        self.service_manager = service_manager
        self.project_root = Path.cwd()

    def build_harness(self, dir_name: str) -> bool:
        """为指定目录构建harness"""
        service = self.service_manager.get_service(dir_name)
        if not service:
            print(f"Error: Service directory '{dir_name}' not found")
            return False

        service_path = service['path']
        generate_msg_cc = service_path / "generate_message.cc"

        if not generate_msg_cc.exists():
            print(f"Error: {generate_msg_cc} not found")
            return False

        print(f"\n=== Building harness for {dir_name} ===")

        # 输出路径：放在服务文件夹内
        harness_output = service_path / "harness"

        # 编译命令
        sources = [
            "harness.mm",
            "fuzz_helpers/debug.cc",
            "fuzz_helpers/initialization.cc",
            "fuzz_helpers/load_library.cc",
            "fuzz_helpers/services_manager.cc",
            str(generate_msg_cc),
            "fuzz_helpers/tool_lib.cc"
        ]

        cmd = [
            "clang++",
            "-fno-omit-frame-pointer",
            "-Wall", "-Wunused-parameter", "-Wextra",
            "-std=c++17",
            "-I./fuzz_helpers", "-I.", "-I./fuzz_exec/" + dir_name,
            "-framework", "Foundation",
            "libmach-modify.dylib"
        ] + sources + ["-o", str(harness_output)]

        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            print(f"✓ Successfully built {harness_output}")

            # Copy libmach-modify.dylib to the service directory
            dylib_src = Path.cwd() / "libmach-modify.dylib"
            dylib_dst = service_path / "libmach-modify.dylib"
            if dylib_src.exists():
                import shutil
                shutil.copy2(dylib_src, dylib_dst)
                print(f"✓ Copied libmach-modify.dylib to {dylib_dst}")
            else:
                print(f"⚠ Warning: libmach-modify.dylib not found at {dylib_src}")

            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Build failed: {e.stderr}")
            return False

    def build_dylib(self) -> bool:
        """构建libmach-modify.dylib"""
        print("\n=== Building libmach-modify.dylib ===")
        cmd = [
            "clang", "-dynamiclib",
            "-o", "libmach-modify.dylib",
            "mach-modify.c", "-ldl",
            "-I./fuzz_helpers",
            "-framework", "CoreFoundation"
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            print("✓ Successfully built libmach-modify.dylib")
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Build failed: {e.stderr}")
            return False

    def clean(self):
        """清理构建产物"""
        print("\n=== Cleaning build artifacts ===")

        # 清理服务目录中的harness
        for service_name, service_info in self.service_manager.services.items():
            service_path = service_info['path']
            harness = service_path / "harness"
            harness_dsym = service_path / "harness.dSYM"

            if harness.exists():
                print(f"Removing {harness}")
                harness.unlink()
            if harness_dsym.exists():
                print(f"Removing {harness_dsym}")
                import shutil
                shutil.rmtree(harness_dsym)

        # 清理dylib
        dylib = Path.cwd() / "libmach-modify.dylib"
        dylib_dsym = Path.cwd() / "libmach-modify.dylib.dSYM"
        if dylib.exists():
            print(f"Removing {dylib}")
            dylib.unlink()
        if dylib_dsym.exists():
            print(f"Removing {dylib_dsym}")
            import shutil
            shutil.rmtree(dylib_dsym)


class FuzzManager:
    """Fuzzing管理器"""

    def __init__(self, service_manager: ServiceManager):
        self.service_manager = service_manager
        self.project_root = Path.cwd()
        self.jackalope_path = self.project_root / "jackalope-modifications/build/Release/coreaudiofuzzer"

    def prepare_directories(self, dir_name: str) -> tuple:
        """准备corpus和output目录"""
        service = self.service_manager.get_service(dir_name)
        if not service:
            return None, None

        service_path = service['path']

        # corpus和out都放在服务文件夹内
        corpus_dir = service_path / "corpus"
        output_dir = service_path / "out"

        corpus_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Copy initial corpus from project root if destination is empty
        source_corpus = self.project_root / "corpus"
        if source_corpus.exists() and not any(corpus_dir.iterdir()):
            print(f"Copying initial corpus from {source_corpus} to {corpus_dir}")
            for item in source_corpus.iterdir():
                if item.is_file() and not item.name.startswith('.'):
                    shutil.copy2(item, corpus_dir)

        return corpus_dir, output_dir

    def generate_fuzz_command(self, dir_name: str, resume: bool = False) -> Optional[str]:
        """生成Jackalope fuzz命令"""
        service = self.service_manager.get_service(dir_name)
        if not service:
            print(f"Error: Service directory '{dir_name}' not found")
            return None

        config = service['config']
        fuzz_config = config.get('fuzz', {})
        service_path = service['path']
        service_name = config.get('name', dir_name)

        corpus_dir, output_dir = self.prepare_directories(dir_name)
        if not corpus_dir:
            return None

        # 检查 harness 是否存在
        harness_path = service_path / "harness"
        if not harness_path.exists():
            print(f"Error: {harness_path} not found. Please build first.")
            return None

        # 使用相对于服务目录的路径
        corpus_input = "-" if resume else "corpus"

        # Jackalope 相对于服务目录的路径
        jackalope_rel = "../../jackalope-modifications/build/Release/coreaudiofuzzer"

        # dylib 相对于服务目录的路径
        dylib_rel = "../../libmach-modify.dylib"

        cmd_parts = [
            jackalope_rel,
            "-hook_functions", "true",
            "-in", corpus_input,
            "-out", "out",
            "-delivery", "file",
            "-instrument_module", fuzz_config.get('instrument_module', service_name),
            "-target_module", "harness",
            "-target_method", "_fuzz",
            "-nargs", "1",
            "-iterations", str(fuzz_config.get('iterations', 1000)),
            "-persist",
            "-loop",
            "-dump_coverage",
            "-cmp_coverage",
            "-target_env", f"DYLD_INSERT_LIBRARIES={dylib_rel}",
            "-nthreads", str(fuzz_config.get('threads', 5)),
            "--",
            "./harness",
            "-f", "@@"
        ]

        return " ".join(cmd_parts)

    def start_fuzzing(self, dir_name: str, resume: bool = False):
        """生成fuzzing命令并保存到run.sh"""
        service = self.service_manager.get_service(dir_name)
        if not service:
            return

        cmd = self.generate_fuzz_command(dir_name, resume)
        if not cmd:
            return

        service_path = service['path']
        run_sh_path = service_path / "run.sh"

        # 将命令和日志重定向组合
        cmd_with_log = f"sudo -E script -q /dev/null {cmd} >> log.txt 2>&1"

        script_content = f"""#!/bin/bash
# Auto-generated fuzzing script for {dir_name}
# Generated on: $(date)

# Change to the script's directory to ensure relative paths work correctly
cd "$(dirname "$0")" || exit

echo "Starting fuzzing for {dir_name}, logging to log.txt..."
{cmd_with_log}
"""

        try:
            with open(run_sh_path, 'w') as f:
                f.write(script_content)

            # chmod +x
            import os
            os.chmod(run_sh_path, 0o755)

            print(f"\n=== Fuzzing setup for {dir_name} ===")
            print(f"Command: {cmd}")
            print(f"\n✓ Saved to {run_sh_path}")
            print(f"  Log output will be appended to log.txt")
            print(f"\nTo run:")
            print(f"sudo fuzz_exec/{dir_name}/run.sh")
        except Exception as e:
            print(f"✗ Failed to save run.sh: {e}")

    def run_multiple(self, dir_names: List[str], resume: bool = False):
        """生成多个服务的fuzzing命令"""
        for dir_name in dir_names:
            self.start_fuzzing(dir_name, resume)


def main():
    parser = argparse.ArgumentParser(
        description="MachServerFuzz - 基于文件路由的Mach服务模糊测试管理工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 列出所有服务
  %(prog)s list

  # 构建并为特定目录生成fuzz脚本
  %(prog)s build -d filecoordinationd

  # 构建并为所有服务生成fuzz脚本
  %(prog)s build --all

  # 清理构建产物
  %(prog)s clean
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # list命令
    list_parser = subparsers.add_parser('list', help='列出所有服务')

    # build命令 (现在也包含fuzz)
    build_parser = subparsers.add_parser('build', help='构建harness并生成fuzz脚本')
    build_parser.add_argument('-d', '--dir', help='服务目录名称')
    build_parser.add_argument('--all', action='store_true', help='构建所有服务')
    build_parser.add_argument('--resume', action='store_true', help='生成恢复命令')

    # clean命令
    clean_parser = subparsers.add_parser('clean', help='清理构建产物')


    args = parser.parse_args()

    if not args.command:
        # 交互模式
        service_mgr = ServiceManager()
        service_mgr.discover_services()
        selected = interactive_select(service_mgr)
        if selected:
            build_mgr = BuildManager(service_mgr)
            fuzz_mgr = FuzzManager(service_mgr)
            
            # 1. 构建 dylib
            if not build_mgr.build_dylib():
                print("Failed to build dylib")
                return
            
            # 2. 构建 harness
            if not build_mgr.build_harness(selected):
                print(f"Failed to build harness for {selected}")
                return
            
            # 3. 生成 fuzz 脚本
            fuzz_mgr.start_fuzzing(selected)
        return

    # 初始化管理器
    service_mgr = ServiceManager()

    if args.command == 'list':
        service_mgr.discover_services()
        service_mgr.list_services()

    elif args.command == 'build':
        build_mgr = BuildManager(service_mgr)
        fuzz_mgr = FuzzManager(service_mgr)

        # 先构建dylib
        if not build_mgr.build_dylib():
            print("Failed to build dylib")
            return

        if args.all:
            service_mgr.discover_services()
            for dir_name in service_mgr.services.keys():
                if build_mgr.build_harness(dir_name):
                    fuzz_mgr.start_fuzzing(dir_name, args.resume)
        elif args.dir:
            service_mgr.discover_services(specific_dir=args.dir)
            if build_mgr.build_harness(args.dir):
                fuzz_mgr.start_fuzzing(args.dir, args.resume)
        else:
            print("Please specify --dir or --all")

    elif args.command == 'clean':
        service_mgr.discover_services()
        build_mgr = BuildManager(service_mgr)
        build_mgr.clean()


if __name__ == "__main__":
    main()
