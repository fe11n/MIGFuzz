
import os
import sys
import json
import argparse
from pathlib import Path

# Add the parent directory to the sys.path to allow imports from other directories
sys.path.append(str(Path(__file__).parent.parent))

from rich.console import Console
from rich.panel import Panel

console = Console()

# --- Helper Functions ---

def get_llm_client():
    """Dynamically imports and returns the LLM API client."""
    try:
        # Ensure we are in the right directory for relative imports in config
        original_cwd = Path.cwd()
        os.chdir(Path(__file__).parent)
        from llm_utils.config import config
        client = config.api_client
        os.chdir(original_cwd)
        return client
    except (ImportError, AttributeError, Exception) as e:
        console.print(f"[bold red]Error initializing LLM API client:[/bold red] {e}")
        console.print("Please check your 'llm_utils/config.py' and API key settings.")
        os.chdir(original_cwd)
        return None

def prepare_notebook_environment(workspace_name, service_name_base):
    """
    Creates a temporary 'services' directory structure that mimics the notebook's
    environment, using symlinks to avoid data duplication.
    Returns a tuple of (original_cwd, temp_service_dir).
    """
    original_cwd = Path.cwd()
    llm_gen_path = Path(__file__).parent
    os.chdir(llm_gen_path)

    project_root = llm_gen_path.parent
    
    # Path to the real mig_functions.json
    mig_functions_file = project_root / "service_file_extractor" / "SystemResource" / "mig_binaries" / service_name_base / "mig_functions.json"
    if not mig_functions_file.exists():
        console.print(f"[bold red]Error:[/bold red] Prerequisite file not found: {mig_functions_file}")
        os.chdir(original_cwd)
        return None, None

    # Create the temporary 'services/<service_name>' directory
    temp_service_dir = llm_gen_path / "services" / service_name_base
    temp_service_dir.mkdir(parents=True, exist_ok=True)

    # Symlink the necessary mig_functions.json
    symlink_path = temp_service_dir / "mig_functions.json"
    if not symlink_path.exists():
        os.symlink(mig_functions_file, symlink_path)

    # Symlink other potential dependencies if they exist
    real_workspace_path = project_root / "fuzz_exec" / workspace_name
    for f in ["form_cons.json", "parameter_semantics.json", "parameter_extra_information.json"]:
        real_file = real_workspace_path / f
        temp_file = temp_service_dir / f
        if real_file.exists() and not temp_file.exists():
            os.symlink(real_file, temp_file)

    return original_cwd, temp_service_dir

def cleanup_notebook_environment(original_cwd, temp_service_dir):
    """Cleans up the temporary symlinks and directory structure."""
    if not temp_service_dir:
        os.chdir(original_cwd)
        return
        
    for item in temp_service_dir.iterdir():
        if item.is_symlink():
            item.unlink()
    
    # Attempt to remove the directory if it's empty
    try:
        temp_service_dir.rmdir()
        (temp_service_dir.parent).rmdir()
    except OSError:
        # Directory is not empty, which is fine.
        pass

    os.chdir(original_cwd)


# --- Core Functions ---

def run_llm_tests():
    """Executes a suite of tests to check the LLM connection and capabilities."""
    console.print(Panel("🧪 [bold green]Running LLM Connection Tests[/bold green]", expand=False))
    
    original_cwd = Path.cwd()
    os.chdir(Path(__file__).parent)
    
    try:
        from llm_function_generator.test_llm import (
            test_llm_connection,
            test_llm_json_response
        )
        client = get_llm_client()
        if not client:
            os.chdir(original_cwd)
            return

        test1 = test_llm_connection(client)
        test2 = test_llm_json_response(client)

        console.print("\n[bold]Test Summary:[/bold]")
        console.print(f"- Basic Connection: {'[green]✅ Passed[/green]' if test1 else '[red]❌ Failed[/red]'}")
        console.print(f"- JSON Response: {'[green]✅ Passed[/green]' if test2 else '[red]❌ Failed[/red]'}")

        if not all([test1, test2]):
            console.print("\n[bold yellow]Some tests failed. Please review the output above.[/bold yellow]")
        else:
            console.print("\n[bold green]🎉 All LLM tests passed successfully![/bold green]")

    except ImportError:
        console.print("[bold red]Error:[/bold red] Could not import test functions from 'llm_function_generator/test_llm.py'.")
    finally:
        os.chdir(original_cwd)


def generate_constraints(workspace_name, service_name_base, method, use_english_prompts=True):
    """Generates structured constraint description file ('form_cons.json')."""
    console.print(Panel(f"📝 [bold green]Generating Constraints for '{service_name_base}' using '{method}' method[/bold green]", expand=False))

    original_cwd, temp_service_dir = prepare_notebook_environment(workspace_name, service_name_base)
    if not original_cwd:
        return

    try:
        from llm_function_generator.init_cons_withllm import (
            generate_form_cons,
            generate_form_cons_twostage,
            generate_form_cons_oneshot,
            generate_form_cons_cot_4step
        )
        method_map = {
            "default": generate_form_cons,
            "twostage": generate_form_cons_twostage,
            "oneshot": generate_form_cons_oneshot,
            "cot": generate_form_cons_cot_4step,
        }

        if method not in method_map:
            console.print(f"[bold red]Error:[/bold red] Invalid method '{method}'.")
            return

        temp_output_file = temp_service_dir / "form_cons.json"
        if temp_output_file.exists():
            temp_output_file.unlink()

        console.print(f"\nCalling function [bold yellow]{method_map[method].__name__}[/bold yellow]...")
        success = method_map[method](service_name_base, use_english_prompts=use_english_prompts)

        real_output_file = Path(original_cwd) / "fuzz_exec" / workspace_name / "form_cons.json"
        if success and temp_output_file.exists():
            console.print("[bold green]✅ Constraint generation successful.[/bold green]")
            temp_output_file.rename(real_output_file)
            console.print(f"📄 Output saved to: [cyan]{real_output_file}[/cyan]")
        else:
            console.print("[bold red]❌ Constraint generation failed.[/bold red]")

    except ImportError:
        console.print("[bold red]Error:[/bold red] Could not import from 'init_cons_withllm.py'.")
    finally:
        cleanup_notebook_environment(original_cwd, temp_service_dir)


def generate_code(workspace_name, service_name_base, use_english_prompts=True):
    """Generates C++ message generator code from 'form_cons.json'."""
    console.print(Panel(f"💻 [bold green]Generating Message Code for '{service_name_base}'[/bold green]", expand=False))

    original_cwd, temp_service_dir = prepare_notebook_environment(workspace_name, service_name_base)
    if not original_cwd:
        return

    try:
        from llm_function_generator.generate_message_code import generate_message_code_for_service_by_id
        
        temp_output_file = temp_service_dir / "generate_message.cc"
        if temp_output_file.exists():
            temp_output_file.unlink()

        console.print(f"\nCalling function [bold yellow]generate_message_code_for_service_by_id[/bold yellow]...")
        success = generate_message_code_for_service_by_id(service_name_base, use_english_prompts=use_english_prompts)

        real_output_file = Path(original_cwd) / "fuzz_exec" / workspace_name / "generate_message.cc"
        if success and temp_output_file.exists():
            console.print("[bold green]✅ Code generation successful.[/bold green]")
            temp_output_file.rename(real_output_file)
            console.print(f"📄 Output saved to: [cyan]{real_output_file}[/cyan]")
        else:
            console.print("[bold red]❌ Code generation failed.[/bold red]")

    except ImportError:
        console.print("[bold red]Error:[/bold red] Could not import from 'generate_message_code.py'.")
    finally:
        cleanup_notebook_environment(original_cwd, temp_service_dir)

def update_semantics(workspace_name, service_name_base, use_english_prompts=True):
    """Generates 'parameter_semantics.json' by analyzing all MIG functions."""
    console.print(Panel(f"🧠 [bold green]Updating Semantics for '{service_name_base}'[/bold green]", expand=False))

    original_cwd, temp_service_dir = prepare_notebook_environment(workspace_name, service_name_base)
    if not original_cwd:
        return

    try:
        from llm_function_generator.generate_second_cons import generate_parameter_semantics

        temp_output_file = temp_service_dir / "parameter_semantics.json"
        if temp_output_file.exists():
            temp_output_file.unlink()

        console.print(f"\nCalling function [bold yellow]generate_parameter_semantics[/bold yellow]...")
        success = generate_parameter_semantics(service_name_base, use_english_prompts=use_english_prompts, use_cache=False)

        real_output_file = Path(original_cwd) / "fuzz_exec" / workspace_name / "parameter_semantics.json"
        if success and temp_output_file.exists():
            console.print("[bold green]✅ Semantics generation successful.[/bold green]")
            temp_output_file.rename(real_output_file)
            console.print(f"📄 Output saved to: [cyan]{real_output_file}[/cyan]")
        else:
            console.print("[bold red]❌ Semantics generation failed.[/bold red]")

    except ImportError:
        console.print("[bold red]Error:[/bold red] Could not import from 'generate_second_cons.py'.")
    finally:
        cleanup_notebook_environment(original_cwd, temp_service_dir)


def regenerate_code_with_semantics(workspace_name, service_name_base, use_english_prompts=True):
    """Regenerates all message functions based on semantic constraints."""
    console.print(Panel(f"🔄 [bold green]Regenerating Code with Semantics for '{service_name_base}'[/bold green]", expand=False))

    original_cwd, temp_service_dir = prepare_notebook_environment(workspace_name, service_name_base)
    if not original_cwd:
        return

    try:
        from llm_function_generator.update_code import regenerate_all_message_with_semantics

        console.print(f"\nCalling function [bold yellow]regenerate_all_message_with_semantics[/bold yellow]...")
        success = regenerate_all_message_with_semantics(service_name_base, use_english_prompts=use_english_prompts)

        if success:
            console.print("[bold green]✅ Code regeneration with semantics successful.[/bold green]")
            console.print(f"Check the 'updated_functions' and 'semantic_rewrites' folders inside [cyan]{temp_service_dir}[/cyan]")
            console.print("[bold yellow]Note:[/bold yellow] This function creates new files in subdirectories, not a single output file.")
        else:
            console.print("[bold red]❌ Code regeneration with semantics failed.[/bold red]")

    except ImportError:
        console.print("[bold red]Error:[/bold red] Could not import from 'update_code.py'.")
    finally:
        # Don't clean up immediately, so user can inspect the output folders
        console.print(f"\n[bold]To inspect results, see:[/] [cyan]{temp_service_dir}[/cyan]")
        os.chdir(original_cwd)


def main():
    parser = argparse.ArgumentParser(description="LLM-based generator for Mach Service Fuzzing.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 'check-config' command
    subparsers.add_parser("check-config", help="Test LLM connection and configuration.")
    
    # 'generate-constraints' command
    parser_cons = subparsers.add_parser("generate-constraints", help="Generate 'form_cons.json' from MIG function analysis.")
    parser_cons.add_argument("workspace_name", help="The name of the workspace directory (e.g., 'com.apple.tailspind_v1').")
    parser_cons.add_argument("--method", choices=["default", "twostage", "oneshot", "cot"], default="default", help="The generation method to use.")

    # 'generate-code' command
    parser_code = subparsers.add_parser("generate-code", help="Generate 'generate_message.cc' from 'form_cons.json'.")
    parser_code.add_argument("workspace_name", help="The name of the workspace directory (e.g., 'com.apple.tailspind_v1').")

    # 'update-semantics' command
    parser_sem = subparsers.add_parser("update-semantics", help="Generate 'parameter_semantics.json'.")
    parser_sem.add_argument("workspace_name", help="The name of the workspace directory.")

    # 'regenerate-code' command
    parser_regen = subparsers.add_parser("regenerate-code", help="Regenerate code based on semantics.")
    parser_regen.add_argument("workspace_name", help="The name of the workspace directory.")

    args = parser.parse_args()
    
    service_name_base = ""
    if hasattr(args, 'workspace_name'):
        service_name_base = args.workspace_name.split('_v')[0]

    if args.command == "check-config":
        run_llm_tests()
    elif args.command == "generate-constraints":
        generate_constraints(args.workspace_name, service_name_base, args.method)
    elif args.command == "generate-code":
        generate_code(args.workspace_name, service_name_base)
    elif args.command == "update-semantics":
        update_semantics(args.workspace_name, service_name_base)
    elif args.command == "regenerate-code":
        regenerate_code_with_semantics(args.workspace_name, service_name_base)


if __name__ == "__main__":
    main()
