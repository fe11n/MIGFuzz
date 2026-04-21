
import questionary
import os
import platform
import sys
import subprocess
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from questionary import Choice

console = Console()

BASE_PATH = Path(__file__).parent
RESOURCE_BASE_PATH = BASE_PATH / "service_file_extractor" / "SystemResource"
SERVICES_ROOT_PATH = BASE_PATH / "fuzz_exec"

def get_macos_version_path():
    """Gets the path for the current macOS version by running `sw_vers`."""
    try:
        # Ensure we are on macOS before running sw_vers
        if sys.platform == "darwin":
            result = subprocess.run(
                ["sw_vers", "-productVersion"],
                capture_output=True,
                text=True,
                check=True
            )
            version = result.stdout.strip()
            console.print(f"📱 Current macOS Version: [bold cyan]{version}[/bold cyan]")
            return RESOURCE_BASE_PATH / f"macOS-{version}"
        else:
            console.print("[bold yellow]Warning:[/bold yellow] Not running on macOS. Using a default path for demonstration.")
            # Fallback for non-macOS environments
            return RESOURCE_BASE_PATH / "macOS-15.7"
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        console.print(f"[bold red]Error determining macOS version:[/bold red] {e}")
        console.print("Falling back to a default path. Please check your system configuration.")
        return RESOURCE_BASE_PATH / "macOS-15.7"

MACOS_VERSION_PATH = get_macos_version_path()
BINARIES_PATH = MACOS_VERSION_PATH / "binaries"
MIG_BINARIES_PATH = BASE_PATH / "mig_services"


def check_prerequisites():
    """
    Checks for essential directories and prompts the user if something is missing.
    This corresponds to the initial stages of the pipeline.
    """
    console.print(Panel("🚀 [bold green]Starting Fuzzkit Pipeline[/bold green] - Prerequisite Check", expand=False))

    # Stage 1: Check for binaries directory (output of extract_services.sh)
    if not BINARIES_PATH.exists():
        console.print(f"\n[bold red]Error:[/bold red] The binaries directory is missing.")
        console.print(f"Expected path: [cyan]{BINARIES_PATH}[/cyan]")
        console.print("This is a required output of the first pipeline stage.")
        
        run_script = questionary.confirm(
            "Do you want to run the 'service_file_extractor/extract_services.sh' script now?",
            default=True
        ).ask()

        if not run_script:
            console.print("\nAborting. Please run the script manually and restart.")
            sys.exit(0)

        script_path = BASE_PATH / "service_file_extractor" / "extract_services.sh"
        if not script_path.is_file():
            console.print(f"\n[bold red]Error:[/bold red] Script not found at {script_path}. Aborting.")
            sys.exit(1)

        console.print(f"\n[bold green]Running script:[/] {script_path}")
        try:
            # Using Popen to stream output in real-time
            process = subprocess.Popen(
                ["sh", str(script_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=script_path.parent
            )

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    console.print(output.strip())
            
            rc = process.poll()
            if rc != 0:
                console.print(f"\n[bold red]Script failed with exit code {rc}.[/bold red]")
                sys.exit(1)

        except Exception as e:
            console.print(f"\n[bold red]An error occurred while running the script:[/bold red] {e}")
            sys.exit(1)

        # Re-check after running the script
        if not BINARIES_PATH.exists():
            console.print(f"\n[bold red]Error:[/bold red] Binaries directory still not found after running the script. Aborting.")
            sys.exit(1)
    
    console.print(f"✅ Binaries directory found: [cyan]{BINARIES_PATH}[/cyan]")

    # Stage 2: Check for MIG binaries directory (output of manual processing)
    if not MIG_BINARIES_PATH.exists():
        console.print(f"\n[bold red]Error:[/bold red] The MIG binaries directory is missing.")
        console.print(f"Expected path: [cyan]{MIG_BINARIES_PATH}[/cyan]")
        console.print("Please prepare the MIG binaries directory and restart the pipeline.")
        sys.exit(1)

    console.print(f"✅ MIG Binaries directory confirmed ready: [cyan]{MIG_BINARIES_PATH}[/cyan]\n")


def select_service(default_service=None):
    """
    Lets the user select a service from the mig_binaries directory.
    """
    try:
        services = [d.name for d in MIG_BINARIES_PATH.iterdir() if d.is_dir()]
        if not services:
            console.print("[bold red]Error:[/bold red] No service directories found in the MIG binaries path.")
            console.print(f"Please check the contents of: [cyan]{MIG_BINARIES_PATH}[/cyan]")
            return None
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] MIG binaries path not found: {MIG_BINARIES_PATH}")
        return None

    sorted_services = sorted(services, key=str.lower)
    
    # Create choices with enumeration
    choices = [Choice(title=f"[{i+1}] {s}", value=s) for i, s in enumerate(sorted_services)]

    # Set the default value for questionary to remember the last selection
    default_value = None
    if default_service and default_service in sorted_services:
        default_value = default_service

    selected_service = questionary.select(
        "Please select a service to work on:",
        choices=choices,
        default=default_value
    ).ask()
    
    return selected_service

def get_binary_path_for_service(service_name):
    """Finds the binary path for a given service name from the summary file."""
    summary_file = MACOS_VERSION_PATH / "launchd_summary.json"
    if not summary_file.exists():
        console.print(f"[bold red]Error:[/bold red] launchd_summary.json not found at {summary_file}")
        return None

    with open(summary_file, 'r') as f:
        data = json.load(f)

    for service in data.get("services", []):
        if service.get("label") == service_name:
            return service.get("program")

    console.print(f"[bold yellow]Warning:[/bold yellow] Could not find program path for service '{service_name}'.")
    return None

def manage_workspace(service_name, last_workspace=None):
    """
    Manages existing workspaces for a service or creates a new one by matching binary paths.
    """
    SERVICES_ROOT_PATH.mkdir(exist_ok=True)

    binary_path = get_binary_path_for_service(service_name)
    if not binary_path:
        console.print("[bold red]Could not determine binary path, cannot manage workspaces.[/bold red]")
        return None, None # Return None for both workspace and action

    # Find existing workspaces by matching the library_path in service.json
    existing_workspaces = []
    if SERVICES_ROOT_PATH.exists():
        for potential_ws in SERVICES_ROOT_PATH.iterdir():
            if not potential_ws.is_dir():
                continue
            
            service_json_path = potential_ws / "service.json"
            if service_json_path.exists():
                try:
                    with open(service_json_path, 'r') as f:
                        data = json.load(f)
                    if data.get("library_path") == binary_path:
                        existing_workspaces.append(potential_ws.name)
                except (json.JSONDecodeError, IOError) as e:
                    console.print(f"[yellow]Warning: Could not read or parse {service_json_path}: {e}[/yellow]")

    sorted_workspaces = sorted(existing_workspaces)
    
    # Enumerate choices for display
    workspace_choices = [Choice(title=f"[{i+1}] {ws}", value=ws) for i, ws in enumerate(sorted_workspaces)]

    choices = workspace_choices + [
        questionary.Separator(),
        Choice(title="[+] Create New Version...", value="Create New Version..."),
        Choice(title="[<-] Back to service selection", value="Back to service selection")
    ]

    # Set default value to remember the last selection
    default_value = None
    if last_workspace and last_workspace in [c.value for c in choices if isinstance(c, Choice)]:
        default_value = last_workspace

    workspace = questionary.select(
        f"Select a workspace for '{service_name}' (binary: {binary_path}):",
        choices=choices,
        default=default_value
    ).ask()

    if workspace is None or workspace == "Back to service selection":
        return None, "back"
    elif workspace == "Create New Version...":
        # Determine the next version number based on existing conventions
        prefix = f"{service_name}_v"
        versions = [int(d.split('_v')[-1]) for d in existing_workspaces if d.startswith(prefix) and d.split('_v')[-1].isdigit()]
        new_version_num = max(versions) + 1 if versions else 1
        new_workspace_name = f"{service_name}_v{new_version_num}"
        
        console.print(f"\n[bold green]Creating new workspace:[/] [yellow]{new_workspace_name}[/yellow]")
        
        # --- Load data from mig_information.json ---
        mig_info_path = MIG_BINARIES_PATH / service_name / "mig_information.json"
        subsystem_num = 0
        dispatch_routines = []
        dispatch_routine_offsets = []

        if mig_info_path.exists():
            try:
                with open(mig_info_path, 'r') as f:
                    mig_data = json.load(f)
                
                subsystem_num = mig_data.get("subsystem_count", 0)
                subsystems = mig_data.get("subsystems", [])
                
                for sub in subsystems:
                    routine = sub.get("routine", {})
                    if "name" in routine:
                        dispatch_routines.append(routine["name"])
                    if "address" in routine:
                        addr_str = routine["address"]
                        try:
                            addr_val = int(addr_str, 16)
                            # Convert VM address to file offset if necessary (assuming 0x100000000 base)
                            if addr_val >= 0x100000000:
                                addr_val -= 0x100000000
                            dispatch_routine_offsets.append(hex(addr_val))
                        except ValueError:
                            dispatch_routine_offsets.append(addr_str)

                console.print(f"✅ Loaded data from {mig_info_path.name}")

            except (json.JSONDecodeError, IOError) as e:
                console.print(f"[yellow]Warning: Could not parse {mig_info_path.name}: {e}. Using default values.[/yellow]")
        else:
            console.print(f"[yellow]Warning: {mig_info_path.name} not found. Using default values for service.json.[/yellow]")
        # --- End of loading data ---

        new_workspace_path = SERVICES_ROOT_PATH / new_workspace_name
        new_workspace_path.mkdir(exist_ok=True)

        # Create the service.json file with the binary path and MIG info
        service_json_content = {
            "library_path": binary_path,
            "start_function": "",
            "subsystem_num": subsystem_num,
            "dispatch_routines": dispatch_routines,
            "dispatch_routine_offsets": dispatch_routine_offsets,
            "fuzz": {
                "enabled": True,
                "instrument_module": Path(binary_path).name,
                "iterations": 1000,
                "threads": 5
            }
        }
        with open(new_workspace_path / "service.json", 'w') as f:
            json.dump(service_json_content, f, indent=2)

        console.print(f"Workspace created at: [cyan]{new_workspace_path}[/cyan]")
        # After creation, loop back to the workspace selection with the new one highlighted
        return new_workspace_name, "created"
    elif workspace:
        manage_workspace_actions(workspace)
        return workspace, "actions_done" # Return the workspace to remember it


def manage_workspace_actions(workspace_name):
    """
    Shows the main action menu for a selected workspace.
    """
    while True:
        choices = [
            Choice(title="[1] Generate Message Function Management", value="Generate Message Function Management"),
            Choice(title="[2] Build Fuzzer", value="Build Fuzzer"),
            questionary.Separator(),
            Choice(title="[<-] Back to workspace selection", value="Back to workspace selection")
        ]
        action = questionary.select(
            f"Actions for workspace '{workspace_name}':",
            choices=choices
        ).ask()

        if action is None or action == "Back to workspace selection":
            break
        elif action == "Generate Message Function Management":
            manage_message_generation(workspace_name)
        elif action == "Build Fuzzer":
            console.print(f"\n[bold cyan]Action:[/bold cyan] Triggering 'Build Fuzzer' for [yellow]{workspace_name}[/yellow]...")

            builder_script_path = BASE_PATH / "fuzzkit" / "fuzzer_builder.py"
            if not builder_script_path.is_file():
                console.print(f"\n[bold red]Error:[/bold red] Build script not found at {builder_script_path}. Aborting.")
                continue

            command = [
                "sudo",
                "-E",
                sys.executable,  # Use the same python interpreter
                str(builder_script_path),
                "build",
                "-d",
                workspace_name
            ]

            console.print(f"\n[bold green]Running command:[/] {' '.join(command)}")
            try:
                # Using Popen to stream output in real-time
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=BASE_PATH  # Run from the project root
                )

                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        # fuzzer_builder.py already has good output, just print it
                        console.print(output.strip())
                
                rc = process.poll()
                if rc == 0:
                    console.print(f"\n[bold green]✅ Successfully built fuzzer for {workspace_name}.[/bold green]\n")
                else:
                    console.print(f"\n[bold red]Script failed with exit code {rc}.[/bold red]\n")

            except Exception as e:
                console.print(f"\n[bold red]An error occurred while running the build script:[/bold red] {e}\n")



def manage_message_generation(workspace_name):
    """
    Shows the sub-menu for message generation, based on chat_with_llm.ipynb.
    """
    console.print(Panel(f"Entering Message Generation Management for [yellow]{workspace_name}[/yellow]", expand=False))
    
    generator_script_path = BASE_PATH / "fuzzkit" / "message_generator.py"
    if not generator_script_path.is_file():
        console.print(f"\n[bold red]Error:[/bold red] Message generator script not found at {generator_script_path}. Aborting.")
        return

    def run_generator_command(command_args):
        command = [
            sys.executable,
            str(generator_script_path)
        ] + command_args

        console.print(f"\n[bold green]Running command:[/] {' '.join(command)}")
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=BASE_PATH
            )
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    console.print(output.strip())
            rc = process.poll()
            if rc == 0:
                console.print(f"\n[bold green]✅ Command completed successfully.[/bold green]\n")
            else:
                console.print(f"\n[bold red]❌ Command failed with exit code {rc}.[/bold red]\n")
        except Exception as e:
            console.print(f"\n[bold red]An error occurred while running the script:[/bold red] {e}\n")

    while True:
        choices = [
            Choice(title="[0] Check LLM Configuration", value="check-config"),
            questionary.Separator(),
            Choice(title="[1] Get Description (Default)", value="desc-default"),
            Choice(title="[2] Get Description (Two-Stage)", value="desc-twostage"),
            Choice(title="[3] Get Description (One-Shot)", value="desc-oneshot"),
            Choice(title="[4] Get Description (CoT)", value="desc-cot"),
            Choice(title="[5] Generate Code from Description", value="generate-code"),
            Choice(title="[6] Update Code with Checker", value="update-checker"),
            Choice(title="[7] Update Code with Semantics", value="update-semantics"),
            questionary.Separator(),
            Choice(title="[<-] Back to workspace actions", value="back")
        ]
        choice = questionary.select(
            "Select a message generation step:",
            choices=choices
        ).ask()

        if choice is None or choice == "back":
            break
        elif choice == "check-config":
            run_generator_command(["check-config"])
        elif choice == "desc-default":
            run_generator_command(["generate-constraints", workspace_name, "--method", "default"])
        elif choice == "desc-twostage":
            run_generator_command(["generate-constraints", workspace_name, "--method", "twostage"])
        elif choice == "desc-oneshot":
            run_generator_command(["generate-constraints", workspace_name, "--method", "oneshot"])
        elif choice == "desc-cot":
            run_generator_command(["generate-constraints", workspace_name, "--method", "cot"])
        elif choice == "generate-code":
            run_generator_command(["generate-code", workspace_name])
        elif choice == "update-semantics":
            run_generator_command(["update-semantics", workspace_name])
        elif choice == "update-checker":
            # This corresponds to regenerate_all_message_with_semantics
            run_generator_command(["regenerate-code", workspace_name])
        else:
            console.print(f"\n[bold red]Error:[/bold red] Unknown option '{choice}'.\n")


def main_loop():
    """
    The main interactive loop of the application.
    """
    last_service = None
    last_workspace = None
    
    while True:
        service = select_service(default_service=last_service)
        if service is None:
            # This happens if the user cancels the selection (e.g., Ctrl+C)
            raise KeyboardInterrupt
        
        last_service = service
        
        # Loop for workspace management until the user goes back
        while True:
            workspace, action = manage_workspace(service, last_workspace=last_workspace)
            
            if action == "back":
                last_workspace = None # Reset workspace when going back to service selection
                break
            elif action == "created":
                last_workspace = workspace # Remember the newly created workspace
                # Loop back to show it selected
                continue
            elif action == "actions_done":
                last_workspace = workspace # Remember the workspace we just acted on
                # Loop back to the workspace menu
                continue
            elif workspace is None:
                # This can happen if binary path is not found
                break

if __name__ == "__main__":
    try:
        check_prerequisites()
        main_loop()
        console.print("\n[bold]Goodbye![/bold]\n")
    except (KeyboardInterrupt, TypeError): # TypeError can be raised by questionary on Ctrl+C
        console.print("\n[bold]Goodbye![/bold]\n")
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {e}")
        import traceback
        traceback.print_exc()

