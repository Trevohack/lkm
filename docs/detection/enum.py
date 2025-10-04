#!/usr/bin/python3  
import os
import subprocess
from rich.console import Console
from rich.table import Table

console = Console()



paths = {
    "Tracing Filter Functions": [
        "/sys/kernel/tracing/available_filter_functions",
        "/sys/debug/kernel/tracing/available_filter_functions",
        "/sys/kernel/tracing/available_filter_functions_addrs",
        "/sys/debug/kernel/tracing/available_filter_functions_addrs",
        "/sys/kernel/tracing/enabled_functions",
        "/sys/debug/kernel/tracing/enabled_functions",
        "/sys/kernel/tracing/touched_functions",
        "/sys/kernel/tracing/kprobe_events"
    ],
    "Kernel Modules": [
        "/sys/module/*",
        "/proc/modules",
        "/proc/kallsyms",
        "/proc/vmallocinfo",
        "/proc/sys/kernel/tainted"
    ],
    "BPF Maps": ["/sys/fs/bpf/"],
    "Kernel Logs": [
        "/var/log/dmesg*",
        "/var/log/kern.log",
        "/dev/kmsg"
    ]
}

def check_paths(category, paths_list):
    table = Table(title=category)
    table.add_column("Path", style="cyan")
    table.add_column("Exists", style="magenta")
    table.add_column("Sample Content", style="green")

    for path in paths_list:
        exists = os.path.exists(path) or bool(subprocess.run(f"ls {path}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout)
        sample = ""
        try:
            if exists:
                if os.path.isdir(path):
                    sample = ", ".join(os.listdir(path)[:5])
                else:
                    with open(path, 'r', errors='ignore') as f:
                        sample = f.read(200).replace("\n", " ")
        except Exception as e:
            sample = f"Error: {e}"

        table.add_row(path, str(exists), sample)
    console.print(table)

def check_commands():
    table = Table(title="Kernel Logs via Commands")
    table.add_column("Command", style="cyan")
    table.add_column("Output Sample", style="green")

    commands = [
        "dmesg | tail -n 10",
        "journalctl -k -n 10"
    ]
    for cmd in commands:
        try:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sample = result.stdout.decode().replace("\n", " ")
        except Exception as e:
            sample = f"Error: {e}"
        table.add_row(cmd, sample)
    console.print(table)

def enumerate_ko_files():
    console.print("\n[bold yellow]Enumerating loaded .ko files...[/bold yellow]")
    try:
        result = subprocess.run("find /lib/modules/$(uname -r) -type f -name '*.ko'", shell=True, stdout=subprocess.PIPE)
        ko_files = result.stdout.decode().splitlines()
        for f in ko_files[:20]: 
            console.print(f"[green]{f}[/green]")
        if len(ko_files) > 20:
            console.print(f"... and {len(ko_files)-20} more")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")

def main():
    console.print("[bold underline magenta]Rootkit & Kernel Enumerator[/bold underline magenta]\n")
    for category, p_list in paths.items():
        check_paths(category, p_list)
    check_commands()
    enumerate_ko_files()

if __name__ == "__main__":
    main()

