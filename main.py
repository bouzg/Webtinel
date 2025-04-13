#!/usr/bin/env python
# coding=utf8
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     Webtinel - Advanced Webshell Detector                    ║
║                     =====================================                    ║
║                                                                              ║
║  An advanced cybersecurity tool for detecting malicious webshells            ║
║  Supports PHP, JSP, and Java files with advanced pattern analysis            ║                                         ║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import multiprocessing
from multiprocessing import Process, Manager, Queue
import os
import sys
import re
import json
from typing import List, Dict, Optional
import logging
from datetime import datetime
from colorama import init, Fore, Back, Style
import threading
from queue import Empty

init()

logging.basicConfig(
    level=logging.INFO,
    format=f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - {Fore.GREEN}%(levelname)s{Style.RESET_ALL} - %(message)s'
)
logger = logging.getLogger(__name__)

class Consumer(multiprocessing.Process):
    """Consumer class processes files in parallel to detect webshell patterns."""
    def __init__(self, result_list, task_queue, webshell_rules):
        super().__init__()
        self.task_queue = task_queue
        self.webshell_rules = webshell_rules
        self.result_list = result_list
        self._stop_event = multiprocessing.Event()

    def run(self):
        """Process files and detect webshell patterns with error handling."""
        while not self._stop_event.is_set():
            try:
                file_name = self.task_queue.get(timeout=1)
                if file_name is None:
                    break
                self.process_file(file_name)
                self.task_queue.task_done()
            except Empty:
                break
            except Exception as e:
                logger.error(f"{Fore.RED}Error processing file: {e}{Style.RESET_ALL}")

    def process_file(self, file_name: str) -> None:
        """Check each file for webshell patterns with improved detection."""
        try:
            with open(file_name, 'r', encoding='utf-8', errors='ignore') as fopen:
                filestr = fopen.read()
                for rule in self.webshell_rules:
                    rule = rule.strip()
                    if re.findall(rule, filestr, re.IGNORECASE):
                        code = self.get_code(file_name, rule)
                        result_dict = {
                            "regex": rule,
                            "code": code,
                            "file_name": file_name,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "severity": self.calculate_severity(code),
                            "file_size": os.path.getsize(file_name),
                            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_name)).strftime("%Y-%m-%d %H:%M:%S")
                        }
                        self.result_list.append(result_dict)
        except Exception as e:
            logger.error(f"{Fore.RED}Error reading file {file_name}: {e}{Style.RESET_ALL}")

    def calculate_severity(self, code: str) -> str:
        """Calculate the severity of the detected webshell with  detection patterns."""
        critical_risk_patterns = ['system(', 'passthru(', 'pcntl_exec(']
        high_risk_patterns = ['eval(', 'exec(', 'shell_exec(', 'assert(']
        medium_risk_patterns = ['base64_decode(', 'gzinflate(', 'str_rot13(', 'preg_replace']
        
        if any(pattern in code.lower() for pattern in critical_risk_patterns):
            return "CRITICAL"
        if any(pattern in code.lower() for pattern in high_risk_patterns):
            return "HIGH"
        if any(pattern in code.lower() for pattern in medium_risk_patterns):
            return "MEDIUM"
        return "LOW"

    def get_code(self, file_name: str, rule: str) -> str:
        """Extract the code context that matches the rule."""
        try:
            with open(file_name, 'r', encoding='utf-8', errors='ignore') as fopen:
                lines = fopen.readlines()
                for i, line in enumerate(lines):
                    if re.findall(rule, line, re.IGNORECASE):
                        context = []
                        start = max(0, i - 2)
                        end = min(len(lines), i + 3)
                        for j in range(start, end):
                            if j == i:
                                context.append(f">>> {lines[j].strip()}")
                            else:
                                context.append(f"    {lines[j].strip()}")
                        return "\n".join(context)
        except Exception as e:
            logger.error(f"{Fore.RED}Error getting code from {file_name}: {e}{Style.RESET_ALL}")
        return ""

def show_banner():
    """Display the  application banner."""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                Webtinel - Advanced Webshell Detector Menu                  ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}1. Start Deep Scan
2. View Documentation
3. About Webtinel
4. Exit{Style.RESET_ALL}
"""
    print(banner)

def list_directory_codes(root_dir: str) -> List[str]:
    """List all PHP, JSP, and Java files in the directory."""
    file_list = []
    allowed_extensions = {'.php', '.jsp', '.java'}
    try:
        for parent, _, fileNames in os.walk(root_dir):
            for name in fileNames:
                if any(name.endswith(ext) for ext in allowed_extensions):
                    file_list.append(os.path.join(parent, name))
    except Exception as e:
        logger.error(f"{Fore.RED}Error listing directory: {e}{Style.RESET_ALL}")
    return file_list

def read_rule(rule_file_path: str) -> List[str]:
    """Read the webshell rules from the provided file."""
    try:
        with open(rule_file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        logger.error(f"{Fore.RED}Error reading rules file: {e}{Style.RESET_ALL}")
        return []

def print_visualization(result_list: List[Dict]) -> None:
    """Print results with  formatting and severity indicators."""
    if result_list:
        logger.info(f"\n{Fore.CYAN}═══════════════════ Threat Detection Results ═══════════════════{Style.RESET_ALL}")
        for result in result_list:
            severity_color = {
                "CRITICAL": Fore.RED + Style.BRIGHT,
                "HIGH": Fore.RED,
                "MEDIUM": Fore.YELLOW,
                "LOW": Fore.GREEN
            }.get(result['severity'], Fore.WHITE)
            
            print(f"\n{Fore.BLUE}╔════ Threat Details ════{Style.RESET_ALL}")
            print(f"{Fore.CYAN}║ File:{Style.RESET_ALL} {result['file_name']}")
            print(f"{Fore.CYAN}║ Size:{Style.RESET_ALL} {result['file_size']} bytes")
            print(f"{Fore.CYAN}║ Last Modified:{Style.RESET_ALL} {result['last_modified']}")
            print(f"{Fore.CYAN}║ Detection Time:{Style.RESET_ALL} {result['timestamp']}")
            print(f"{Fore.CYAN}║ Threat Level:{Style.RESET_ALL} {severity_color}{result['severity']}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}║ Matched Pattern:{Style.RESET_ALL} {result['regex']}")
            print(f"{Fore.CYAN}║ Code Context:{Style.RESET_ALL}\n{result['code']}")
            print(f"{Fore.BLUE}╚{'═' * 60}{Style.RESET_ALL}")
    else:
        logger.info(f"\n{Fore.GREEN}No malicious patterns detected.{Style.RESET_ALL}")

def show_help():
    """Display  help information."""
    help_text = f"""
{Fore.CYAN}═══════════════════ Webtinel Documentation ═══════════════════

Usage: python script.py <directory_path>

Advanced Detection Capabilities:
- Deep scanning of PHP, JSP, and Java files
- Advanced powered pattern analysis
- Context-aware code analysis
- Multi-threaded processing

Severity Classifications:
{Fore.RED + Style.BRIGHT}CRITICAL{Style.RESET_ALL}: Immediate security threat detected
{Fore.RED}HIGH{Style.RESET_ALL}: Serious security risk identified
{Fore.YELLOW}MEDIUM{Style.RESET_ALL}: Potential security concern
{Fore.GREEN}LOW{Style.RESET_ALL}: Minor suspicious pattern

Press Enter to return to main menu...{Style.RESET_ALL}
"""
    print(help_text)
    input()

def show_about():
    about_text = f"""
{Fore.CYAN}═══════════════════ About Webtinel ═══════════════════

Webtinel - Advanced Webshell Detector

A cybersecurity tool leveraging advanced
algorithms and pattern analysis to detect
webshells and malicious code injections.

Key Features:
- Advanced Detection
- Multi-threaded Analysis
- Context Pattern Matching
- Advanced Threat Classification
- Detailed Security Reporting
- Cross-platform Compatibility

Press Enter to return to main menu...{Style.RESET_ALL}
"""
    print(about_text)
    input()

def main():
    """ main function with improved error handling and user interface."""
    while True:
        show_banner()
        choice = input(f"{Fore.CYAN}Enter your choice (1-4): {Style.RESET_ALL}")

        if choice == "1":
            file_path = input(f"{Fore.CYAN}Please specify the folder to scan: {Style.RESET_ALL}")
            
            if not os.path.exists(file_path):
                logger.error(f"{Fore.RED}Invalid folder path. Please specify a correct path.{Style.RESET_ALL}")
                continue

            logger.info(f"{Fore.GREEN}Initiating scan on: {file_path}{Style.RESET_ALL}")
            file_list = list_directory_codes(file_path)
            webshell_rule_path = "./rules/rule.txt"

            if not os.path.exists(webshell_rule_path):
                logger.error(f"{Fore.RED}Rules file not found: {webshell_rule_path}{Style.RESET_ALL}")
                return

            webshell_rules = read_rule(webshell_rule_path)

            if not webshell_rules:
                logger.error(f"{Fore.RED}No detection rules found{Style.RESET_ALL}")
                return

            print(f"\n{Fore.GREEN}Scan Overview:")
            for i, file in enumerate(file_list[:10], 1):
                print(f"{Fore.CYAN}  {i}. {file}{Style.RESET_ALL}")
            if len(file_list) > 10:
                print(f"{Fore.CYAN}  ... and {len(file_list) - 10} more files{Style.RESET_ALL}")
            
            logger.info(f"{Fore.CYAN}Initializing security scan...{Style.RESET_ALL}")
            
            mgr = multiprocessing.Manager()
            result_list = mgr.list()
            task_queue = multiprocessing.JoinableQueue()

            for file_path in file_list:
                task_queue.put(file_path)

            num_processors = min(multiprocessing.cpu_count(), 4)
            processes = []

            logger.info(f"{Fore.CYAN}Launching {num_processors} analysis threads...{Style.RESET_ALL}")

            for _ in range(num_processors):
                process = Consumer(result_list, task_queue, webshell_rules)
                processes.append(process)
                process.start()

            for _ in range(num_processors):
                task_queue.put(None)

            for process in processes:
                process.join()

            print_visualization(result_list)
            logger.info(f"{Fore.GREEN}Security scan completed successfully{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press Enter to return to main menu...{Style.RESET_ALL}")

        elif choice == "2":
            show_help()
        elif choice == "3":
            show_about()
        elif choice == "4":
            print(f"\n{Fore.GREEN}Thank you for using Webtinel!{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"{Fore.RED}Invalid selection. Please choose 1-4.{Style.RESET_ALL}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)
