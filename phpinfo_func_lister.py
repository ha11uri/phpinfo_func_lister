# Author: ha11uri
# Repo: https://github.com/ha11uri/phpinfo_func_lister
# Python Version: 3.6+
# Usage:
#   python phpinfo_func_lister.py --url <URL> [--headers <HEADER_1> <HEADER_2>...]
#   python phpinfo_func_lister.py --file <FILE_PATH>

import argparse
import requests

def list_allowed_dangerous_functions(phpinfo_output):
    """
    Parses the output of phpinfo() to identify and list dangerous functions that are allowed by the server.

    Args:
        phpinfo_output: A string containing the HTML output of phpinfo().

    Returns:
        A list of dangerous functions that are not disabled.
        Returns an empty list if 'disable_functions' is not found or if no dangerous functions are allowed.
    """
    disabled_functions = []
    # The separator string for disable_functions in phpinfo() output
    separator = 'class="e">disable_functions</td><td class="v">'

    if separator in phpinfo_output:
        try:
            # Extract the comma-separated list of disabled functions
            raw_list = phpinfo_output.split(separator)[1].split("</td>")[0]
            # Clean up the list, removing empty strings
            disabled_functions = [func.strip() for func in raw_list.split(',') if func.strip()]
        except IndexError:
            # This can happen if the HTML is malformed.
            # We can treat this as 'not found'.
            return None
    else:
        # Separator not found, so we can't determine the disabled functions.
        return None

    # A curated list of functions often considered "dangerous" if left enabled, with descriptions.
    DANGEROUS_FUNCTIONS_DESCRIPTIONS = {
        'pcntl_alarm': 'Can set a timer that delivers a signal to the process, potentially leading to race conditions or denial of service.',
        'pcntl_fork': 'Creates a child process, which can be used to background malicious tasks or create fork bombs.',
        'pcntl_waitpid': 'Can be used to wait for state changes in a child process, useful for coordinating multi-stage attacks.',
        'pcntl_wait': 'Similar to pcntl_waitpid, used for process control.',
        'pcntl_wifexited': 'Checks if a child process has terminated normally. Used in process control.',
        'pcntl_wifstopped': 'Checks if a child process is stopped. Used in process control.',
        'pcntl_wifsignaled': 'Checks if a child process was terminated by a signal. Used in process control.',
        'pcntl_wifcontinued': 'Checks if a child process was resumed. Used in process control.',
        'pcntl_wexitstatus': 'Returns the exit code of a terminated child process. Used in process control.',
        'pcntl_wtermsig': 'Returns the signal that caused a child process to terminate. Used in process control.',
        'pcntl_wstopsig': 'Returns the signal that caused a child process to stop. Used in process control.',
        'pcntl_signal': 'Installs a signal handler, which can be used to intercept or manipulate process signals.',
        'pcntl_signal_get_handler': 'Gets the current signal handler for a signal.',
        'pcntl_signal_dispatch': 'Dispatches pending signals, can be used to trigger signal handlers.',
        'pcntl_get_last_error': 'Retrieves the last error number set by a pcntl function.',
        'pcntl_strerror': 'Retrieves the system error message for a given error number.',
        'pcntl_sigprocmask': 'Can be used to block or unblock signals, potentially preventing a process from being terminated.',
        'pcntl_sigwaitinfo': 'Waits for a signal, can be used to synchronize malicious activities.',
        'pcntl_sigtimedwait': 'Waits for a signal for a specified amount of time.',
        'pcntl_exec': 'Executes a program in the current process space, effectively replacing the PHP process with another program.',
        'pcntl_getpriority': 'Gets the priority of a process.',
        'pcntl_setpriority': 'Sets the priority of a process, can be used to make a malicious process more or less likely to be scheduled.',
        'pcntl_async_signals': 'Enables or disables asynchronous signal handling.',
        'error_log': 'Can be used to write to arbitrary files on the system, potentially leading to file creation or corruption.',
        'system': 'Executes an external program and displays the output. A direct way to run shell commands.',
        'exec': 'Executes an external program. Can be used for remote code execution.',
        'shell_exec': "Executes a command via shell and returns the complete output as a string.",
        'popen': 'Opens a pipe to a process executed by forking the command given by command.',
        'proc_open': 'Executes a command and opens file pointers for input/output.',
        'passthru': 'Executes an external program and displays raw output.',
        'link': 'Creates a hard link, which can be used to manipulate files and permissions.',
        'symlink': 'Creates a symbolic link, which can be used to point to and access sensitive files.',
        'syslog': 'Can be used to write messages to the system log, a tactic that could potentially flood the log or conceal malicious activities.',
        'ld': 'Dynamically loads a new library into the PHP runtime.',
        'mail': 'Can be used to send spam or phishing emails, or to exfiltrate data.',
        'imap_open': 'Can be used to open a mailbox on an IMAP server, potentially accessing sensitive emails.',
        'imap_mail': 'Sends an email.',
        'mb_send_mail': 'Sends an email with multibyte character support.',
        'libvirt_connect': 'Connects to a hypervisor, potentially allowing for virtual machine manipulation or escape.',
        'gnupg_init': 'Initializes a GnuPG resource, which can be used for encryption and decryption, potentially to exfiltrate data securely.'
    }

    # Find the intersection between dangerous functions and enabled functions
    allowed_dangerous_functions = {
        func: desc for func, desc in DANGEROUS_FUNCTIONS_DESCRIPTIONS.items() if func not in disabled_functions
    }

    return allowed_dangerous_functions

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Find allowed dangerous functions from phpinfo().")
    parser.add_argument("--url", help="URL of the phpinfo() page.")
    parser.add_argument("--file", help="Path to a local file containing phpinfo() output.")
    parser.add_argument("--headers", nargs='+', help="Custom headers to include in the request, in 'Key:Value' format.")

    args = parser.parse_args()
    phpinfo_content = ""

    if args.url:
           custom_headers = {}
           if args.headers:
               for header in args.headers:
                   try:
                       key, value = header.split(':', 1)
                       custom_headers[key.strip()] = value.strip()
                   except ValueError:
                       print(f"Warning: Skipping invalid header format: {header}")
   
           try:
               response = requests.get(args.url, headers=custom_headers)
               response.raise_for_status()  # Raise an exception for bad status codes
               phpinfo_content = response.text
           except requests.exceptions.RequestException as e:
               print(f"Error fetching URL: {e}")
               exit(1)
       elif args.file:
           try:
               with open(args.file, 'r') as f:
                   phpinfo_content = f.read()
           except FileNotFoundError:
               print(f"Error: File not found at {args.file}")
               exit(1)
       else:
           parser.print_help()
           exit(1)
   
       allowed_functions = list_allowed_dangerous_functions(phpinfo_content)
   
       if allowed_functions is None:
           print("Error: Could not find the 'disable_functions' list in the provided input.")
           print("Please ensure the URL or file contains valid phpinfo() output.")
       elif allowed_functions:
           print("The following dangerous functions are allowed on the server:")
           for func, desc in allowed_functions.items():
               print(f"- {func}: {desc}")
       else:
           print("All known dangerous functions are disabled.")