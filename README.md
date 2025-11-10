PHPInfo Function Lister

phpinfo_func_lister.py is a Python script designed for penetration testers and security auditors to quickly analyze the output of a PHP phpinfo() page. It parses the page to identify which "dangerous" PHP
functions are enabled on the server, providing valuable insights into potential security weaknesses.

Why is this useful for Pentesters?

During a web application penetration test, discovering a phpinfo() page is a common finding. This page contains a wealth of information about the server's configuration, including the disable_functions
directive, which lists functions that have been disabled for security reasons.

Manually cross-referencing the enabled functions with a list of potentially dangerous ones is tedious. This tool automates that process. By simply pointing the script at a phpinfo() page, a pentester can
instantly see if functions that could lead to Remote Code Execution (RCE), file system manipulation, or data exfiltration (like system, exec, shell_exec, proc_open, etc.) are available for exploitation.

Features
   - Parses `phpinfo()` from URL or Local File: Analyze a live phpinfo() page or a saved HTML file.
   - Identifies Dangerous Functions: Checks against a curated list of functions often considered risky if enabled.
   - Provides Pentesting Context: Outputs a description for each allowed function, explaining its potential use in an attack.
   - Supports Custom Headers: Allows you to add custom HTTP headers to the request, which can be crucial for accessing protected phpinfo() pages.
   - User-Friendly Output: Presents the findings in a clear, easy-to-read list.

Requirements
The script requires Python 3.6+ and the requests library.

You can install the requests library using pip:
  1 pip install requests

Usage
The script can be run from the command line with several options.
  1. Analyze a `phpinfo()` page from a URL:
    python phpinfo_func_lister.py --url http://example.com/phpinfo.php
  2. Analyze a `phpinfo()` page saved as a local file:
    python phpinfo_func_lister.py --file /path/to/phpinfo.html
  3. Analyze a URL that requires custom headers:

You can pass one or more headers using the --headers argument.
    python phpinfo_func_lister.py --url http://dev.example.com/phpinfo.php --headers "Authorization: Bearer <TOKEN>" "Special-Dev: only4dev"

Example Output
  If the script finds allowed dangerous functions, the output will look like this:
   1 The following dangerous functions are allowed on the server:
   2 - system: Executes an external program and displays the output. A direct way to run shell commands.
   3 - exec: Executes an external program. Can be used for remote code execution.
   4 - shell_exec: Executes a command via shell and returns the complete output as a string.
   5 - proc_open: Executes a command and opens file pointers for input/output.
   6 - symlink: Creates a symbolic link, which can be used to point to and access sensitive files.

If the disable_functions list cannot be found, it will produce an error:
   1 Error: Could not find the 'disable_functions' list in the provided input.
   2 Please ensure the URL or file contains valid phpinfo() output.

If all known dangerous functions are properly disabled, it will report:
   1 All known dangerous functions are disabled.

