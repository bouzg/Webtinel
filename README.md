# Webtinel - Advanced Webshell Detector

Webtinel is a powerful cybersecurity tool designed to detect malicious webshells in PHP, JSP, and Java files. By leveraging advanced pattern analysis and multi-threaded processing, Webtinel provides quick and accurate identification of potential security threats in web applications.

## Features

- **Multi-threaded analysis** for faster scanning.
- **Advanced pattern detection** for webshells in PHP, JSP, and Java files.
- **Contextual threat reporting** with severity classification (Critical, High, Medium, Low).
- **Detailed file analysis** with matched patterns and code context.
- Cross-platform compatibility for easy integration.

## How to Use

1. Clone the repository:
    ```bash
    git clone https://github.com/bouzg/webtinel.git
    ```

2. Navigate to the project directory:
    ```bash
    cd webtinel
    ```

3. Run the tool with the directory you want to scan:
    ```bash
    python main.py /path/to/scan
    ```

4. View results with detailed threat information.

## Requirements

- Python 3.x
- `colorama` library for colored output

Install dependencies:
```bash
pip install -r requirements.txt
