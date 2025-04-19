# Python Port Scanner

A powerful, multi-threaded port scanner built in Python to identify open ports, services, and their details on a target host. This tool is designed for network administrators and security enthusiasts to perform efficient and detailed port scanning.

## Features

- **Custom Port Range Input**: Specify a single port or a range (e.g., "1-300").
- **Comprehensive Scanning**: Scans all ports within the specified range for TCP/UDP protocols.
- **Detailed Output**:
  - Port number
  - Protocol (TCP/UDP)
  - Service name
  - Service description
  - Status (Open/Closed)
  - Response time
- **Multi-threading**: Utilizes `ThreadPoolExecutor` for fast, parallel scanning.
- **Error Handling**: Robust input validation and exception handling for a smooth experience.
- **Progress Bar**: Displays scan progress using the `tqdm` library.
- **Color-coded Output**: Enhances readability with `colorama` for visual feedback.
- **Save Results**: Option to save scan results to a CSV file.
- **Timeout Settings**: Configurable timeout for port scanning.
- **Tabulated Output**: Presents results in a clean, organized table using `tabulate`.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/seiethereum/Port-Scanner.git
   cd port-scanner
   ```

2. Install dependencies for enhanced functionality:

   ```bash
   pip install tqdm colorama tabulate
   ```

   Note: The script works with Python's standard library alone, but the above packages provide progress bars, colored output, and formatted tables.

## Usage

1. Run the script:

   ```bash
   python port_scanner.py
   ```

2. Follow the prompts:

   - Enter the target IP address.
   - Specify the port range (e.g., "1-1000").
   - Set the timeout value (default: 1.0 seconds).
   - Set the number of threads (default: 100).

3. Wait for the scan to complete and view the results in the console.

4. Optionally, save the results to a CSV file when prompted.

## Example

```bash
$ python port_scanner.py
Enter target IP address: 192.168.1.1
Enter port range (e.g., 1-1000): 1-100
Enter timeout (seconds, default 1.0): 0.5
Enter number of threads (default 100): 50
Scanning ports: 100%|██████████| 100/100 [00:02<00:00, 45.12ports/s]
Results:
+------+----------+---------+------------------+--------+---------------+
| Port | Protocol | Service | Description      | Status | Response Time |
+------+----------+---------+------------------+--------+---------------+
| 22   | TCP      | ssh     | Secure Shell     | Open   | 0.021s        |
| 80   | TCP      | http    | Web Server       | Open   | 0.015s        |
| 23   | TCP      | telnet  | Telnet Protocol  | Closed | 0.500s        |
+------+----------+---------+------------------+--------+---------------+
Save results to CSV? (y/n): y
Results saved to scan_results_192.168.1.1.csv
```

## Notes

- The scanner includes a dictionary of common services for quick identification.
- For unknown ports, it uses `socket.getservbyport()` to attempt service identification.
- Multi-threading significantly speeds up scans for large port ranges.
- Comprehensive error handling ensures a robust user experience.
- Use responsibly and only scan hosts you have permission to test.

## Requirements

- Python 3.6+
- Optional dependencies:
  - `tqdm`: For progress bars
  - `colorama`: For colored console output
  - `tabulate`: For formatted table output

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss improvements or bugs.

## Disclaimer

This tool is for educational and ethical use only. Unauthorized scanning of networks or systems is illegal and unethical. Always obtain explicit permission before scanning any target.
