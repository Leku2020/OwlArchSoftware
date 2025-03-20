---
layout: software
title: OwlSearch
permalink: /owlsearch
---

[🔙 Go back home](/OwlArchSoftware/)
# OwlSearch - README

OwlSearch is a versatile command-line tool designed to query and retrieve information from various threat intelligence platforms, including VirusTotal, MalwareBazaar, AbuseIPDB, and Shodan. This README provides an overview of the tool's functionality, installation instructions, usage examples, and configuration details.

## Table of Contents
1. [Features](#features)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Usage](#usage)
   - [Interactive Help](#interactive-help)
   - [VirusTotal](#virustotal)
   - [MalwareBazaar](#malwarebazaar)
   - [AbuseIPDB](#abuseipdb)
   - [Shodan](#shodan)
   - [History](#history)
5. [Saving Results](#saving-results)
6. [Contributing](#contributing)
7. [License](#license)

---

## Features
- Query multiple threat intelligence platforms (VirusTotal, MalwareBazaar, AbuseIPDB, Shodan).
- Support for various search types such as IP addresses, domains, hashes, tags, signatures, and more.
- Ability to process queries from files or command-line arguments.
- Save query results to JSON files for later analysis.
- Maintain a history of past queries for reference.
- Interactive help for easy navigation of available options.

---

## Installation
1. **Prerequisites**:
   - Python 3.x installed on your system.
   - `requests`, `configparser`, and `argparse` libraries (usually included with Python).

2. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/owlSearch.git
   cd owlSearch
   ```

3. **Set Up Configuration**:
   Create a configuration file at `/usr/share/owlSearch/config.ini` with the following structure:
   ```ini
   [keys]
   VT_API_KEY = your_virustotal_api_key
   MB_AUTH_KEY = your_malwarebazaar_api_key
   ABUSEIPDB_API_KEY = your_abuseipdb_api_key
   SHODAN_API_KEY = your_shodan_api_key
   ```

4. **Make the Script Executable**:
   ```bash
   chmod +x owlSearch.py
   ```

5. **Run the Tool**:
   ```bash
   python owlSearch.py --help
   ```

---

## Configuration
The tool relies on API keys stored in a configuration file located at `/usr/share/owlSearch/config.ini`. Ensure that the file contains valid API keys for the services you intend to use. If the file is missing or improperly configured, the tool will exit with an error.

Example configuration file:
```ini
[keys]
VT_API_KEY = your_virustotal_api_key
MB_AUTH_KEY = your_malwarebazaar_api_key
ABUSEIPDB_API_KEY = your_abuseipdb_api_key
SHODAN_API_KEY = your_shodan_api_key
```

---

## Usage

### Interactive Help
To view detailed interactive help, run:
```bash
python owlSearch.py --help-interactive
```

### VirusTotal
Perform searches in VirusTotal using IPs, domains, or hashes.

#### Examples:
- Search by IP:
  ```bash
  python owlSearch.py --vt --ip 8.8.8.8
  ```
- Search multiple domains from a file:
  ```bash
  python owlSearch.py --vt --domain-file domains.txt
  ```

### MalwareBazaar
Query MalwareBazaar for malware samples, tags, signatures, and more.

#### Examples:
- Search by hash:
  ```bash
  python owlSearch.py --mb --hash d41d8cd98f00b204e9800998ecf8427e
  ```
- Download a sample:
  ```bash
  python owlSearch.py --mb --sample d41d8cd98f00b204e9800998ecf8427e
  ```

### AbuseIPDB
Check IP reputation, fetch blacklists, and retrieve reports.

#### Examples:
- Check an IP address:
  ```bash
  python owlSearch.py --abuseipdb --check-ip 192.168.1.1
  ```
- Fetch the blacklist:
  ```bash
  python owlSearch.py --abuseipdb --blacklist
  ```

### Shodan
Use Shodan to search for hosts, resolve domain names, and analyze queries.

#### Examples:
- Count results for a query:
  ```bash
  python owlSearch.py --shodan --count "port:22"
  ```
- Resolve domain names:
  ```bash
  python owlSearch.py --shodan --resolve google.com,qwen.ai
  ```

### History
View the history of past queries:
```bash
python owlSearch.py --history
```

---

## Saving Results
You can save query results to a JSON file using the `-o` or `--output` option:
```bash
python owlSearch.py --vt --ip 8.8.8.8 --output results.json
```

---

## Contributing
Contributions are welcome! If you find a bug or have a feature request, please open an issue or submit a pull request.

---

## License
This project is licensed under the MIT License.

## Contributions

Contributions are welcome! If you'd like to improve the script, open an issue or submit a pull request on [GitHub](https://github.com/Leku2020/OwlArchSoftware/tree/main).
