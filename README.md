# Ivanti Connect Around Vulnerability Checker

- [Ivanti Connect Around Vulnerability Checker](#ivanti-connect-around-vulnerability-checker)
  - [Overview](#overview)
  - [Features](#features)
  - [Types of Checks](#types-of-checks)
    - [WEB ACCESS](#web-access)
    - [SYSTEM INFO](#system-info)
    - [BYPASS DETECTED](#bypass-detected)
  - [Status Types Explanation](#status-types-explanation)
  - [Getting Started](#getting-started)
    - [Requirements](#requirements)
    - [Usage](#usage)
      - [Arguments](#arguments)
        - [Target Specification](#target-specification)
        - [Custom Variables](#custom-variables)
        - [Output Stylization](#output-stylization)
  - [To Do](#to-do)
  - [Intended Use and Disclaimer](#intended-use-and-disclaimer)
    - [Purpose](#purpose)
    - [Disclaimer](#disclaimer)
  - [License](#license)
  - [Contribution Guidelines](#contribution-guidelines)
    - [Reporting Issues](#reporting-issues)
    - [Submitting Pull Requests](#submitting-pull-requests)
  - [Acknowledgments](#acknowledgments)
  - [About Me](#about-me)

## Overview

The Connect Around attack chain, involving CVE-2023-46805 and CVE-2024-21887, poses a significant threat to Ivanti Connect Secure & Policy Secure appliances. This attack chain enables unauthorized access and command execution on vulnerable systems. CVE-2023-46805 allows attackers to bypass authentication controls, while CVE-2024-21887, a command injection vulnerability, can be exploited without needing authentication when combined with the former. This duo of vulnerabilities necessitates urgent attention from organizations using Ivanti products, urging them to apply available mitigations as detailed in the Ivanti Community Forum.

In response to the need for organizations to validate mitigation status, the Ivanti Connect Around Vulnerability Checker has been developed. This script is designed to assess Ivanti Connect Secure & Policy Secure appliances for vulnerabilities associated with the Connect Around attack chain. It performs checks to verify the presence of these vulnerabilities and outputs the results in a CSV format. Various mitigation validation methodologies are employed to provide a comprehensive and reliable assessment.

## Features

- **Concurrent Host Checks**: Efficiently scans multiple hosts simultaneously, significantly reducing the time needed to assess vulnerabilities across a network.
- **Customizable Command-Line Arguments**: Offers flexibility to define specific parameters such as input and output file paths, the number of concurrent threads for scanning, and selectable ports, ensuring tailored and precise scans.
- **Adaptive Output Management**: Automatically generates output files with a default naming convention based on the current date and time, while also allowing users to specify custom filenames to suit their organizational needs.
- **Advanced Error Handling**: Provides comprehensive error reporting, including detailed HTTP error codes, network connectivity issues, and other unexpected errors, enabling precise identification and troubleshooting of potential problems during scanning.
- **Port Flexibility**: Allows users to define specific ports to scan (with 80 and 443 as defaults), catering to varied network configurations and enhancing the depth of vulnerability assessment.
- **Color-Coded Console Output**: Optional feature for an enhanced user experience, offering color-coded output in the console for quick and easy identification of different scan statuses, improving readability and interpretation of results.


## Types of Checks

The script conducts various checks to assess the security status of Ivanti Connect Secure systems. Each check is based on specific methodologies adapted from research within the information security community.

### WEB ACCESS
- **Methodology**: Adapted from WatchTowr Labs research.
- **Description**: Requests the `/api/v1/configuration/users/user-roles/user-role/rest-userrole1/web/web-bookmarks/bookmark` endpoint without authentication.
- **Positive Result**: Status displayed - "Vulnerable".
- **Negative Result**: Status displayed - "Mitigated".
- **Research Link**: [WatchTowr Labs Research](https://labs.watchtowr.com/welcome-to-2024-the-sslvpn-chaos-continues-ivanti-cve-2023-46805-cve-2024-21887/).

### SYSTEM INFO
- **Methodology**: Adapted from Stephen Fewer's research at Rapid7.
- **Description**: Attempts to access the the `/api/v1/system/system-information` URI.
- **Positive Result**: Status displayed - "Vulnerable".
- **Negative Result**: Status displayed - "Mitigated".
- **Research Link**: [Metasploit Framework Module](https://github.com/rapid7/metasploit-framework/blob/de6ed9e1d6e39593582369083c6f7678c7d89262/modules/exploits/linux/http/ivanti_connect_secure_rce_cve_2023_46805.rb).

### BYPASS DETECTED
- **Methodology**: Adapted from research by Rapid7 at AttackerKB.
- **Description**: Atempts to access the `/api/v1/totp/user-backup-code` URI.
- **Positive Result**: Status displayed - "Vulnerable (Bypass Detected)".
- **Negative Result**: Status displayed - "Not Vulnerable".
- **Research Link**: [Rapid7 Analysis on AttackerKB](https://attackerkb.com/topics/AdUh6by52K/cve-2023-46805/rapid7-analysis).

Each check provides insights into potential vulnerabilities. "Vulnerable" indicates a confirmed vulnerability, while "Mitigated" or "Not Vulnerable" signifies that the system appears secure against the specific vulnerability being tested.


## Status Types Explanation

The script categorizes each check with specific status types, providing insight into the security posture of the scanned host. Here are the descriptions of each status type:

- **Mitigated**: Indicates that the system has mitigations in place against the vulnerabilities checked. This status is returned when responses typical of a secure and patched system are detected.

- **Vulnerable**: This status suggests that the system is vulnerable to the specific checks performed by the script. It is returned when the system exhibits known patterns or responses that indicate a vulnerability.

- **HTTP Error**: Returned when the script encounters standard HTTP error responses (other than 403 Forbidden) from the target system. It usually indicates a problem with the web server or the request.

- **Network Issue**: This status is used when the script encounters network-related issues, such as an inability to reach the host. It combines former statuses like "Host Unreachable" and "Network Error."

- **Timeout Error**: Indicates that the request to the target timed out, suggesting potential network or configuration issues that prevented the script from completing its check.

- **Connection Error**: Similar to "Timeout Error," this status is used when there are issues establishing a connection to the host, which could be due to network problems, incorrect hostnames, etc.

- **Ivanti Presence Inconclusive**: Formerly known as "Attestation Needed," this status is returned when the script's checks do not yield definitive evidence of either vulnerability or mitigation. It suggests that further manual investigation is required to determine the security status of the system.

- **Vulnerable (Bypass Detected)**: Specific to the bypass vulnerability check, this status indicates that the system is vulnerable to the authentication bypass technique described in the script's methodology.

Each status provides a snapshot of the system's security posture concerning the vulnerabilities checked. Users should consider these statuses as initial indicators and, where necessary, conduct further manual investigations to confirm the system's actual security status.

## Getting Started

### Requirements

- Python 3
- `requests` module
- `urllib3` module
- Optional: `colorama` module for color-coded output

### Usage

To run the script, use the following command:

`python ivanti_scan.py -i [input_file]`

Optionally, run with additional arguments:

`python ivanti_scan.py -i [input_file] -o [output_file] -t [number_of_threads] -p [port1 port2 ...] --color`

#### Arguments

##### Target Specification

Utilize one of these options to specify target(s) for testing.
- `-i` or `--input`: Path to input file containing list of targets.
- `-u` or `--url`: Single URL string to test.

##### Custom Variables
- `-o` or `--output`: Optional. Name of the output CSV file. Default is `[current_date_time]_results.csv`.
- `-t` or `--threads`: Optional. Number of threads to use for concurrent execution. Default is `20`.
- `-p` or `--ports`: Optional. Specify ports to check (e.g., 80 443). Default checks ports 80 and 443.
- `-a` or `--user-agent`: Optional. Specify user agent string. Defaults to: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.3`

##### Output Stylization
- `-c` or `--color`: Optional. Enable color-coded output if `colorama` is installed.

## To Do
- [ ] Allow user specification of testing methods
- [ ] Add additional validation methods
- [ ] Improve output formatting

## Intended Use and Disclaimer

### Purpose
This tool is designed for individuals and organizations aiming to validate the mitigation of vulnerabilities within their own environments. It is specifically intended for use on Ivanti Connect Secure appliances where explicit permission for security testing has been granted.

### Disclaimer
- **Ethical Use**: This script should only be used for lawful purposes. Users are responsible for ensuring they have authorization to test the target systems.
- **Accuracy**: While efforts have been made to ensure the accuracy and effectiveness of this tool, it is provided "as is", and users should interpret the results with an understanding of its limitations.
- **No Warranty**: The author, Chris Farrell, provides this tool without warranty of any kind. Users assume all risks associated with its use.
- **Responsibility**: Users must comply with all applicable laws and regulations. The author is not responsible for any misuse of this tool or any damages that result from its use.

By using this tool, you acknowledge and agree to these terms.

## License
This project is licensed under the MIT License with an Ethical Use Clause - see the [LICENSE](LICENSE.md) file for details.

## Contribution Guidelines

We welcome contributions to the Ivanti Connect Around Vulnerability Checker project! If you're looking to contribute, here are a few ways you can help:

### Reporting Issues
- **Error Reports**: If you find any errors or bugs, please create an issue detailing the problem, steps to reproduce it, and any relevant logs or screenshots.
- **Feature Requests**: Have ideas for new features or enhancements? We'd love to hear them! Please submit an issue with a clear description of your proposed feature.

### Submitting Pull Requests
- **Improving Functionality**: Contributions that improve the tool's functionality are greatly appreciated. If you have developed a fix or enhancement, feel free to submit a pull request.
- **Guidelines**:
  - Fork the repository and create your branch from `main`.
  - Write clear and concise commit messages.
  - Ensure your code adheres to the existing style to maintain consistency.
  - Create a pull request with a detailed description of your changes.

Thank you for considering contributing to this project.

## Acknowledgments

This project leverages research and methodologies developed by several esteemed groups and individuals in the field of cybersecurity. We extend our gratitude to:

- **WatchTowr Labs**: For their insightful research into Ivanti Connect Secure vulnerabilities. Their work has been instrumental in developing the WEB ACCESS check methodology.
  - [WatchTowr Labs Research](https://labs.watchtowr.com/welcome-to-2024-the-sslvpn-chaos-continues-ivanti-cve-2023-46805-cve-2024-21887/)

- **Stephen Fewer of Rapid7**: His work on the Metasploit Module provided valuable insights into the SYSTEM INFO check methodology.
  - [Metasploit Framework Module by Stephen Fewer](https://github.com/rapid7/metasploit-framework/blob/de6ed9e1d6e39593582369083c6f7678c7d89262/modules/exploits/linux/http/ivanti_connect_secure_rce_cve_2023_46805.rb)

- **Rapid7 at AttackerKB**: Their research into authentication bypass techniques greatly contributed to the BYPASS DETECTED check methodology.
  - [Rapid7 Analysis on AttackerKB](https://attackerkb.com/topics/AdUh6by52K/cve-2023-46805/rapid7-analysis)

A special thanks to these groups and individuals for their contributions to the field of cybersecurity, which have greatly aided the development of this tool.


## About Me

Chris Farrell is a vulnerability researcher committed to enhancing cybersecurity through thorough analysis and comprehensive solutions.
