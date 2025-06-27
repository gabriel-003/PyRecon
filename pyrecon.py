from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import sys
import argparse
import threading
import logging


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def test_port(address: str, dest_port: int) -> tuple[int, bool]:
    # Checks if port is listening and returns (port_num, is_open)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((address, dest_port)) == 0
            return (dest_port, result)
    except (OSError, ValueError):
        return (dest_port, False)


def scan_ports_threaded(target: str, ports: list, max_threads: int = 10, verbose: bool = False):
    # Scan ports using threading and returns formatted results
    results = []
    results_lock = threading.Lock()
    interrupted = threading.Event()

    def scan_and_store(port):
        # Scans a single port and stores result in shared results list 
        if interrupted.is_set():  # Check if scan should be interrupted
            return
            
        port_num, is_open = test_port(target, port)
        status = "OPEN" if is_open else "CLOSED"
        result = f"{target} : {port_num} : {status}"

        with results_lock:
            if not interrupted.is_set():
                results.append((port_num, result, is_open))
    
    logging.info(f"Scanning {len(ports)} ports on {target} with {max_threads} threads")

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit port scan tasks
            futures = [executor.submit(scan_and_store, port) for port in ports]

            # Wait for tasks to complete
            for future in as_completed(futures):
                if interrupted.is_set():
                    break
                try:
                    future.result()
                except Exception as e:
                    if not interrupted.is_set():
                        logging.error(f"Error scanning port: {e}")
    
    except KeyboardInterrupt:
        logging.info("\nScan interrupted by user")
        interrupted.set()
        # Cancel remaining futures
        for future in futures:
            future.cancel()
        return []

    # Sort results by port number to maintain order
    results.sort(key=lambda x: x[0])
    
    # Print results in order based on verbose flag
    for port_num, result, is_open in results:
        if verbose or is_open:
            logging.info(result)
    
    formatted_results = [result for _, result, _ in results]
    open_count = sum(1 for _, _, is_open in results if is_open)
    
    logging.info(f"Found {open_count} open port(s)")
    
    return formatted_results

def parse_ports(ports_str: str):
    # Parses ports passed as args and returns a set of ports
    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            except ValueError:
                raise ValueError(f"Invalid port range: {part}")
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise ValueError(f"Invalid port: {part}")
    return sorted(ports)


def write_to_file(results: list, filename: str):
    # Writes scan result to file and prints if it worked
    try:
        with open(filename, 'w') as f:
            for line in results:
                f.write(line + "\n")
        logging.info(f"Results saved to {filename}")
    except IOError as e:
        logging.error(f"Error writing to file: {e}")


def main():

    # Argument parsing

    VERSION = "1.0.0"

    parser = argparse.ArgumentParser(description="PyRecon port scanner")

    parser.add_argument(
        "--version",
        action='version',
        version=f'%(prog)s {VERSION}'
    )

    parser.add_argument("target", help="Target IP address or hostname")

    parser.add_argument(
        "-p", "--ports",
        help="Comma-separated list of ports or range (default = 1-1023)",
        default="1-1023"
    )

    parser.add_argument(
        "-t", "--threads",
        help="Number of threads to use (default = 50)",
        type=int,
        default=50
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output - show all ports, including closed ones(optional)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output results of scan to a .txt file (optional)"
    )

    args = parser.parse_args()

    try:
        target = socket.gethostbyname(args.target)
    except socket.gaierror:
        logging.error(f"Error: Unable to resolve hostname {args.target}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error resolving hostname {e}")
        sys.exit(1)
        

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        logging.error(e)
        return


    # Port scan function call
    results = scan_ports_threaded(target, ports, args.threads, args.verbose)


    # If -o or --output is used
    if args.output:
        write_to_file(results, args.output)


if __name__ == "__main__":
    main()