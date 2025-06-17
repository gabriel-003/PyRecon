from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import sys
import argparse
import threading


def test_port(address: str, dest_port: int) -> tuple[int, bool]:
    # Checks if port is listening and returns (port_num, is_open)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((address, dest_port)) == 0
            return (dest_port, result)
    except (OSError, ValueError):
        return (dest_port, False)


def scan_ports_threaded(target: str, ports: list, max_threads: int = 10):
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
                results.append((port_num, result))
                print(result)
    
    print(f"Scanning {len(ports)} ports on {target} with {max_threads} threads")

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
                        print(f"Error scanning port: {e}")
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        interrupted.set()
        # Cancel remaining futures
        for future in futures:
            future.cancel()
        raise

    # Sort results by port number
    results.sort(key=lambda x: x[0])
    formatted_results = [result[1] for result in results]
    
    print(f"Found {sum(1 for _, result in results if 'OPEN' in result)} open port(s)")
    
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
        print(f"Results saved to {filename}")
    except IOError as e:
        print(f"Error writing to file: {e}")


def main():

    # Argument parsing

    parser = argparse.ArgumentParser(description="PyRecon port scanner")

    parser.add_argument("target", help="Target IP address or hostname")

    parser.add_argument(
        "-p", "--ports",
        help="Comma-separated list of ports or range (default = 0-1023)",
        default="0-1023"
    )

    parser.add_argument(
        "-t", "--threads",
        help="Number of threads to use (default = 10)",
        type=int,
        default=10
    )

    parser.add_argument(
        "-o", "--output",
        help="Output results of scan to a .txt file (optional)"
    )

    args = parser.parse_args()

    target = socket.gethostbyname(args.target)
        

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(e)
        return


    # Test with example.com and 192.168.69.128
    # Usage example: python3 pyrecon.py 192.168.69.128 -p "1-1000" -t 200 -o results.txt
    # Main function call
    results = scan_ports_threaded(target, ports, args.threads)


    # If -o or --output is used
    if args.output:
        write_to_file(results, args.output)


if __name__ == "__main__":
    main()