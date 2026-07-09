import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
import argparse

def scan_port(ip, port, timeout = 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result =  s.connect_ex((ip,port))
        return result == 0
    finally:
        s.close()

def scan_range_sequence(ip, ports, timeout = 1):
    #scanning a number of ports one by one and returning open ports
    open_ports = []
    for port in ports:
        if(scan_port(ip, port, timeout)):
            open_ports.append(port)
    return open_ports

def scan_range_thread(ip, ports, timeout = 1, max_workers = 50):
      open_ports = []
      with ThreadPoolExecutor(max_workers=max_workers) as executor:
         future_port = {
            executor.submit(scan_port, ip , port, timeout, ) : port
            for port in ports
          }
         for future in as_completed(future_port):
             port = future_port[future]
             if future.result():
                 open_ports.append(port)

      return  sorted(open_ports)
def build_parser():
     parser = argparse.ArgumentParser(
        prog = "port_scanner",
        description = " a simple TCP port scanner"
     )
     subparsers = parser.add_subparsers(dest = "command", required = True)
     scan_parsers = subparsers.add_parser("scan", help = "scan a IP adress or hostname")
     scan_parsers.add_argument("target", help = "target IP adress")
     scan_parsers.add_argument("--ports", default="1-100", help="port range")
     scan_parsers.add_argument("--timeout", type=float, default=1.0, help="timeout per port in seconds")
     return parser
def parse_portrange(port_rangestr):
     #turning the range into a list 
     if "-" in port_rangestr:
         start_str, end_str = port_rangestr.split("-")
         start = int(start_str)
         end = int(end_str)
         return list(range(start, end + 1))
     else:
         return [int(portrange_str)]

if __name__== "__main__" :
    parser = build_parser()
    args = parser.parse_args()
    ports = parse_portrange(args.ports)
    print(f"Scanning {args.target} (ports {args.ports})...")
    start = time.time()
    open_ports = scan_range_thread(args.target, ports, timeout=args.timeout)
    elapsed = time.time() - start
    for port in open_ports:
        print(f"[OPEN] {port}")

    print(f"Scan complete. {len(open_ports)} open ports found in {elapsed:.2f}s")










