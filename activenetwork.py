import subprocess
import platform
import socket
import queue
import threading

# ip list
ip_queue = queue.Queue()

# ip to scan
target_ip = "127.0.0.1"  #127.0.0.1 for local tests
ip_queue.put(target_ip)

# ports to scan
ports_to_scan = [21, 22, 23, 80, 135, 139, 443, 445, 3306, 3389, 8080]

def ping(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        output = subprocess.check_output(['ping', param, '1', ip], stderr=subprocess.DEVNULL).decode()
        return output
    except subprocess.CalledProcessError:
        return None

def guess_os(ip):
    result = ping(ip)
    if result is None:
        return "Unknown"

    ttl = None
    for line in result.splitlines():
        line = line.strip()
        if "TTL=" in line.upper():
            # windows ping output
            ttl_part = line.upper().split("TTL=")[1]
            ttl = int(ttl_part.split()[0])
            break
        elif "ttl=" in line:
            # linux/mac ping output
            ttl_part = line.split("ttl=")[1]
            ttl = int(ttl_part.split()[0])
            break

    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco/Network device"
    else:
        return "Unknown"

def scan_ports(ip):
    open_ports = []
    for port in ports_to_scan:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            sock.close()
    return open_ports

def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((ip, port))
        sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')  #used to http ports
        banner = sock.recv(1024).decode(errors='ignore')
        sock.close()
        return banner.strip()
    except:
        return None

def worker():
    while not ip_queue.empty():
        ip = ip_queue.get()
        output = ping(ip)
        if output is None:
            print(f"[-] Host {ip} did not respond to ping. Trying anyway...")

        print(f"\n[+] scanning host {ip}")
        os_guess = guess_os(ip)
        print(f"    ↳ OS guess: {os_guess}")
        open_ports = scan_ports(ip)
        if open_ports:
            for port in open_ports:
                banner = grab_banner(ip, port)
                print(f"    ↳ port {port} is open", end="")
                if banner:
                    print(f" | banner: {banner}")
                else:
                    print()
        else:
            print("    ↳ no open ports found.")
        ip_queue.task_done()

threads = []
for i in range(1):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("\nscan complete.")
