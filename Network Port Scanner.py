import tkinter as tk
from tkinter import messagebox
import socket
import threading
import logging

# Configure logging
logging.basicConfig(filename='port_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_ports():
    target = target_entry.get()
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    num_threads = int(num_threads_entry.get())
    filename = filename_entry.get()

    # Clear previous scan status
    scan_status_text.delete(1.0, tk.END)

    logging.info(f"Starting scan on target {target} from port {start_port} to port {end_port} with {num_threads} threads")

    scan_thread = threading.Thread(target=start_scan, args=(target, start_port, end_port, num_threads, filename))
    scan_thread.start()

def start_scan(target, start_port, end_port, num_threads, filename):
    results = []
    scan_functions = {
        'TCP': scan_tcp,
        'UDP': scan_udp,
        'SYN': scan_syn
    }

    for port in range(start_port, end_port + 1):
        scan_func = scan_functions.get(scan_type_var.get())
        thread = threading.Thread(target=scan_func, args=(target, port, results))
        thread.start()

    for thread in threading.enumerate():
        if thread != threading.current_thread():
            thread.join()

    save_results(filename, results)
    messagebox.showinfo("Scan Complete", "Scan completed. Results saved to port_scan_report.txt")

def scan_tcp(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            service_name = socket.getservbyport(port)
            service_info = f"{target}:{port} ({service_name}) - TCP Port is open"
            results.append(service_info)
            logging.info(service_info)
            scan_status_text.insert(tk.END, service_info + "\n")
            scan_status_text.update_idletasks()  # Update GUI
    except Exception as e:
        logging.error(f"Error scanning TCP port {port}: {str(e)}")

def scan_udp(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b'', (target, port))
        data, _ = sock.recvfrom(1024)
        service_name = socket.getservbyport(port)
        service_info = f"{target}:{port} ({service_name}) - UDP Port is open"
        results.append(service_info)
        logging.info(service_info)
        scan_status_text.insert(tk.END, service_info + "\n")
        scan_status_text.update_idletasks()  # Update GUI
    except Exception as e:
        logging.error(f"Error scanning UDP port {port}: {str(e)}")

def scan_syn(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            service_name = socket.getservbyport(port)
            service_info = f"{target}:{port} ({service_name}) - SYN Port is open"
            results.append(service_info)
            logging.info(service_info)
            scan_status_text.insert(tk.END, service_info + "\n")
            scan_status_text.update_idletasks()  # Update GUI
    except Exception as e:
        logging.error(f"Error scanning SYN port {port}: {str(e)}")

def save_results(filename, results):
    with open(filename, 'w') as file:
        for result in results:
            file.write(result + '\n')
    logging.info(f"Scan results saved to {filename}")

# Create GUI window
root = tk.Tk()
root.title("Port Scanner")

# Styling
root.configure(bg="#f0f0f0")

# Target input
tk.Label(root, text="Target IP address or hostname:", bg="#f0f0f0").pack()
target_entry = tk.Entry(root)
target_entry.pack()

# Port range input
tk.Label(root, text="Start Port:", bg="#f0f0f0").pack()
start_port_entry = tk.Entry(root)
start_port_entry.pack()

tk.Label(root, text="End Port:", bg="#f0f0f0").pack()
end_port_entry = tk.Entry(root)
end_port_entry.pack()

# Number of threads input
tk.Label(root, text="Number of Threads:", bg="#f0f0f0").pack()
num_threads_entry = tk.Entry(root)
num_threads_entry.pack()

# Scan type input
tk.Label(root, text="Scan Type:", bg="#f0f0f0").pack()
scan_type_var = tk.StringVar(root)
scan_type_var.set("TCP")
scan_type_menu = tk.OptionMenu(root, scan_type_var, "TCP", "UDP", "SYN")
scan_type_menu.pack()

# Filename input
tk.Label(root, text="Filename to save scan results:", bg="#f0f0f0").pack()
filename_entry = tk.Entry(root)
filename_entry.pack()

# Scan button
scan_button = tk.Button(root, text="Scan", command=scan_ports, bg="#4caf50", fg="white")
scan_button.pack()

# Scan status display
tk.Label(root, text="Scan Status:", bg="#f0f0f0").pack()
scan_status_text = tk.Text(root, height=10, width=50)
scan_status_text.pack()

root.mainloop()
