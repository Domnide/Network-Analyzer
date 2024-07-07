from scapy.all import *
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import matplotlib.pyplot as plt
import os
import queue
import time

class PacketAnalyzer:
    def __init__(self, interface=None, log_file="packet_log.txt"):
        self.interface = interface
        self.log_file = log_file
        self.packet_count = 0
        self.protocol_counts = {}
        self.payload_directory = "payloads"
        self.timestamp_list = []
        self.packet_size_list = []
        self.protocol_details = {}
        self.security_alerts = []
        self.packet_queue = queue.Queue()

        # Create directory for storing payload files if it doesn't exist
        if not os.path.exists(self.payload_directory):
            os.makedirs(self.payload_directory)

    def packet_handler(self):
        while True:
            try:
                packet = self.packet_queue.get()
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = packet[IP].proto
                    self.log_packet(src_ip, dst_ip, protocol)
                    self.packet_count += 1
                    self.update_protocol_counts(protocol)
                    self.inspect_payload(packet)
                    self.analyze_traffic_patterns(packet)
                    self.analyze_protocol(packet)
                    self.detect_security_vulnerabilities(packet)
            except Exception as e:
                print(f"Error processing packet: {e}")
            finally:
                self.packet_queue.task_done()

    def log_packet(self, src_ip, dst_ip, protocol):
        protocol_name = self.get_protocol_name(protocol)
        try:
            with open(self.log_file, "a") as f:
                f.write(f"Packet captured - Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol_name} ({protocol})\n")
                print(f"Packet captured - Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol_name} ({protocol})")
        except Exception as e:
            print(f"Error logging packet: {e}")

    def get_protocol_name(self, proto):
        protocol_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return protocol_names.get(proto, f'Unknown ({proto})')

    def update_protocol_counts(self, protocol):
        protocol_name = self.get_protocol_name(protocol)
        if protocol_name in self.protocol_counts:
            self.protocol_counts[protocol_name] += 1
        else:
            self.protocol_counts[protocol_name] = 1

    def inspect_payload(self, packet):
        # Save packet payload to a file for inspection
        try:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"{self.payload_directory}/packet_{timestamp}.txt"
            with open(filename, "wb") as f:
                f.write(bytes(packet))
        except Exception as e:
            print(f"Error saving payload: {e}")

    def analyze_traffic_patterns(self, packet):
        try:
            timestamp = time.time()
            self.timestamp_list.append(timestamp)
            self.packet_size_list.append(len(packet))
        except Exception as e:
            print(f"Error analyzing traffic patterns: {e}")

    def analyze_protocol(self, packet):
        try:
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                protocol_info = {
                    "Source Port": src_port,
                    "Destination Port": dst_port,
                    "Flags": flags,
                    # Add more protocol-specific details as needed
                }
                self.protocol_details[self.packet_count] = protocol_info
        except Exception as e:
            print(f"Error analyzing protocol: {e}")

    def detect_security_vulnerabilities(self, packet):
        try:
            if DNS in packet:
                # Example: Detecting DNS tunneling
                queries = packet[DNSQR].qname.decode().lower()
                if "attacker-controlled-domain.com" in queries:
                    self.security_alerts.append("Detected potential DNS tunneling attack.")
        except Exception as e:
            print(f"Error detecting security vulnerabilities: {e}")

    def start_capture(self):
        try:
            print(f"Starting packet capture on interface {self.interface}. Press Ctrl+C to stop.")
            # Start packet processing thread
            processing_thread = threading.Thread(target=self.packet_handler)
            processing_thread.start()
            # Start sniffing packets
            sniff(iface=self.interface, prn=lambda x: self.packet_queue.put(x), store=0)
        except KeyboardInterrupt:
            print("\nPacket capture stopped by user.")
            self.packet_queue.join()  # Wait for all packets to be processed
            self.generate_report()
        except Exception as e:
            print(f"Error capturing packets: {e}")

    def run_gui(self):
        root = tk.Tk()
        root.title("Packet Analyzer")

        # Create a notebook (tabbed interface)
        notebook = ttk.Notebook(root)
        notebook.grid(row=0, column=0, padx=10, pady=10, sticky=tk.NSEW)

        # Frame for Packet Log tab
        packet_log_frame = ttk.Frame(notebook)
        notebook.add(packet_log_frame, text='Packet Log')

        # Scrolled text box for packet log
        log_text = scrolledtext.ScrolledText(packet_log_frame, width=100, height=20)
        log_text.pack(expand=True, fill=tk.BOTH)

        # Function to update packet log display
        def update_log():
            log_text.delete(1.0, tk.END)
            if os.path.exists(self.log_file):
                with open(self.log_file, "r") as f:
                    log_text.insert(tk.END, f.read())
            log_text.after(1000, update_log)  # Update every second

        # Start updating log display
        update_log()

        # Frame for Statistics tab
        statistics_frame = ttk.Frame(notebook)
        notebook.add(statistics_frame, text='Statistics')

        # Button to show protocol distribution plot
        def show_protocol_distribution():
            plt.figure(figsize=(8, 6))
            protocols = list(self.protocol_counts.keys())
            counts = list(self.protocol_counts.values())
            plt.bar(protocols, counts, color='skyblue')
            plt.xlabel('Protocol')
            plt.ylabel('Packet Count')
            plt.title('Protocol Distribution')
            plt.xticks(rotation=45)
            plt.grid(True)
            plt.show()

        show_plot_button = tk.Button(statistics_frame, text="Show Protocol Distribution", command=show_protocol_distribution)
        show_plot_button.pack(padx=10, pady=10)

        # Button to show traffic patterns plot
        def show_traffic_patterns():
            plt.figure(figsize=(10, 6))
            plt.plot(self.timestamp_list, self.packet_size_list, marker='o', linestyle='-')
            plt.xlabel('Timestamp')
            plt.ylabel('Packet Size')
            plt.title('Traffic Patterns')
            plt.grid(True)
            plt.show()

        show_traffic_button = tk.Button(statistics_frame, text="Show Traffic Patterns", command=show_traffic_patterns)
        show_traffic_button.pack(padx=10, pady=10)

        # Frame for Security tab
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text='Security')

        # Button to show security alerts
        def show_security_alerts():
            if self.security_alerts:
                alert_message = "\n".join(self.security_alerts)
            else:
                alert_message = "No security alerts detected."
            messagebox.showinfo("Security Alerts", alert_message)

        show_alerts_button = tk.Button(security_frame, text="Show Security Alerts", command=show_security_alerts)
        show_alerts_button.pack(padx=10, pady=10)

        # Start the GUI main loop
        root.mainloop()

    def generate_report(self):
        # Generate a detailed report summarizing captured data
        try:
            report_file = "capture_report.txt"
            with open(report_file, "w") as f:
                f.write(f"Packet Capture Report\n")
                f.write(f"Total Packets Captured: {self.packet_count}\n\n")
                f.write(f"Protocol Distribution:\n")
                for protocol, count in self.protocol_counts.items():
                    f.write(f"{protocol}: {count}\n")
                f.write(f"\nProtocol Details:\n")
                for packet_num, details in self.protocol_details.items():
                    f.write(f"Packet {packet_num}:\n")
                    for key, value in details.items():
                        f.write(f"{key}: {value}\n")
                    f.write("\n")
                f.write(f"\nSecurity Alerts:\n")
                if self.security_alerts:
                    f.write("\n".join(self.security_alerts))
                else:
                    f.write("No security alerts detected.")
            messagebox.showinfo("Capture Stopped", f"Packet capture stopped. Report generated: {report_file}")
        except Exception as e:
            print(f"Error generating report: {e}")

    def get_available_interfaces(self):
        interfaces = get_working_ifaces()
        interface_list = [(iface.name, iface.description) for iface in interfaces]
        return interface_list

    def select_interface(self):
        interfaces = self.get_available_interfaces()
        if not interfaces:
            print("No available network interfaces found.")
            return None

        print("Available network interfaces:")
        for idx, (name, description) in enumerate(interfaces):
            print(f"{idx + 1}: {name} ({description})")

        while True:
            try:
                choice = int(input("Select an interface by number: ")) - 1
                if 0 <= choice < len(interfaces):
                    selected_interface = interfaces[choice][0]
                    return selected_interface
                else:
                    print("Invalid choice. Please select a valid interface number.")
            except ValueError:
                print("Invalid input. Please enter a number.")

if __name__ == "__main__":
    analyzer = PacketAnalyzer()

    selected_interface = analyzer.select_interface()
    if selected_interface:
        analyzer.interface = selected_interface

        capture_thread = threading.Thread(target=analyzer.start_capture)
        capture_thread.start()

        analyzer.run_gui()
        capture_thread.join()
