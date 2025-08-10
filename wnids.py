from scapy.all import *
from tkinter import *
from tkinter import messagebox, scrolledtext, ttk
import threading
import time
import os
import re


alerts = []
trusted_aps = {}


def get_available_interfaces():
    try:
        interfaces = [iface.name for iface in Ifaces().values() if iface.flags & 0x10000]
        if not interfaces:
            interfaces = [iface.name for iface in Ifaces().values() if 'wlan' in iface.name or 'mon' in iface.name]
        return interfaces
    except Exception as e:
        messagebox.showerror("Error", f"Could not retrieve interfaces: {e}")
        return []

def check_monitor_mode(interface):
    try:
        result = os.popen(f"iwconfig {interface}").read()
        return "Mode:Monitor" in result
    except Exception:
        return False



def update_gui(alert_text, color="black"):
    listbox.config(state=NORMAL)
    listbox.insert(END, alert_text + "\n", color)
    listbox.yview(END)
    listbox.config(state=DISABLED)

def clear_alerts():
    listbox.config(state=NORMAL)
    listbox.delete(1.0, END)
    listbox.config(state=DISABLED)
    alerts.clear()

def add_trusted_ap_gui():
    def save_ap():
        ssid = ssid_entry.get().strip()
        bssid = bssid_entry.get().strip().upper()
        if not ssid or not bssid:
            messagebox.showerror("Input Error", "SSID and BSSID cannot be empty.")
            return
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid):
            messagebox.showerror("Input Error", "Invalid BSSID format.")
            return
        trusted_aps[ssid] = bssid
        update_gui(f"⭐ Trusted AP added: SSID='{ssid}', BSSID={bssid}", "blue")
        ap_window.destroy()

    ap_window = Toplevel(root)
    ap_window.title("Add Trusted AP")
    Label(ap_window, text="SSID:").pack(pady=5)
    ssid_entry = Entry(ap_window, width=30)
    ssid_entry.pack(pady=5)
    Label(ap_window, text="BSSID (XX:XX:XX:XX:XX:XX):").pack(pady=5)
    bssid_entry = Entry(ap_window, width=30)
    bssid_entry.pack(pady=5)
    Button(ap_window, text="Add AP", command=save_ap, bg="green", fg="white").pack(pady=10)

# Packet Analyzer 

def detect_attack(pkt):
    timestamp = time.strftime("%H:%M:%S")

    if pkt.haslayer(Dot11Deauth):
        mac = pkt.addr2
        alert_msg = f"⚠️ Deauth attack from {mac} at {timestamp}"
        if alert_msg not in alerts:
            alerts.append(alert_msg)
            update_gui(alert_msg, "red")

    elif pkt.haslayer(Dot11Beacon):
        try:
            ssid = pkt[Dot11Elt].info.decode(errors="ignore")
            bssid = pkt[Dot11].addr2.upper()

            if ssid and bssid:
                if ssid in trusted_aps and trusted_aps[ssid] != bssid:
                    alert_msg = f"❗ Rogue AP: SSID='{ssid}', BSSID={bssid} (Expected: {trusted_aps[ssid]}) at {timestamp}"
                    if alert_msg not in alerts:
                        alerts.append(alert_msg)
                        update_gui(alert_msg, "orange")
                elif ssid not in trusted_aps:
                    alert_msg = f"❓ Unknown AP: SSID='{ssid}', BSSID={bssid} at {timestamp}"
                    if alert_msg not in alerts:
                        alerts.append(alert_msg)
                        update_gui(alert_msg, "purple")
        except Exception:
            pass

# Sniffing Control

sniff_thread = None
stop_sniffing_event = threading.Event()

def start_sniff():
    global sniff_thread
    interface = interface_var.get()

    if not interface:
        messagebox.showerror("Error", "Please select or enter a wireless interface.")
        return

    if not check_monitor_mode(interface):
        messagebox.showwarning("Warning", f"'{interface}' not in monitor mode. Sniffing may not work correctly.")

    if sniff_thread and sniff_thread.is_alive():
        messagebox.showinfo("Info", "Sniffing is already active.")
        return

    clear_alerts()
    update_gui(f"Monitoring on {interface}...", "blue")
    stop_sniffing_event.clear()

    sniff_thread = threading.Thread(target=run_sniff_loop, args=(interface,), daemon=True)
    sniff_thread.start()
    start_button.config(state=DISABLED)
    stop_button.config(state=NORMAL)

def run_sniff_loop(interface):
    try:
        sniff(iface=interface, prn=detect_attack, store=0, stop_filter=lambda x: stop_sniffing_event.is_set())
    except Exception as e:
        update_gui(f"Sniffing error: {e}", "red")
        messagebox.showerror("Sniffing Error", str(e))
    finally:
        update_gui("Monitoring stopped.", "blue")
        root.after(100, lambda: start_button.config(state=NORMAL))
        root.after(100, lambda: stop_button.config(state=DISABLED))

def stop_sniff():
    if sniff_thread and sniff_thread.is_alive():
        stop_sniffing_event.set()
        update_gui("Stopping monitoring...", "blue")
    else:
        messagebox.showinfo("Info", "Sniffing is not active.")

# GUI Setup

root = Tk()
root.title("Wireless Intrusion Detection - Deauth & Rogue AP")
root.geometry("800x600")

control_frame = Frame(root, padx=10, pady=10)
control_frame.pack(fill=X)

Label(control_frame, text="Wireless Interface:").grid(row=0, column=0, padx=5, pady=5, sticky=W)
interface_var = StringVar()
interface_entry = ttk.Combobox(control_frame, textvariable=interface_var, width=30)
interface_entry['values'] = get_available_interfaces()
interface_entry.grid(row=0, column=1, padx=5, pady=5, sticky=EW)
interface_entry.set("Select or Type Interface (e.g., wlan0mon)")

button_frame = Frame(control_frame)
button_frame.grid(row=1, column=0, columnspan=2, pady=10)

start_button = Button(button_frame, text="Start Monitoring", command=start_sniff, bg="green", fg="white", width=15)
start_button.pack(side=LEFT, padx=5)

stop_button = Button(button_frame, text="Stop Monitoring", command=stop_sniff, bg="red", fg="white", width=15, state=DISABLED)
stop_button.pack(side=LEFT, padx=5)

clear_button = Button(button_frame, text="Clear Alerts", command=clear_alerts, bg="blue", fg="white", width=15)
clear_button.pack(side=LEFT, padx=5)

add_ap_button = Button(button_frame, text="Add Trusted AP", command=add_trusted_ap_gui, bg="darkgreen", fg="white", width=15)
add_ap_button.pack(side=LEFT, padx=5)

Label(root, text="Alerts:").pack(padx=10, pady=(0, 5), anchor=W)
listbox = scrolledtext.ScrolledText(root, width=90, height=25, wrap=WORD, state=DISABLED, bg="#F0F0F0", fg="black")
listbox.pack(padx=10, pady=10, fill=BOTH, expand=True)

listbox.tag_config("red", foreground="red")
listbox.tag_config("orange", foreground="orange")
listbox.tag_config("purple", foreground="purple")
listbox.tag_config("blue", foreground="blue")

root.mainloop()
