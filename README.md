# 📡 Wireless Network Intrusion Detection System (WNIDS)

A **real-time Wireless Intrusion Detection System** built in Python using **Scapy** and **Tkinter** to detect:
- **Deauthentication attacks**
- **Rogue Access Points (Evil Twin attacks)**

This project was developed as part of the **COS 0642 Wireless Network Security** course at **German-Malaysian Institute**.

---

## 🚀 Features
- Real-time packet sniffing for IEEE 802.11 management frames.
- **Deauthentication Attack Detection** (⚠️ red alerts).
- **Rogue AP Detection** via SSID/BSSID mismatch (❗ orange alerts).
- **Unknown AP Detection** (❓ purple alerts).
- Add and manage **trusted access points** via GUI.
- Color-coded live alerts with timestamps.
- One-click **Start/Stop monitoring** and **Clear alerts**.

---

## 🛠 Tools & Technologies
- **Python 3** — Scapy, Tkinter, Threading, Regex
- **Linux (Kali recommended)** — For packet capture
- **Alfa AWUS036NHA** wireless adapter (or similar with monitor mode)
- **Aircrack-ng Suite** — For attack simulation
- **iwconfig** — For checking monitor mode

---

## 📦 Installation
### 1. Clone the Repository
```bash
git clone https://github.com/public0x/wireless-network-ids.git
cd wireless-network-ids
```

### 2. Install Dependencies
```bash
sudo apt update
sudo apt install python3-pip
pip3 install scapy
```
---

## ▶️ Usage
- Enable Monitor Mode on your wireless adapter:
```bash
sudo airmon-ng start wlan0
```
Example output might create *wlan0mon*.

- Run the IDS:
```bash
sudo python3 wnids.py
```
Select your interface (e.g., wlan0mon) in the GUI and click Start Monitoring.

---

## 🧪 Testing the IDS
- Simulating a Deauthentication Attack
```bash
sudo aireplay-ng --deauth 10 -a <BSSID> wlan0mon
```
- Simulating a Rogue Access Point
```bash
airbase-ng -e "YourSSID" -c 6 wlan0mon
```

---

## 📷 Screenshots
| Feature | Screenshot |
|---------|------------|
| **Main GUI** | ![GUI](https://raw.githubusercontent.com/public0x/wireless-network-ids/main/screenshots/main_gui.png) |
| **Deauth Detection** | ![Deauth Alert](https://raw.githubusercontent.com/public0x/wireless-network-ids/main/screenshots/deauth_alert.png) |
| **Rogue AP Detection** | ![Rogue AP](https://raw.githubusercontent.com/public0x/wireless-network-ids/main/screenshots/rogue_ap.png) |
	
---

📜 License
This project is licensed under the MIT License — you can use and modify it freely.

👨‍💻 Authors
Public0x
