# 🔥 Network-Based Phishing Toolkit - MITM + Fake Login Pages 🔥

**This tool allows you to perform a Man-in-the-Middle (MITM) attack on a target, redirect them to a phishing login page, and capture credentials.**  

![GitHub Repo Size](https://img.shields.io/github/repo-size/KevinKhemra007/Network-Phishing-Tool)  
![GitHub Stars](https://img.shields.io/github/stars/KevinKhemra007/Network-Phishing-Tool?style=social)  
![GitHub Forks](https://img.shields.io/github/forks/KevinKhemra007/Network-Phishing-Tool?style=social)  
![GitHub License](https://img.shields.io/github/license/KevinKhemra007/Network-Phishing-Tool)  

---

## **📌 Features**
✅ **Intercept traffic & capture login credentials**  
✅ **Perform MITM attack using ARP Spoofing**  
✅ **Redirect victims to a fake login page**  
✅ **Auto-save captured credentials to a text file**  
✅ **Easy-to-use menu with a clean interface**  

---

![Screenshot 2025-03-12 055945](https://github.com/user-attachments/assets/23b22d39-6adc-4804-abf1-38a0c89fc2dc)

---
## **🔧 Installation & Setup**
### **Step 1: Install Required Dependencies**
```bash
sudo apt update && sudo apt install apache2 php bettercap dnsmasq -y
pip install colorama scapy netfilterqueue
git clone https://github.com/KevinKhemra007/Network-Phishing-Tool.git
cd Network-Phishing-Tool
python phishing_network.py
python3 phishing_network.py
