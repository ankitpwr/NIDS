# Run this ONCE as Administrator to find your correct Windows interface name.
# Copy the interface name that matches your 192.168.125.x IP address
# and paste it into INTERFACE in agent.py

from scapy.all import get_if_list, get_if_addr

print("Available interfaces and their IPs:\n")
for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
        marker = "  ← USE THIS ONE" if ip.startswith("192.168.125") else ""
        print(f"  {iface:<60} IP: {ip}{marker}")
    except:
        print(f"  {iface:<60} IP: (could not get IP)")