# PrimitiveIds
Primitive Ids based on analyzing packets from wireshark
Now it can detect scannings only. Can detect next scan types:
1. Xmas scan
2. Half open or stealth scan
3. Null scan
4. Udp scan
5. Icmp ping scan


How it works:
  1. Give pcap file as argument. For example:
    "python3 analyzer.py halfopen.pcap"
  2. It will go through all packets in file with using scapy framework
  3. Then it will show you report. Which scans it has detected,source ip adresses, ports which was scanned
  
Weak working with big pcap files.
