# Sample PCAP Files

Place sample `.pcap` or `.pcapng` files here for testing NetTrace.

## Recommended sources for real-world malicious traffic samples

| Source | URL | Notes |
|--------|-----|-------|
| **Malware Traffic Analysis** | [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net) | Real C2, ransomware, banking trojan captures |
| **Wireshark Sample Captures** | [wiki.wireshark.org/SampleCaptures](https://wiki.wireshark.org/SampleCaptures) | Protocol and attack samples |
| **SecRepo.com** | [secrepo.com](https://www.secrepo.com/) | Curated security PCAP dataset |
| **PcapNg Captures** | [github.com/automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) | ICS/SCADA network captures |
| **CTF Challenges** | HackTheBox, PicoCTF, CyberDefenders | Forensics / PCAP challenge files |

## Quick test

Generate a simple test PCAP using tcpdump (Linux/macOS):

```bash
# 60-second capture on interface eth0
sudo tcpdump -i eth0 -w samples/test_capture.pcap -G 60 -W 1

# Then run NetTrace against it
python netTrace.py -f samples/test_capture.pcap
```

Or use a pre-built test PCAP from CyberDefenders:
- [CyberDefenders: Network Forensics Challenges](https://cyberdefenders.org/blueteam-ctf-challenges/?type=network-forensics)
