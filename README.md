# Pcap_Analyzer
Pcap_Analyzer is a Python script that analyzes network traffic captured in a pcap file and generates a report containing various statistics about the captured traffic.

## Dependencies
- Python 3.x
- Scapy

## Usage
```
python pcap_analyzer.py <pcap file> [-h] [-c <count>] [-t <time>]
```
The script takes a pcap file as input and generates a report containing the following statistics:

- Total number of packets captured
- Number of packets per protocol
- Top source and destination IP addresses
- Top source and destination ports
- Average packet size
- Total data transfered in bytes
- Duration of capture

You can use the optional arguments to limit the number of packets analyzed:
- c <count>: Only analyze the first <count> packets
- t <time>: Only analyze packets captured within the last <time> seconds
  
## Example Usage
  ```
  python pcap_analyzer.py example.pcap -c 100

  ```
