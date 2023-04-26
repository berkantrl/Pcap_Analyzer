import os
import scapy.all as scapy 
import dpkt
import socket
import subprocess
import sys

# define the capture function
def capture_network_traffic(output_file,interface):
    # capture network traffic for 20 seconds
    packets = scapy.sniff(iface=interface, timeout=20)

    # write the captured packets to a file in npcap format
    scapy.wrpcap(output_file, packets)

def is_monitor_mode(interface):
    try:
        output = subprocess.check_output(['netsh', 'interface', 'show', 'interface', interface])
        output = output.decode('utf-8').strip().split('\n')
        for line in output:
            if 'Type' in line:
                return 'Monitor' in line
        return False
    except:
        return False
    
def print_help():
    usage = """pcap_analyzer.py [-h] [-i INTERFACE]
    Pcap Analyzer Tool:
    -h : Help message
    .i : Interface
    """
    print(usage)
    sys.exit(1)

def extract_information(output_file,interface):
    with open(output_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        packets = []
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            
            ip = eth.data
            packet = {
                'timestamp': ts,
                'src_ip': socket.inet_ntoa(ip.src),
                'dst_ip': socket.inet_ntoa(ip.dst),
                'src_mac': ':'.join('%02x' % b for b in eth.src),
                'dst_mac': ':'.join('%02x' % b for b in eth.dst),
                'protocol': ip.__class__.__name__,
                'src_port': 0,
                'dst_port': 0,
                'packet_len': len(buf)
            }
            
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                packet['src_port'] = tcp.sport
                packet['dst_port'] = tcp.dport
            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                packet['src_port'] = udp.sport
                packet['dst_port'] = udp.dport
            
            if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
                packet['payload'] = ip.data.data.hex()
            
            packets.append(packet)

    is_monitor = is_monitor_mode(interface)
    # write the packets to an XML file
    with open('output.xml', 'w') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<Packets>\n')
        
        for packet in packets:
            f.write('\t<Packet>\n')
            f.write('\t\t<Time>{}</Time>\n'.format(packet['timestamp']))
            f.write('\t\t<Source_IP>{}</Source_IP>\n'.format(packet['src_ip']))
            f.write('\t\t<Destination_IP>{}</Destination_IP>\n'.format(packet['dst_ip']))
            f.write('\t\t<Source_MAC>{}</Source_MAC>\n'.format(packet['src_mac']))
            f.write('\t\t<Destination_MAC>{}</Destination_MAC>\n'.format(packet['dst_mac']))
            f.write('\t\t<Protocol>{}</Protocol>\n'.format(packet['protocol']))
            f.write('\t\t<Source_Port>{}</Source_Port>\n'.format(packet['src_port']))
            f.write('\t\t<Destination_Port>{}</Destination_Port>\n'.format(packet['dst_port']))
            f.write('\t\t<Length>{}</Length>\n'.format(packet['packet_len']))
            
            if is_monitor:
                if packet.haslayer(scapy.Dot11):  # Check if packet has Dot11 layer
                    if packet.type == 0 and packet.subtype == 8:  # Check if packet is a beacon frame
                        signal_strength = -(256 - int(packet.notdecoded[-2:].hex(), 16))
                        f.write('\t\t<Signal_Strength>{}</Signal_Strength>\n'.format(signal_strength))

            if 'payload' in packet:
                f.write('\t\t<Payload>{}</Payload>\n'.format(packet['payload']))
            
            f.write('\t</Packet>\n')
        
        f.write('</Packets>\n')

def main():

    if len(sys.argv) == 3:
        tmp = sys.argv[1:]
        if tmp[0].lower() == '-i':
            interface = tmp[1]
        else:
            print_help()
    else:
        print_help()

    # define the output file path
    output_file = os.path.join('network_traffic.pcap')

    # call the capture function
    capture_network_traffic(output_file,interface)

    extract_information(output_file,interface)

if __name__ =='__main__':
    main() 