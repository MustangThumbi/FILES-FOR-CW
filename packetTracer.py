import datetime
import socket
import os
import dpkt
import networkx as nx
import dpkt
import matplotlib.pyplot as plt
import re

# stores IP addresses from the PCAP file
ips = set()


def inet_to_str(inet):
    """Converts inet into string to read IPv4 packets
    """
    return socket.inet_ntop(socket.AF_INET, inet)


def print_packets(pcap):
    """Prints out the packets with the UTC timestamp, source IP address
    and destination IP address
    """
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        # Print out the timestamp in UTC
        print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
        # Unpack the Ethernet frame (mac src/dst, ethernet type)
        eth = dpkt.ethernet.Ethernet(buf)
        # checks if the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue
        # Unpacks the data within the Ethernet frame (the IP packet)
        ip = eth.data
        # Prints the source and ip address
        print('IP: %s -> %s \n' % (inet_to_str(ip.src), inet_to_str(ip.dst)))

        # extracts source and destination IP addresses
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)

        # keeping set of unique IPs
        ips.add(src_ip)
        ips.add(dst_ip)

    # prints total number of IP addresses
    print(f'Total number IP addresses found: {len(ips)}')
 # creates a graph from the pcap file
def create_graph(pcap):
    G = nx.DiGraph()
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data

            http = dpkt.http.Request(tcp.data)
            if http.method == 'GET':
                uri = http.uri.lower()
                if '.gif' in uri:
                    G.add_edge(src, dst)
        except Exception:
            # error trapping
            pass
    return G

 # prints the graph info
def print_graph_info(G):
    print(f'Number of nodes: {G.number_of_nodes()}')
    print(f'Number of edges: {G.number_of_edges()}')
    print(f'Number of connected components: {nx.number_connected_components(G)}')
    print(f'Average clustering coefficient: {nx.average_clustering(G)}')

 # plots the graph
def plot_graph(G):
    plt.figure(figsize=(12, 12))
    pos = nx.spring_layout(G)
    nx.draw_networkx_nodes(G, pos, node_size=100, node_color='b')
    nx.draw_networkx_edges(G, pos, alpha=0.5, edge_color='b')
    nx.draw_networkx_labels(G, pos, font_size=10, font_family='sans-serif')
    plt.axis('off')
    plt.show()


def test():
    """Opens a test pcap file and then prints out the packets"""
    with open('evidence-packet-analysis.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)

def findDownload(pcap):
    """in current form, finds any gif files downloaded and prints
       request source (Downloader), gif URI and destination (provider) IP"""

    found = False
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data

            http = dpkt.http.Request(tcp.data)
            if http.method == 'GET':
                uri = http.uri.lower()
                if '.gif' in uri:
                    print(f'[!] {src} downloaded {uri} from {dst}')
                    found = True
        except Exception:
            # error trapping
            pass
    return found


"""
 Calls findDownload function and prints found gif files
"""

with open('evidence-packet-analysis.pcap', 'rb') as f:
    pcapFile = dpkt.pcap.Reader(f)

    print(f'[*] Analysing {f} for gif files')
    result = findDownload(pcapFile)
    if result is False:
        print('No gif downloads found in this file')



def email():
    '''function to parse emails from the page'''
    with open('evidence-packet-analysis.pcap', 'rb') as f:
        s = f.read().decode('latin-1')
        email = re.findall(r'[\w\.-]+@[\w\.-]+', str(s))  # searches for emails according to the regex
        email_list = []  # creates an empty list
        summary = len(email)
        print(str(summary) + " email addresses found.")  # prints summary (number of emails) + text string
        for i in email:
            email_list.append(i)  # appends email list
        return print(email_list)


def parse_pcap():
    pcapfile = 'evidence-packet-analysis.pcap'
    f = open(pcapfile, 'rb')
    pcap = dpkt.pcap.Reader(f)

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        print(f'#<INFO> eth ethernet packet: {repr(eth)}')

        ip = eth.data
        print(f'#<INFO> eth.data: {repr(ip)}')
        tcp = ip.data
        print(f'#<INFO> ethernet packet: {repr(tcp)}')
        print(f'{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}')

        break # stop after first packet

    

# create a graph of the ip pairs



# main function to call all other functions
def main():
    test()
    with open('evidence-packet-analysis.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        G = create_graph(pcap)
        print_graph_info(G)
        plot_graph(G)
        
if __name__ == '__main__':
    main()


