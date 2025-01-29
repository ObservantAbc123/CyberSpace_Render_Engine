
import scapy
from scapy.all import sniff
import pygame
import scapy.sendrecv

# 1. create a backend using scapy and stdout
#    style text output.

# 2. link that to a pygame representation of
#    a graph showing the network traffic/use.
     

DEBUG_MODE = 0
###
packets_captured = 0
captured_packets = dict()
###
# link_layer_protocol = dict()
# network_layer_protocol = dict()
# transport_layer_protocol = dict()
# application_layer_protocol = dict()
sending_ip_address = dict()
receiving_ip_address = dict()
flags = dict()



def packet_callback(captured_packet):
    if not DEBUG_MODE and captured_packet is not None:
        captured_packets[packets_captured] = captured_packet
        packets_captured += 1
    else:
        print(captured_packet.lastlayer())
        



def execute_packet_capture():
    capture_time = input("--enter the number of seconds for capture duration--\r\n")
    print("--beginning capture--\r\n")

    packet_capture = sniff(timeout=int(capture_time), prn=lambda packet:packet_callback(packet))
    
    print("--capture ended--\r\n")


def analyze_packets(packet_capture):
    for marker in packet_capture.keys:
            packet_summary_truncated = packet_capture[marker].summary()
            split_capture = str.split(packet_summary_truncated, ' ')
            if split_capture[0] == "TCP":
                 
            


if __name__ == '__main__':
    execute_packet_capture()
    if not DEBUG_MODE:
        print("--%d packets captured; storing analyzing and packet attributes--", packets_captured) 
        analyze_packets(captured_packets)

