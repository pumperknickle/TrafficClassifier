from scapy.all import *
from itertools import groupby
import sys
import glob
from featureTransforms import convert_to_features

directory = sys.argv[1]
extended = directory + '/*/'
paths = glob.glob(extended)

def rewind(self, amount):
  self.time -= amount
  return self

def normalize_packet_time(packets):
  timestamps = map(lambda x: x.time, packets)
  first_time = min(list(timestamps))
  normalized_packets = map(lambda x: rewind(x, first_time), packets)
  return list(normalized_packets)

def get_packet_time(packet):
  return packet.time

def group(interval, packets):
  groups_iter = groupby(packets, lambda x: int(x.time/Decimal(interval)))
  groups = []
  for key, group in groups_iter:
    group_array = []
    for thing in group:
      group_array.append(thing)
    groups.append(group_array)
  return groups

def get_all_ips(packets):
  packet_set = set()
  for packet in packets:
    ip_src=packet[IP].src
    ip_dst=packet[IP].dst
    packet_set.add(ip_src)
    packet_Set.add(ip_dst)
  return list(packet_set)
  

directoryToPackets = dict()
counter = 0
directoryToScalar = dict()
labels = []
features = []
w = 1.0

packet_set = set()
for path in paths:
  pcapPath = path + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  for file in pcapFiles:
    pcap = rdpcap(file)
    for packet in pcap:
      if IP in packet:
        ip_src=packet[IP].src
        ip_dst=packet[IP].dst
        packet_set.add(ip_src)
        packet_set.add(ip_dst)
      else:
        print("ip")

all_ips = list(packet_set)

for path in paths:
  pcapPath = path + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  for file in pcapFiles:
    pcap = rdpcap(file)
    normalized_pcap = normalize_packet_time(pcap)
    normalized_pcap.sort(key=get_packet_time)
    pcap_w_groups = group(w, normalized_pcap)
    for vw in pcap_w_groups:
      fv = convert_to_features(vw, all_ips)
      features.append(fv)
      labels.append(counter)
  counter = counter + 1
print(features)
print(labels)        
