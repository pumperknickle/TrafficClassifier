from scapy.all import *
from itertools import groupby
import statistics

s = 0.01

def group_then_length(interval, packets):
  groups_iter = groupby(packets, lambda x: int(x.time/Decimal(interval)))
  groups = []
  for key, group in groups_iter:
    group_array = []
    for thing in group:
      group_array.append(len(thing))
    groups.append((key, group_array))
  return groups

def mean(lst):
    return sum(lst) / len(lst)

def calculate_mean(packets):
  group_iterator = group_then_length(s, packets)
  group_packets = []
  for k, v in group_iterator:
    group_packets.append(sum(v))
  group_packets = group_packets + ([0] * (int(1/(s)) - len(group_packets)))
  return mean(group_packets)

def calculate_standard_dev(packets):
  group_iterator = group_then_length(s, packets)
  group_packets = []
  for k, v in group_iterator:
    group_packets.append(sum(v))
  group_packets = group_packets + ([0] * (int(1/(s)) - len(group_packets)))
  return statistics.stdev(group_packets)

def calculate_send_traffic(packets, allIPs):
  ipToPackets = dict()
  total_traffic_sent = 0
  for packet in packets:
    total_traffic_sent += len(packet)
    if IP in packet:
      ip_src=packet[IP].src
      if ip_src in ipToPackets:
        ipToPackets[ip_src] += len(packet)
      else:
        ipToPackets[ip_src] = len(packet)
  features = []
  for ip in allIPs:
    if ip in ipToPackets:
      sent_traffic_ratio = float(ipToPackets[ip])/float(total_traffic_sent)
      features.append(sent_traffic_ratio)
    else:
      features.append(0.0)
  return features

def convert_to_features(packets, allIPs):
  featureVector = []
  featureVector.append(calculate_mean(packets))
  featureVector.append(calculate_standard_dev(packets))
  for ip_traffic in calculate_send_traffic(packets, allIPs):
    featureVector.append(ip_traffic)
  return featureVector
