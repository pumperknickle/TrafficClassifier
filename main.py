from scapy.all import *
from itertools import groupby
import statistics 

packets=rdpcap("/Users/jbao/DeviceIdentityClassifier/scan.pcap")
timestamps = map(lambda x: x.time, packets)
print(min(list(timestamps)))
streams = dict()

for packet in packets:
  if IP in packet:
    ip_src=packet[IP].src
    ip_dst=packet[IP].dst
    if str(ip_src) in streams:
      streams[ip_src].append(packet)
    else:
      streams[ip_src] = [packet]

def shift_back_time(self, amount):
  self.time -= amount
  return self

def shift_timestamps(packets):
  timestamps = map(lambda x: x.time, packets)
  start_time = min(list(timestamps))
  modified_packets = map(lambda x: shift_back_time(x, start_time), packets)
  return list(modified_packets)

def get_time(packet):
  return packet.time

def group_then_convert(interval, packets):
  groups_iter = groupby(packets, lambda x: int(x.time/(interval)))
  groups = []
  for key, group in groups_iter:
    group_array = []
    for thing in group:
      group_array.append(len(thing))
    groups.append((key, group_array))
  return groups

def group(interval, packets):
  groups_iter = groupby(packets, lambda x: int(x.time/(interval)))
  groups = []
  for key, group in groups_iter:
    group_array = []
    for thing in group:
      group_array.append(thing)
    groups.append((key, group_array))
  return groups

def mean(lst): 
    return sum(lst) / len(lst) 

features = []
labels = []
for key in streams:
  print(key)
  streams[key] = shift_timestamps(streams[key])
  streams[key].sort(key=get_time)
  times = map(lambda x: x.time, streams[key])
  lengths = map(lambda x: len(x), streams[key])
  intervals = group(10, streams[key])
  for k, v in intervals:
    sub_groups = group_then_convert(1, v)
    sub_group = []
    for k, v in sub_groups:
      sub_group.append(sum(v))
    sub_group = sub_group + ([0] * (10 - len(sub_group)))
    print(sub_group)
    features.append([mean(sub_group), statistics.stdev(sub_group)])
    labels.append(key)
print(features)
print(labels)

from sklearn.neighbors import KNeighborsClassifier
neigh = KNeighborsClassifier(n_neighbors=3)
neigh.fit(features, labels)
print(neigh.predict([[73, 230]]))
