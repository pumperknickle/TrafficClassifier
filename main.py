from scapy.all import *
from itertools import groupby
import statistics 
import sys

packets=rdpcap(sys.argv[1])
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
mapping = dict()
counter = 0
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
    labels.append(counter)
  counter = counter + 1
print(features)
print(labels)

from sklearn.neighbors import KNeighborsClassifier
neigh = KNeighborsClassifier(n_neighbors=3)
neigh.fit(features, labels)

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap

firstSet = list(map(lambda x: x[0], features))
secondSet = list(map(lambda x: x[1], features))
x_min, x_max = min(firstSet) - 1, max(firstSet) + 1
y_min, y_max = min(secondSet) - 1, max(secondSet) + 1

h = 1

print(firstSet)
print(secondSet)
print(x_min)
print(x_max)

xx, yy = np.meshgrid(np.arange(x_min, x_max, h),
                     np.arange(y_min, y_max, h))
Z = neigh.predict(np.c_[xx.ravel(), yy.ravel()])

print(Z)

# Create color maps
cmap_light = ListedColormap(['#FFAAAA', '#AAFFAA', '#AAAAFF']) # for meshgrid
cmap_bold = ListedColormap(['#FF0000', '#00FF00', '#0000FF']) # for points

Z = Z.reshape(xx.shape)
plt.figure()
plt.pcolormesh(xx, yy, Z, cmap=cmap_light)

plt.scatter(firstSet, secondSet, c=labels, cmap=cmap_bold)
plt.xlim(xx.min(), xx.max())
plt.ylim(yy.min(), yy.max())
plt.title("Device Traffic Clustering")
plt.show()


print(neigh.predict([[73, 230]]))
