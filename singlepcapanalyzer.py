from scapy.all import *
from itertools import groupby
import statistics
import sys
import glob

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
  groups_iter = groupby(packets, lambda x: int(x.time/Decimal(interval)))
  groups = []
  for key, group in groups_iter:
    group_array = []
    for thing in group:
      group_array.append(len(thing))
    groups.append((key, group_array))
  return groups

def group(interval, packets):
  groups_iter = groupby(packets, lambda x: int(x.time/Decimal(interval)))
  groups = []
  for key, group in groups_iter:
    group_array = []
    for thing in group:
      group_array.append(thing)
    groups.append((key, group_array))
  return groups

def mean(lst): 
    return sum(lst) / len(lst) 

directory = sys.argv[1]
extended = directory + '/*/'
paths = glob.glob(extended)
streams = dict()
counter = 0
mapping = dict()
features = []
labels = []
print(paths)

for path in paths:
  pcapPath = path + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  for file in pcapFiles:
    packets_in_file = rdpcap(file)
    print(packets_in_file)
    shifted_packets = shift_timestamps(packets_in_file)
    shifted_packets.sort(key=get_time)
    intervals = group(1.0, shifted_packets)
    for k, v in intervals:
      featureVector = []
      keyStream = v
      secondIntervals = [0.1, 0.01, 0.001]
      for secondInterval in secondIntervals:
        sub_groups = group_then_convert(secondInterval, keyStream)
        sub_group = []
        for k, v in sub_groups:
          sub_group.append(sum(v))
        sub_group = sub_group + ([0] * (int(1/(secondInterval)) - len(sub_group)))
        featureVector.append(mean(sub_group))
        featureVector.append(statistics.stdev(sub_group))
      features.append(featureVector)
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



predicted = neigh.predict(features)

from sklearn.metrics import confusion_matrix
cm = confusion_matrix(labels, predicted)
import seaborn as sns
ax= plt.subplot()
sns.heatmap(cm, annot=True, ax = ax); #annot=True to annotate cells

# labels, title and ticks
ax.set_xlabel('Predicted labels');ax.set_ylabel('True labels'); 
ax.set_title('Confusion Matrix'); 
plt.show()

