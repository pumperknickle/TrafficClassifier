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

firstSet = list(map(lambda x: x[0], features))
secondSet = list(map(lambda x: x[1], features))
thirdSet = list(map(lambda x: x[2], features))
fourthSet = list(map(lambda x: x[3], features))
fifthSet = list(map(lambda x: x[4], features))
sixthSet = list(map(lambda x: x[5], features))

x_min, x_max = min(firstSet) - 1, max(firstSet) + 1
y_min, y_max = min(secondSet) - 1, max(secondSet) + 1
third_min, third_max = min(thirdSet) - 1, max(thirdSet) + 1
fourth_min, fourth_max = min(fourthSet) - 1, max(fourthSet) + 1
fifth_min, fifth_max = min(fifthSet) - 1, max(fifthSet) + 1
sixth_min, sixth_max = min(sixthSet) - 1, max(sixthSet) + 1

h = 50

xx, yy, third, fourth, fifth, sixth = np.meshgrid(np.arange(x_min, x_max, h),
                     np.arange(y_min, y_max, h),
                     np.arange(third_min, third_max, h),
                     np.arange(fourth_min, fourth_max, h),
                     np.arange(fifth_min, fifth_max, h),
                     np.arange(sixth_min, sixth_max, h))
Z = neigh.predict(np.c_[xx.ravel(), yy.ravel(), third.ravel(), fourth.ravel(), fifth.ravel(), sixth.ravel()])
predicted = neigh.predict(features)
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
plt.xlabel("mean traffic (1/10 ms interval)")
plt.ylabel("standard deviation")
plt.show()

from sklearn.metrics import confusion_matrix
cm = confusion_matrix(labels, predicted)
import seaborn as sns
ax= plt.subplot()
sns.heatmap(cm, annot=True, ax = ax); #annot=True to annotate cells

# labels, title and ticks
ax.set_xlabel('Predicted labels');ax.set_ylabel('True labels'); 
ax.set_title('Confusion Matrix'); 
plt.show()

