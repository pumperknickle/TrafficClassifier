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

import numpy as np
import pandas
from keras.models import Sequential
from keras.layers import Dense
from keras.wrappers.scikit_learn import KerasClassifier
from keras.utils import np_utils
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline

dummy_labels = np_utils.to_categorical(labels)
num_classes = len(dummy_labels[0])
num_features = len(features[0])
X = np.array(features)

# define baseline model
def baseline_model():
	# create model
	model = Sequential()
	model.add(Dense(8, input_dim=num_features, activation='relu'))
	model.add(Dense(num_classes, activation='softmax'))
	# Compile model
	model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
	return model

estimator = KerasClassifier(build_fn=baseline_model, epochs=200, batch_size=5, verbose=1)
kfold = KFold(n_splits=10, shuffle=True)
results = cross_val_score(estimator, X, dummy_labels, cv=kfold)
print("Baseline: %.2f%% (%.2f%%)" % (results.mean()*100, results.std()*100))
