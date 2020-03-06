from scapy.all import *
from itertools import groupby
import sys
import glob
from featureTransforms import convert_to_features
import pyshark

directory = sys.argv[1]
extended = directory + '/*/'
paths = glob.glob(extended)
sequence_length = 100

def extractFeatures(lst, n):
  features = []
  for i in range(len(lst) - n - 1):
    end = n+i
    start = i
    features.append(lst[start:end])
  return features

def extractLabels(lst, n):
   labels = []
   for i in range(len(lst) - n - 1):
     end = n+1
     labels.append(lst[end])
   return labels

def get_sequences(packets):
  sequences = []
  for i in range(len(packets)-1):
    next_packet_size = len(packets[i+1])
    next_packet_interval = packets[i+1].time - packets[i].time
    sequences.append([next_packet_size, next_packet_interval])
  return sequences

counter = 0
features = []
labels = []

for path in paths:
  pcapPath = path + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  for file in pcapFiles:
    print(file)
    pcap1 = pyshark.FileCapture(pathToFile)
    print(pcap1[0])
    pcap = rdpcap(file)
    sequences = get_sequences(pcap)
    featuresForFile = extractFeatures(sequences, sequence_length)
    labelsForFile = extractLabels(sequences, sequence_length)
    for feature in featuresForFile:
      features.append(feature)
    for label in labelsForFile:
      labels.append(label)

import numpy as np
from keras.layers import Dropout
from keras.models import Sequential
from keras.layers import Dense
from keras.wrappers.scikit_learn import KerasRegressor
from keras.utils import np_utils
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline
from keras.layers import LSTM

def baseline_model():
  model = Sequential()
  model.add(LSTM(100, input_shape=(sequence_length, 2), return_sequences=True))
  model.add(Dropout(0.2))
  model.add(LSTM(100))
  model.add(Dropout(0.2))
  model.add(Dense(20, kernel_initializer='normal', activation='relu'))
  model.add(Dense(2, kernel_initializer='normal'))
  model.compile(loss='mean_squared_error', optimizer='adam')
  return model

from keras.utils import plot_model
plot_model(baseline_model(), to_file='model.png', show_shapes=True, show_layer_names=True)

estimator = KerasRegressor(build_fn=baseline_model, epochs=50, batch_size=5, verbose=1)
kfold = KFold(n_splits=10, shuffle=True)
gi
