from scapy.all import *
from itertools import groupby
import sys
import glob
from featureTransforms import convert_to_features

directory = sys.argv[1]
extended = directory + '/*/'
paths = glob.glob(extended)
sequence_length = 100

def split_sequence_unevenly(lst, n):
  for i in range(0, len(lst), n):
     yield lst[i:i + n]

def split_sequence_evenly(lst, n):
  split = list(split_sequence_unevenly(lst, n))
  split.pop()
  return split

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
    pcap = rdpcap(file)
    sequences = get_sequences(pcap)
    chunks = split_sequence_evenly(sequences, sequence_length)
    for chunk in chunks:
      features.append(chunk)
      labels.append(counter)
  counter += 1

import numpy as np
from keras.layers import Flatten
from keras.layers import Dropout
from keras.models import Sequential
from keras.layers import Dense
from keras.wrappers.scikit_learn import KerasClassifier
from keras.utils import np_utils
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline
from keras.layers.convolutional import Conv1D
from keras.layers.convolutional import MaxPooling1D

dummy_labels = np_utils.to_categorical(labels)
num_classes = len(dummy_labels[0])

def baseline_model():
  model = Sequential()
  model.add(Conv1D(filters=64, kernel_size=3, activation='relu', input_shape=(sequence_length, 2)))
  model.add(Conv1D(filters=64, kernel_size=3, activation='relu'))
  model.add(Dropout(0.5))
  model.add(MaxPooling1D(pool_size=2))
  model.add(Flatten())
  model.add(Dense(100, activation='relu'))
  model.add(Dense(num_classes, activation='softmax'))
  model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
  return model

print(features)
from keras.utils import plot_model
plot_model(baseline_model(), to_file='model.png', show_shapes=True, show_layer_names=True)

estimator = KerasClassifier(build_fn=baseline_model, epochs=200, batch_size=5, verbose=1)
kfold = KFold(n_splits=10, shuffle=True)
results = cross_val_score(estimator, np.array(features), dummy_labels, cv=kfold)
print("Baseline: %.2f%% (%.2f%%)" % (results.mean()*100, results.std()*100))
