import sys
import glob
import numpy as np
from keras.utils import plot_model
from keras.utils import np_utils
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold
from keras.models import Sequential
from keras.layers import Dense
from keras.wrappers.scikit_learn import KerasClassifier
from advancedPcapAnalyzer import extractFeatures, extractSignatures, ngrams, dbcluster, dbclustermin, convertToFeatures
from activityGeneration import generate
from math import floor, ceil

directory = sys.argv[1]
extended = directory + '/*/'
paths = glob.glob(extended)

# distance metric used by dbscan
distance_threshold = 5.0
# total ngrams divided by cluster threshold is equal to the min_samples needed to form a cluster in dbscan
min_cluster = 10
min_sig_size = 2
max_sig_size = 5

currentDevice = 0
fake_sequences = dict()
real_sequences = dict()

device_numbers = dict()

for path in paths:
  device_numbers[currentDevice] = path
  real = []
  pcapPath = path + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  for file in pcapFiles:
    featureV = convertToFeatures(file)
    if len(featureV) != 0: 
      real.append(featureV)
    else:
      print(path)
      print("empty feature!")
  gen = []
  if len(real) == 0 or len(real[0]) == 0:
    continue
  generated = generate(path, distance_threshold, min_cluster, min_sig_size, max_sig_size, len(real))
  for g in generated:
    if len(g) != 0:
      gen.append(g)
    else:
      print("empty generation!")
  if len(real) != 0 and len(gen) != 0 and len(real[0]) != 0 and len(gen[0]) != 0:
    real_sequences[currentDevice] = real
    fake_sequences[currentDevice] = gen
    currentDevice += 1

all_fake_features = dict()
all_real_features = dict()

for device in real_sequences:
  real = real_sequences[device]
  fake = fake_sequences[device]
  if (len(fake) == 0 or len(real) == 0) or len(fake) != len(real):
    continue
  real_features = [None] * len(real)
  fake_features = [None] * len(fake)
  for i in range(min_sig_size, max_sig_size + 1):
    allngrams = []
    for feature in real:
      ngramVector = ngrams(i, feature)
      for ngram in ngramVector:
        allngrams.append(ngram)
    cluster = dbclustermin(allngrams, distance_threshold, min_cluster)
    signatures = extractSignatures(cluster, i)
    for n in range(len(real)):
      feature = real[n]
      extractedNgrams = ngrams(i, feature)
      newFeatures = extractFeatures(extractedNgrams, signatures)
      if real_features[n] == None:
        real_features[n] = newFeatures
      else:
        real_features[n] = real_features[n] + newFeatures
    for n in range(len(fake)):
      feature = fake[n]
      extractedNgrams = ngrams(i, feature)
      newFeatures = extractFeatures(extractedNgrams, signatures)
      if fake_features[n] == None:
        fake_features[n] = newFeatures
      else:
        fake_features[n] = fake_features[n] + newFeatures
  all_fake_features[device] = fake_features.copy()
  all_real_features[device] = real_features.copy()

def baseline_model():
  model = Sequential()
  model.add(Dense(300, activation='relu'))
  model.add(Dense(300, activation='relu'))
  model.add(Dense(2, activation='softmax'))
  model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
  return model

all_results = dict()

for device in all_fake_features:
  print(device_numbers[device])
  X_real = all_real_features[device]
  X_fake = all_fake_features[device]
  for i in range(len(X_real)):
    print("real")
    print(X_real[i])
    print("fake")
    print(X_fake[i])
    differences = []
    for n in range(len(X_real[i])):
      differences.append(abs(X_real[i][n] - X_fake[i][n]))
    print(differences)
    

for device in all_fake_features:
  X_real = all_real_features[device]
  X_fake = all_fake_features[device]
  real_labels = [0] * len(X_real)
  fake_labels = [1] * len(X_fake)
  features = X_real + X_fake
  labels = real_labels + fake_labels
  dummy_labels = np_utils.to_categorical(labels)
  estimator = KerasClassifier(build_fn=baseline_model, epochs=200, batch_size=5, verbose=1)
  kfold = KFold(n_splits=10, shuffle=True)
  results = cross_val_score(estimator, np.array(features), dummy_labels, cv=kfold)
  print("Baseline: %.2f%% (%.2f%%)" % (results.mean()*100, results.std()*100))
  all_results[device] = results.mean()

for key, value in all_results.items():
  print(device_numbers[key])
  print(value)
