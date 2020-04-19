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

for path in paths:
  real = []
  pcapPath = path + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  for file in pcapFiles:
    featureV = convertToFeatures(file)
    real.append(featureV)
  generated = generate(path, distance_threshold, min_cluster, min_sig_size, max_sig_size, len(real))
  real_sequences[currentDevice] = real
  fake_sequences[currentDevice] = generated
  currentDevice += 1

all_fake_features = dict()
all_real_features = dict()

for device in real_sequences:
  real = real_sequences[device]
  fake = fake_sequences[device]
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
    for n in range(len(real_features)):
      feature = real_features[n]
      extractedNgrams = ngrams(i, feature)
      newFeatures = extractFeatures(extractedNgrams, signatures)
      if real_features[n] == None:
        real_features[n] = newFeatures
      else:
        real_features[n] = real_features[n] + newFeatures
    for n in range(len(fake_features)):
      feature = fake_features[n]
      extractedNgrams = ngrams(i, feature)
      newFeatures = extractFeatures(extractedNgrams, signatures)
      if fake_features[n] == None:
        fake_features[n] = newFeatures
      else:
        fake_features[n] = fake_features[n] + newFeatures
  all_fake_features[device] = fake_features
  all_real_features[device] = real_features

def baseline_model():
  model = Sequential()
  model.add(Dense(300, activation='relu'))
  model.add(Dense(300, activation='relu'))
  model.add(Dense(2, activation='softmax'))
  model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
  return model

for device in all_fake_features:
  X_real = all_real_features[device]
  X_fake = all_fake_features[device]
  real_labels = [0] * len(X_real)
  fake_labels = [1] * len(X_fake)
  labels = real_labels.extend(fake_labels)
  features = X_real.extend(X_fake)
  estimator = KerasClassifier(build_fn=baseline_model, epochs=200, batch_size=5, verbose=1)
  kfold = KFold(n_splits=10, shuffle=True)
  results = cross_val_score(estimator, np.array(features), np.array(labels), cv=kfold)
  print("Baseline: %.2f%% (%.2f%%)" % (results.mean()*100, results.std()*100))

  
