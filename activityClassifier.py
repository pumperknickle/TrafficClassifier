import sys
import glob
from advancedPcapAnalyzer import extractFeatures, extractSignatures, ngrams, dbcluster, dbclustermin, convertToFeatures

directory = sys.argv[1]
extended = directory + '/*/'
paths = glob.glob(extended)


# distance metric used by dbscan
distance_threshold = 5.0
# total ngrams divided by cluster threshold is equal to the min_samples needed to form a cluster in dbscan
cluster_threshold = 5000

currentLabel = 0
features = []
labels = []

# convert pcaps to packet size sequences
for path in paths:
  pcapPath = path + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  for file in pcapFiles:
    print(file)
    print(currentLabel)
    featureV = convertToFeatures(file)
    features.append(featureV)
    labels.append(currentLabel)
  currentLabel += 1

print(features)
signatureFeatures = [None] * len(features)

# Create features
for i in range(2, 6):
  allngrams = []
  for feature in features:
    ngramVector = ngrams(i, feature)
    for ngram in ngramVector:
      allngrams.append(ngram)
  cluster = dbclustermin(allngrams, distance_threshold, 4)
  signatures = extractSignatures(cluster, i)
  for n in range(len(features)):
    feature = features[n]
    extractedNgrams = ngrams(i, feature)
    newFeatures = extractFeatures(extractedNgrams, signatures)
    if signatureFeatures[n] == None:
      signatureFeatures[n] = newFeatures
    else:
      signatureFeatures[n] = signatureFeatures[n] + newFeatures

finalFeatures = []
finalLabels = []
for i in range(len(features)):
  signatureFeature = signatureFeatures[i]
  if not all(v == 0 for v in signatureFeature):
    finalFeatures.append(signatureFeature)
    finalLabels.append(labels[i])
  

import numpy as np
from keras.utils import np_utils
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold
from keras.models import Sequential
from keras.layers import Dense
from keras.wrappers.scikit_learn import KerasClassifier

dummy_labels = np_utils.to_categorical(finalLabels)
num_classes = len(dummy_labels[0])

def baseline_model():
  model = Sequential()
  model.add(Dense(300, activation='relu'))
  model.add(Dense(300, activation='relu'))
  model.add(Dense(num_classes, activation='softmax'))
  model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
  return model

from keras.utils import plot_model
plot_model(baseline_model(), to_file='model.png', show_shapes=True, show_layer_names=True)

estimator = KerasClassifier(build_fn=baseline_model, epochs=200, batch_size=5, verbose=1)
kfold = KFold(n_splits=10, shuffle=True)
results = cross_val_score(estimator, np.array(finalFeatures), dummy_labels, cv=kfold)
print("Baseline: %.2f%% (%.2f%%)" % (results.mean()*100, results.std()*100))
