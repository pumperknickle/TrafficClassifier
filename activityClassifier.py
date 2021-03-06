import sys
import glob
from advancedPcapAnalyzer import extractFeatures, extractSignatures, ngrams, dbcluster, dbclustermin, convertToFeatures, signatureExtractionAll, featureExtractionAll

directory = sys.argv[1]
extended = directory + '/*/'
paths = glob.glob(extended)

# distance metric used by dbscan
distance_threshold = 5.0
# total ngrams divided by cluster threshold is equal to the min_samples needed to form a cluster in dbscan
cluster_threshold = 4

currentLabel = 0
features = []
labels = []

# convert pcaps to packet size sequences
for path in paths:
  pcapPath = path + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  for file in pcapFiles:
    featureV = convertToFeatures(file)
    features.append(featureV)
    labels.append(currentLabel)
  currentLabel += 1

all_signatures = signatureExtractionAll(features, 2, 5, distance_threshold, cluster_threshold)
signatureFeatures = featureExtractionAll(features, all_signatures)

finalFeatures = []
finalLabels = []
totalClassified = 0
for i in range(len(signatureFeatures)):
  signatureFeature = signatureFeatures[i]
  if not all(v == 0 for v in signatureFeature):
    finalFeatures.append(signatureFeature)
    finalLabels.append(labels[i])

print('total classified')
print(len(set(finalLabels)))
  
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
