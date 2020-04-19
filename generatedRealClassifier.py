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
max_sig_generated = 200
seqeunces_per_device = 20

currentLabel = 0
features = []
labels = []

generatedFeatures = []
generatedLabels = []

# convert pcaps to packet size sequences
for path in paths:
  generated = generate(path, distance_threshold, min_cluster, min_sig_size, max_sig_size, seqeunces_per_device)
  for g in generated:
    print(path)
    print(g)
    generatedFeatures.append(g)
    generatedLabels.append(currentLabel)
  pcapPath = path + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  for file in pcapFiles:
    featureV = convertToFeatures(file)
    features.append(featureV)
    labels.append(currentLabel)
  currentLabel += 1

print(features)
print(generatedFeatures)
signatureFeatures = [None] * len(features)
generatedSignatureFeatures = [None] * len(generatedFeatures)

# Create features
for i in range(min_sig_size, max_sig_size + 1):
  allngrams = []
  for feature in features:
    ngramVector = ngrams(i, feature)
    for ngram in ngramVector:
      allngrams.append(ngram)
  cluster = dbclustermin(allngrams, distance_threshold, min_cluster)
  signatures = extractSignatures(cluster, i)
  for n in range(len(features)):
    feature = features[n]
    extractedNgrams = ngrams(i, feature)
    newFeatures = extractFeatures(extractedNgrams, signatures)
    if signatureFeatures[n] == None:
      signatureFeatures[n] = newFeatures
    else:
      signatureFeatures[n] = signatureFeatures[n] + newFeatures
  for n in range(len(generatedFeatures)):
    feature = generatedFeatures[n]
    extractedNgrams = ngrams(i, feature)
    newFeatures = extractFeatures(extractedNgrams, signatures)
    if generatedSignatureFeatures[n] == None:
      generatedSignatureFeatures[n] = newFeatures
    else:
      generatedSignatureFeatures[n] = generatedSignatureFeatures[n] + newFeatures

finalFeatures = []
finalLabels = []

for i in range(len(signatureFeatures)):
  signatureFeature = signatureFeatures[i]
  if not all(v == 0 for v in signatureFeature):
    finalFeatures.append(signatureFeature)
    finalLabels.append(labels[i])

finalGeneratedFeatures = []
finalGeneratedLabels = []

for i in range(len(generatedFeatures)):
  signatureFeature = generatedSignatureFeatures[i]
  if not all(v == 0 for v in signatureFeature):
    finalGeneratedFeatures.append(signatureFeature)
    finalGeneratedLabels.append(generatedLabels[i])

dummy_labels = np_utils.to_categorical(finalLabels)
num_classes = len(dummy_labels[0])
dummy_generated_labels = np_utils.to_categorical(finalGeneratedLabels)

def baseline_model():
  model = Sequential()
  model.add(Dense(300, activation='relu'))
  model.add(Dense(300, activation='relu'))
  model.add(Dense(num_classes, activation='softmax'))
  model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
  return model

plot_model(baseline_model(), to_file='model.png', show_shapes=True, show_layer_names=True)
model = baseline_model()
model.fit(np.array(finalFeatures), dummy_labels, validation_data=(np.array(finalGeneratedFeatures), dummy_generated_labels), epochs=200, batch_size=5)
