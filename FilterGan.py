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
from advancedPcapAnalyzer import extractFeatures, extractSignatures, ngrams, dbcluster, dbclustermin, convertToFeatures, signatureExtractionAll, featureExtractionAll
from activityGeneration import generateWithSignatures, createTransitions, generateWithTransitions

directory = sys.argv[1]
extended = directory + '/*/'
paths = glob.glob(extended)

distance_threshold = 5.0
cluster_threshold = 4
min_sig_size = 2
max_sig_size = 5

all_sequences = []
real_sequences = dict()
real_features = dict()
device_names = dict()
device_number = 0

for path in paths:
  device_names[device_number] = path
  pcapPath = path + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  real = []
  for file in pcapFiles:
    sequence = convertToFeatures(file)
    all_sequences.append(sequence)
    if len(sequence) > 0:
      real.append(sequence)
  if len(real) <= 10:
    continue
  real_sequences[device_number] = real
  device_number += 1

all_signatures = signatureExtractionAll(all_sequences, min_sig_size, max_sig_size, distance_threshold, cluster_threshold)

for key in real_sequences:
  real = real_sequences[key]
  real_features[key] = featureExtractionAll(real, all_signatures)
  if all(v == 0 for v in real_features[key]):
    print("zero features")
    print(key)

all_transitions = dict()

for device, sequences in real_sequences.items():
  all_transitions[device] = createTransitions(sequences, all_signatures)

def baseline_model():
  model = Sequential()
  model.add(Dense(300, activation='relu'))
  model.add(Dense(300, activation='relu'))
  model.add(Dense(2, activation='softmax'))
  model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
  return model

def generatePassingFakes(total, n, transitions, all_signatures, classifier):
  filteredFakes = []
  while(total > 0):
    fake_sequences = generateWithTransitions(transitions, n)
    fakes = featureExtractionAll(fake_sequences, all_signatures)
    y_pred = classifier.predict(np.array(fakes))
    for i in range(len(y_pred)):
      if y_pred[i] < 0.5:
        filteredFakes.append(fakes[i])
        total -= 1
  return filteredFakes

def filterLoop(classifiers=dict(), previous_fakes = dict(), all_signatures=[], all_transitions=dict(), real_features=[], n=0, iterations_left=0, all_results=dict()):
  if iterations_left == 0:
    return (all_results, classifiers)
  results_for_iteration = dict()
  for deviceNumber, sequences in real_sequences.items():
    reals = real_features[deviceNumber]
    transitions = all_transitions[deviceNumber]
    real_labels = [0] * len(reals)
    estimator = KerasClassifier(build_fn=baseline_model, epochs=200, batch_size=5, verbose=1)
    kfold = KFold(n_splits=4, shuffle=True)
    filteredFakes = []
    if not deviceNumber in classifiers:
      fake_sequences = generateWithTransitions(transitions, n)
      filteredFakes = featureExtractionAll(fake_sequences, all_signatures)
    else:
      classifier = classifiers[deviceNumber]
      filteredFakes = generatePassingFakes(n, n, transitions, all_signatures, classifier)
    print("number of fakes that trick classifier")
    print(len(filteredFakes))
    all_fakes = previous_fakes.get(deviceNumber, []) + filteredFakes
    previous_fakes[deviceNumber] = all_fakes
    fake_labels = [1] * len(all_fakes)
    features = reals + all_fakes
    labels = real_labels + fake_labels
    dummy_labels = np_utils.to_categorical(labels)
    filteredFeatures = reals + filteredFakes
    filtered_fake_labels = [1] * len(filteredFakes)
    filtered_labels = real_labels + filtered_fake_labels
    filtered_dummy_labels = np_utils.to_categorical(filtered_labels)
    results = cross_val_score(estimator, np.array(filteredFeatures), filtered_dummy_labels, cv=kfold)
    print("Baseline: %.2f%% (%.2f%%)" % (results.mean()*100, results.std()*100))
    results_for_iteration[deviceNumber] = results.mean()
    nextEstimator = KerasClassifier(build_fn=baseline_model, epochs=200, batch_size=5, verbose=1)
    nextEstimator.fit(np.array(features), dummy_labels, batch_size=5, epochs=200)
    classifiers[deviceNumber] = nextEstimator
  all_results[iterations_left] = results_for_iteration
  filterLoop(classifiers=classifiers, previous_fakes=previous_fakes, all_signatures=all_signatures, all_transitions=all_transitions, real_features=real_features, n=n, iterations_left=iterations_left - 1, all_results=all_results)

results = filterLoop(all_signatures=all_signatures, all_transitions=all_transitions, real_features=real_features, n=20, iterations_left=10)
for key, value in results[0].items():
  print(key)
  print(value)

for key, value in device_names.items():
  print(key)
  print(value)
