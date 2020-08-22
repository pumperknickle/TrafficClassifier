import sys
import glob
import numpy as np
import csv
from keras.utils import plot_model
from keras.utils import np_utils
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold
from keras.models import Sequential
from keras.layers import Dense
from keras.wrappers.scikit_learn import KerasClassifier
from advancedPcapAnalyzer import featureExtractionAll, signatureExtractionAll, ngrams, dbcluster, dbclustermin, \
    convertToFeatures
from activityGeneration import generate
from math import floor, ceil

distance_threshold = 5.0
cluster_threshold = 4
min_sig_size = 1
max_sig_size = 7

real_filename = 'real_data1.txt'
fake_filename = 'fake_data1.txt'


def extractSequences(filename):
    sequences = []
    with open(filename, mode="rU") as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=' ', dialect=csv.excel)
        for row in csv_reader:
            sequences.append(row)
    return sequences


real = extractSequences(real_filename)
fake = extractSequences(fake_filename)

all_signatures = signatureExtractionAll(real + fake, min_sig_size, max_sig_size, distance_threshold, cluster_threshold)

real_features = featureExtractionAll(real, all_signatures)
print('reals')
print(real_features[0])
print(real_features[1])
print(real_features[2])
fake_features = featureExtractionAll(fake, all_signatures)
print('fakee')
print(fake_features[0])
print(fake_features[1])
print(fake_features[2])


def baseline_model():
    model = Sequential()
    model.add(Dense(300, activation='relu'))
    model.add(Dense(300, activation='relu'))
    model.add(Dense(2, activation='softmax'))
    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    return model


real_labels = [0] * len(real_features)
fake_labels = [1] * len(fake_features)

features = real_features + fake_features
labels = real_labels + fake_labels
dummy_labels = np_utils.to_categorical(labels)
estimator = KerasClassifier(build_fn=baseline_model, epochs=60, batch_size=5, verbose=1)
kfold = KFold(n_splits=5, shuffle=True)
results = cross_val_score(estimator, np.array(features), dummy_labels, cv=kfold)
print("Baseline: %.2f%% (%.2f%%)" % (results.mean() * 100, results.std() * 100))
