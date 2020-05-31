import pyshark
import sys
import math
import statistics
from sklearn.cluster import DBSCAN
import random

def most_common(lst):
    return max(set(lst), key=lst.count) 
 
def convertToFeatures(pathToFile):
  pcaps = pyshark.FileCapture(pathToFile)
  pcaps.set_debug()
  tuples = []
  for pcap in pcaps:
    if 'IP' in pcap and 'TCP' in pcap and 'TLS' not in pcap:
      tuples.append([pcap.ip.src, pcap.ip.dst, pcap.length])
    else: 
      if 'TLS' in pcap and 'TCP' in pcap and 'IP' in pcap:
        try:
          tlsPCAP = getattr(pcap.tls, 'tls.record.content_type')
          if tlsPCAP == 23:
            tuples.append([pcap.ip.src, pcap.ip.dst, pcap.length])
        except:
          print("TLS did not have content type attribute!")
  pcaps.close()
  sources = [row[0] for row in tuples]
  destinations = [row[1] for row in tuples]
  if not sources and not destinations:
    return []
  most_common_ip = most_common(sources + destinations)
  features = []
  for row in tuples:
    if row[0] == most_common_ip:
      length = int(row[2])
      features.append(length)
    else:
      length = int(row[2]) * -1
      features.append(length)
  return features

def ngrams(n, sequence):
  output = []
  for i in range(len(sequence)-n+1):
    output.append(sequence[i:i+n])
  return output

def isPingPong(sequence):
  for i in range(len(sequence)-1):
    if sequence[i] > 0 and sequence[i+1] > 0:
      return False
    if sequence[i] < 0 and sequence[i+1] < 0:
      return False
  return True

def countngrams(sequences):
  counts = dict()
  for i in sequences:
    counts[tuple(i)] = counts.get(tuple(i), 0) + 1
  return counts

def similarity(x, y, coefficient_of_variation_threshold):
  coefficients_of_variations = []
  for i in len(x):
    mean = (x.get(i, 0) + y.get(i, 0))/2
    variance = ((x.get(i, 0) - mean) ** 2) + ((y.get(i, 0) - mean) ** 2)
    standard_dev = math.sqrt(variance)
    coefficients_of_variations.append(float(standard_dev)/mean)
  return statistics.mean(coefficients_of_variations) < coefficient_of_variation_threshold

def dbclustermin(x, eps, min_samples):
  db = DBSCAN(eps, min_samples).fit(x)
  clusters = dict()
  for i in range(len(db.labels_)):
    if db.labels_[i] != -1:
      clusters[db.labels_[i]] = clusters.get(db.labels_[i], []) + [x[i]]
  return list(clusters.values())

# Cluster using dbscan
def dbcluster(x, eps, samples_ratio):
  min_samples = math.floor(len(x)/float(samples_ratio))
  db = DBSCAN(eps, min_samples).fit(x)
  clusters = dict()
  for i in range(len(db.labels_)):
    if db.labels_[i] != -1:
      clusters[db.labels_[i]] = clusters.get(db.labels_[i], []) + [x[i]]
  return list(clusters.values())

# Extract Signatures from cluster
def extractSignatures(clusters, n):
  signatures = []
  for cluster in clusters:
    signature = []
    for i in range(n):
      column = []
      for seq in cluster:
        column.append(seq[i])
      signature.append((min(column), max(column)))
    signatures.append(signature)
  return signatures

def matches(ngram, signature):
  for i in range(len(ngram)):
    ngramElement = ngram[i]
    signatureElement = signature[i]
    sigMin = signatureElement[0]
    sigMax = signatureElement[1]
    if ngramElement < sigMin or ngramElement > sigMax:
      return False
  return True

def generate_from_sig(signature):
  generated = []
  for tuple in signature:
    generated.append(random.randint(tuple[0], tuple[1]))
  return generated

def extractFeatures(ngrams, signatures):
  features = []
  for signature in signatures:
    count = 0
    for ngram in ngrams:
      if matches(ngram, signature):
        count += 1
    frequency = 0 if len(ngrams) == 0 else (count)/float(len(ngrams))
    features.append(frequency)
  return features

def signatureExtractionAll(sequences, minSigSize, maxSigSize, distance_threshold, cluster_threshold):
  all_signatures = dict()
  for i in range(minSigSize, maxSigSize + 1):
    allngrams = []
    for sequence in sequences:
      ngramVector = ngrams(i, sequence)
      for ngram in ngramVector:
        allngrams.append(ngram)
    cluster = dbclustermin(allngrams, distance_threshold, cluster_threshold)
    signatures = extractSignatures(cluster, i)
    all_signatures[i] = signatures
  return all_signatures

def featureExtractionAll(sequences, all_signatures):
  signatureFeatures = [None] * len(sequences)
  for i in range(len(sequences)):
    signatureFeatures[i] = featureExtraction(sequences[i], all_signatures)
  return signatureFeatures

def featureExtraction(sequence, all_signatures):
  all_features = []
  for i, signatures in all_signatures.items():
    ngramVector = ngrams(i, sequence)
    newFeatures = extractFeatures(ngramVector, signatures)
    all_features = all_features + newFeatures
  return all_features


def signatureToString(signature):
  signature_ints = []
  for tuple in signature:
    signature_ints.append(tuple[0])
    signature_ints.append(tuple[1])
  return ', '.join(str(x) for x in signature_ints)

def stringToSignature(item):
  item.replace(" ", "")
  arr = item.split(',')
  int_arr = [int(numeric_string) for numeric_string in arr]
  sig = []
  for i in range(0, len(int_arr), 2):
    sig.append((int_arr[i], int_arr[i+1]))
  return sig
        
pathToFile = '/Users/jbao/DeviceIdentityClassifier/captures2/D-LinkSensor/Setup-B-1-STA.pcap'
features = convertToFeatures(pathToFile)
bigrams = ngrams(3, features)
cluster = dbcluster(bigrams, 3.0, 100)
signatures = extractSignatures(cluster, 3)
features = extractFeatures(bigrams, signatures)
print(features)
