import sys
import glob
from advancedPcapAnalyzer import extractFeatures, extractSignatures, ngrams, dbcluster, dbclustermin, convertToFeatures, matches, signatureToString, stringToSignature, generate_from_sig
import random

def convert_sequence(sequence, all_signatures, minSigSize, maxSigSize):
  if len(sequence) == 0:
    return []
  if len(sequence) < 2:
    return [sequence]
  for i in range(maxSigSize, minSigSize - 1, -1):
    prefix = sequence[:i]
    signatures = all_signatures[i]
    for signature in signatures:
      if matches(prefix, signature):
        return [signature] + convert_sequence(sequence[i:], all_signatures, minSigSize, maxSigSize)
  return [sequence[:1]] + convert_sequence(sequence[1:], all_signatures, minSigSize, maxSigSize)

def choose(elements):
  total = sum(elements.values())
  rand_val = random.randint(0, total-1)
  for key, value in elements.items():
    if rand_val <= value:
      return key
    rand_val -= value

def is_int(val):
    try:
        num = int(val)
    except ValueError:
        return False
    return True

def generate(directory, distance_threshold, clusterMin, minSigSize, maxSigSize, maxSigsGenerated):
  pcapPath = directory + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  sequences = []
  all_signatures = dict()
  for file in pcapFiles:
    sequence = convertToFeatures(file)
    print(sequence)
    sequences.append(sequence)
  for i in range(minSigSize, maxSigSize + 1):
    allngrams = []
    for sequence in sequences:
      ngramVector = ngrams(i, sequence)
      for ngram in ngramVector:
        allngrams.append(ngram)
    cluster = dbclustermin(allngrams, distance_threshold, clusterMin)
    signatures = extractSignatures(cluster, i)
    all_signatures[i] = signatures
  converted_sequences = []
  for sequence in sequences:
    converted_sequences.append(convert_sequence(sequence, all_signatures, minSigSize, maxSigSize))
  transitions = dict()
  starting = dict()
  for sequence in converted_sequences:
    firstElement = sequence[0]
    firstStringElement = str(firstElement[0]) if isinstance(firstElement[0], int) else signatureToString(firstElement)
    starting[firstStringElement] = starting.get(firstStringElement, 0) + 1
    bigrams = ngrams(2, sequence)
    for bigram in bigrams:
      leftSingle = isinstance(bigram[0][0], int)
      rightSingle = isinstance(bigram[1][0], int)
      left = str(bigram[0][0]) if leftSingle else signatureToString(bigram[0])
      right = str(bigram[1][0]) if rightSingle else signatureToString(bigram[1])
      trans_for_element = transitions.get(left, dict())
      trans_for_element[right] = trans_for_element.get(right, 0) + 1
      transitions[left] = trans_for_element
  generated = []
  previous_element = choose(starting)
  if is_int(previous_element):
    generated.append(int(previous_element))
  else:
    discrete = generate_from_sig(stringToSignature(previous_element))
    for item in discrete:
      generated.append(item)
  for i in range(maxSigsGenerated):
    if not previous_element in transitions:
      break
    next_choose = transitions[previous_element]
    previous_element = choose(next_choose)
    if is_int(previous_element):
      generated.append(int(previous_element))
    else:
      discrete = generate_from_sig(stringToSignature(previous_element))
      for item in discrete:
        generated.append(item)
  return generated

directory = sys.argv[1]
print(generate(directory, 5, 10, 2, 5, 200))

