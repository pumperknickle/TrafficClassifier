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
  rand_val = random.randint(0, total)
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

def stringRep(sig):
  return str(sig[0]) if isinstance(sig[0], int) else signatureToString(sig)    

def generate(directory, distance_threshold, clusterMin, minSigSize, maxSigSize, n):
  pcapPath = directory + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  sequences = []
  all_signatures = dict()
  for file in pcapFiles:
    sequence = convertToFeatures(file)
    sequences.append(sequence)
  # Extract signatures from all packet streams
  for i in range(minSigSize, maxSigSize + 1):
    allngrams = []
    for sequence in sequences:
      ngramVector = ngrams(i, sequence)
      for ngram in ngramVector:
        allngrams.append(ngram)
    if len(allngrams) == 0:
      return []
    cluster = dbclustermin(allngrams, distance_threshold, clusterMin)
    signatures = extractSignatures(cluster, i)
    all_signatures[i] = signatures
  # Convert array of packets to array of signatures and chatty packets
  converted_sequences = []
  for sequence in sequences:
    converted_sequence = convert_sequence(sequence, all_signatures, minSigSize, maxSigSize)
    converted_sequences.append(convert_sequence(sequence, all_signatures, minSigSize, maxSigSize))
  # Extract Markov Chain from array of signatures and chatty packets
  transitions = dict()
  for sequence in converted_sequences:    
    extendedSequence = ["start"] + sequence + ["end"]
    bigrams = ngrams(2, extendedSequence)
    for bigram in bigrams:
      leftSingle = isinstance(bigram[0][0], int)
      rightSingle = isinstance(bigram[1][0], int)
      left = "start" if bigram[0] == "start" else (str(bigram[0][0]) if leftSingle else signatureToString(bigram[0]))
      right = "end" if bigram[1] == "end" else (str(bigram[1][0]) if rightSingle else signatureToString(bigram[1]))
      trans_for_element = transitions.get(left, dict())
      trans_for_element[right] = trans_for_element.get(right, 0) + 1
      transitions[left] = trans_for_element
  # Generate with markov chain
  all_gen = []
  for num in range(n):  
    generated = []
    generatedSigs = []
    previous_element = "start"
    while not previous_element == 'end':
      next_choose = transitions[previous_element]
      previous_element = choose(next_choose)
      if previous_element == "end":
        break
      elif is_int(previous_element):
        generated.append(int(previous_element))
        generatedSigs.append(previous_element)
      else:
        generatedSigs.append(previous_element)
        discrete = generate_from_sig(stringToSignature(previous_element))
        for item in discrete:
          generated.append(item)
    all_gen.append(generated)
  return all_gen
