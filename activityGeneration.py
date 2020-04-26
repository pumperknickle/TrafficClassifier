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

def remove_trailing(sequence):
  sequence_length = len(sequence)
  last_element = sequence[sequence_length - 1]
  for i in range(sequence_length - 2, -1, -1):
    if last_element != sequence[i]:
      return sequence[:i+1]
  return []

def max_consecutive_repetitions(seq):
  result=1
  max_result=0
  last_seen=seq[0]
  for v in seq[1:]:
    if v==last_seen:
      result += 1
    else:
      if result > max_result:
        max_result = result
      last_seen = v
      result = 1
  if result > max_result:
    max_result = result
  return max_result

def exceeds_max_repetitions(seq, max):
  if len(seq) < max + 1:
    return False
  last_elements = seq[-max - 1:]
  if len(set(last_elements)) == 1:
    return True
  return False

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
  converted_sequences = []
  max_repititons = 1
  max_signature_repetitions = 1
  min_packets = 10000000
  max_packets = 0
  for sequence in sequences:
    sequence_length = len(sequence)
    min_packets = min(min_packets, sequence_length)
    max_packets = max(max_packets, sequence_length)
    max_repititons = max(max_repititons, max_consecutive_repetitions(sequence))
    converted_sequence = convert_sequence(sequence, all_signatures, minSigSize, maxSigSize)
    max_signature_repetitions = max(max_signature_repetitions, max_consecutive_repetitions(converted_sequence))
    converted_sequences.append(convert_sequence(sequence, all_signatures, minSigSize, maxSigSize))
  transitions = dict()
  for sequence in converted_sequences:    
    firstElement = sequence[0]
    firstStringElement = str(firstElement[0]) if isinstance(firstElement[0], int) else signatureToString(firstElement)
    lastElement = sequence[-1]
    lastStringElement = str(lastElement[0]) if isinstance(lastElement[0], int) else signatureToString(lastElement)
    elements_for_start = transitions.get("start", dict())
    elements_for_start[firstStringElement] = elements_for_start.get(firstStringElement, 0) + 1
    transitions["start"] = elements_for_start
    elements_for_last = transitions.get(lastStringElement, dict())
    elements_for_last["end"] = elements_for_last.get("end", 0) + 1
    transitions[lastStringElement] = elements_for_last
    bigrams = ngrams(2, sequence)
    for bigram in bigrams:
      leftSingle = isinstance(bigram[0][0], int)
      rightSingle = isinstance(bigram[1][0], int)
      left = str(bigram[0][0]) if leftSingle else signatureToString(bigram[0])
      right = str(bigram[1][0]) if rightSingle else signatureToString(bigram[1])
      trans_for_element = transitions.get(left, dict())
      trans_for_element[right] = trans_for_element.get(right, 0) + 1
      transitions[left] = trans_for_element
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
