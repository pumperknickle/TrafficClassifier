import sys
import glob
from advancedPcapAnalyzer import extractFeatures, extractSignatures, ngrams, dbcluster, dbclustermin, convertToFeatures, matches, signatureToString, stringToSignature, generate_from_sig
import random 

directory = sys.argv[1]
distance_threshold = 5.0
pcapPath = directory + '/*.pcap'
pcapFiles = glob.glob(pcapPath)

sequences = []
all_signatures = dict()

for file in pcapFiles:
  sequence = convertToFeatures(file)
  sequences.append(sequence)

for i in range(2, 6):
  allngrams = []
  for sequence in sequences:
    ngramVector = ngrams(i, sequence)
    for ngram in ngramVector:
      allngrams.append(ngram)  
  cluster = dbclustermin(allngrams, distance_threshold, 10)
  signatures = extractSignatures(cluster, i)
  all_signatures[i] = signatures

signatures_captured = 0
non_signatures_captured = 0

def convert_sequence(sequence):
  global signatures_captured
  global non_signatures_captured
  if len(sequence) == 0:
    return []
  if len(sequence) < 2:
    return [sequence]
  for i in range(5, 1, -1):
    prefix = sequence[:i]
    signatures = all_signatures[i]
    for signature in signatures:
      if matches(prefix, signature):
        signatures_captured += 1
        return [signature] + convert_sequence(sequence[i:])
  non_signatures_captured += 1
  return [sequence[:1]] + convert_sequence(sequence[1:])

converted_sequences = []

for sequence in sequences:
  converted_sequences.append(convert_sequence(sequence))

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

print(transitions)
print(starting)

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

generated = []
previous_element = choose(starting)
if is_int(previous_element):
  generated.append(int(previous_element))
else:
  discrete = generate_from_sig(stringToSignature(previous_element))
  for item in discrete:
    generated.append(item)
for i in range(200):
  next_choose = transitions[previous_element]
  previous_element = choose(next_choose)
  if is_int(previous_element):
    generated.append(int(previous_element))
  else:
    discrete = generate_from_sig(stringToSignature(previous_element))
    for item in discrete:
      generated.append(item)  

print(generated)
