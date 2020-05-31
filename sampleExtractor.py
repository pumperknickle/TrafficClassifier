import sys
import glob
import csv

from advancedPcapAnalyzer import convertToFeatures

seq_length = 20
currentLabel = 0
sequences = []
labels = []

directory = sys.argv[1]
extended = directory + '/*/'
paths = glob.glob(extended)

minDicts = dict()
maxDicts = dict()
    
# convert pcaps to packet size sequences
for path in paths:
  minDicts[currentLabel] = 5000
  maxDicts[currentLabel] = -5000
  pcapPath = path + '/*.pcap'
  pcapFiles = glob.glob(pcapPath)
  for file in pcapFiles:
    featureV = convertToFeatures(file)
    sequences.append(featureV)
    labels.append(currentLabel)
  currentLabel += 1

def divide_chunks(l, n): 
    # looping till length l 
    for i in range(0, len(l), n):  
        yield l[i:i + n] 

for i in range(len(sequences)):
  chunks = divide_chunks(sequences[i], seq_length)
  for chunk in chunks:
    if min(chunk) < minDicts[labels[i]]:
      minDicts[labels[i]] = min(chunk)
    if max(chunk) > maxDicts[labels[i]]:
      maxDicts[labels[i]] = max(chunk)

for i in range(len(sequences)):
  print(labels[1])
  filename = str(labels[i]) + '.csv'
  with open(filename, mode='w') as csvfile:
    csv_writer = csv.writer(csvfile, delimiter=' ')
    chunks = divide_chunks(sequences[i], seq_length)
    for chunk in chunks:
      alteredChunk = list(map(lambda x: x - minDicts[labels[i]], chunk))
      if len(chunk) == seq_length:
        csv_writer.writerow(alteredChunk)

print(maxDicts)
print(minDicts)
