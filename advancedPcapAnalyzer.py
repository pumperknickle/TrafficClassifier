import pyshark
import sys


pathToFile = '/Users/jbao/DeviceIdentityClassifier/captures2/D-LinkSensor/'
pcaps = pyshark.FileCapture(pathToFile)
for pcap in pcaps:
  if 'IP' in pcap and 'TCP' in pcap and 'TLS' not in pcap:
    print(pcap.ip.src)
    print(pcap.ip.dst)
    print(pcap.length) 
  if 'TLS' in pcap and 'TCP' in pcap and 'IP' in pcap:
    try:
      tlsPCAP = getattr(pcap.tls, 'tls.record.content_type')
      if tlsPCAP == 23:
        print(pcap.ip.src)
        print(pcap.ip.dst)
        print(pcap.length)
    except:
      print("weird!")

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
  sources = [row[0] for row in tuples]
  destinations = [row[1] for row in tuples]
  print(sources)
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

features = convertToFeatures(pathToFile)
print(features)
