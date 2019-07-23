import sys
from pcapfile import savefile
from struct import *
import pcapy as p
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
#testcap = open('4stage1user-2.pcap', 'rb')
#capfile = savefile.load_savefile( testcap, verbose = True)
#print (capfile)
#for pkt in capfile.packets:
#  print ('%.6f' % pkt.timestamp)
timeArray = {}
userTypeCounter = defaultdict(int)
packets =rdpcap('4stage10000user.pcap')
for pkt in packets:
  print ('%.16f' % pkt.time)
# pkt[Ether].show()
  pkt[TCP].show()
  content = pkt[Raw].load
  while True:
    hexArray = bytearray()
    hexArray.extend(content)
  #  print (hexArray)
    pin = 0
    pout = 0
    if hexArray[0] != 0x01:
      print ('something is wrong! code is not 1')
    if hexArray[1] == 0x0d:
#     print ('packet out')
      imsiString = hexArray[30:34]
      code = hexArray[26]
      pout = 1
    if hexArray[1] == 0x0a:
#     print ('packet in')
      code = hexArray[20]
      imsiString = hexArray[24:28]
      pin = 1
    if pin == 0 and pout == 0:
      print ("something is wrong, no packet in or packet out")
    if pin == 1 and pout == 1:
      print ("something is wrong, packet both in packet in and packet out!")
#   if code == 0x7e:
#     print ("7e is here")
#   print (len (hexArray))
 #  num = int(hexArray[2:3].encode('hex'), 16)
  # ofLength = content[2:4].decode('utf-8')
    ofLength = hexArray[2:4]
    ofLengthInt = unpack ('!H', ofLength)
#   print (ofLengthInt)
    if ofLengthInt[0] != len (hexArray):
      print ("error! probably multiple of messages!")
#   print (int.from_bytes (hexArray[2:3], byteorder='big'))
#   imsiString = hexArray[28:32]
    try:
      imsi = unpack ('I', imsiString)
    except:
      break;
#above try is added because wireshark doesn't save full size packet and makes problem for parsing packets!
    print ("code is", code )
    print ("imsi is" , imsi[0])
    userIndex = imsi[0]
    typeIndex = 20
    stepIndex = 21
    if code == 0x6f and pin == 1:
      typeIndex = 1
      stepIndex = 0
      userTypeCounter[userIndex, 1] += 1
      print ("index 1 step 0")
    elif code == 0x6f and pout == 1:
      typeIndex = 1
      stepIndex = 1
      userTypeCounter[userIndex, 1] += 1
      print ("index 1 step 1")
    elif code == 0x73 and pin == 1:
      typeIndex = 1
      stepIndex = 2
      userTypeCounter[userIndex, 1] += 1
      print ("index 1 step 2")
    elif code == 0x73 and pout == 1:
      typeIndex = 1
      stepIndex = 3
      userTypeCounter[userIndex, 1] += 1
      print ("index 1 step 3")
    elif code == 0x70 and pin == 1:
      typeIndex = 2
      stepIndex = 0
      userTypeCounter[userIndex, 2] += 1
      print ("index 2 step 0")
    elif code == 0x70 and pout == 1:
      typeIndex = 2
      stepIndex = 1
      userTypeCounter[userIndex, 2] += 1
      print ("index 2 step 1")
    elif code == 0x74 and pin == 1:
      typeIndex = 2
      stepIndex = 2
      userTypeCounter[userIndex, 2] += 1
      print ("index 2 step 2")
    elif code == 0x74 and pout == 1:
      typeIndex = 2
      stepIndex = 3
      userTypeCounter[userIndex, 2] += 1
      print ("index 2 step 3")
    elif code == 0x71 and pin == 1:
      typeIndex = 3
      stepIndex = 0
      userTypeCounter[userIndex, 3] += 1
      print ("index 3 step 0")
    elif code == 0x71 and pout == 1:
      typeIndex = 3
      stepIndex = 1
      userTypeCounter[userIndex, 3] += 1
      print ("index 3 step 1")
    elif code == 0x75 and pin == 1:
      typeIndex = 3
      stepIndex = 2
      userTypeCounter[userIndex, 3] += 1
      print ("index 3 step 2")
    elif code == 0x75 and pout == 1:
      typeIndex = 3
      stepIndex = 3
      userTypeCounter[userIndex, 3] += 1
      print ("index 3 step 3")
    elif code == 0x72 and pin == 1:
      typeIndex = 4
      stepIndex = 0
      userTypeCounter[userIndex, 4] += 1
      print ("index 4 step 0")
    elif code == 0x72 and pout == 1:
      typeIndex = 4
      stepIndex = 1
      userTypeCounter[userIndex, 4] += 1
      print ("index 4 step 1")
    elif code == 0x76 and pin == 1:
      typeIndex = 4
      stepIndex = 2
      userTypeCounter[userIndex, 4] += 1
      print ("index 4 step 2")
    elif code == 0x76 and pout == 1:
      typeIndex = 4
      stepIndex = 3
      userTypeCounter[userIndex, 4] += 1
      print ("index 4 step 3")
    elif code == 0x77 and pin == 1:
      typeIndex = 5
      stepIndex = 0
      userTypeCounter[userIndex, 5] += 1
      print ("index 5 step 0")
    elif code == 0x77 and pout == 1:
      typeIndex = 5
      stepIndex = 1
      userTypeCounter[userIndex, 5] += 1
      print ("index 5 step 1")
    elif code == 0x7d and pin == 1:
      typeIndex = 5
      stepIndex = 2
      userTypeCounter[userIndex, 5] += 1
      print ("index 5 step 2")
    elif code == 0x7d and pout == 1:
      typeIndex = 5
      stepIndex = 3
      userTypeCounter[userIndex, 5] += 1
      print ("index 5 step 3")
    elif code == 0x78 and pin == 1:
      typeIndex = 6
      stepIndex = 0
      userTypeCounter[userIndex, 6] += 1
      print ("index 6 step 0")
    elif code == 0x78 and pout == 1:
      typeIndex = 6
      stepIndex = 1
      userTypeCounter[userIndex, 6] += 1
      print ("index 6 step 1")
    elif code == 0x7e and pin == 1:
      typeIndex = 6
      stepIndex = 2
      userTypeCounter[userIndex, 6] += 1
      print ("index 6 step 2")
    elif code == 0x7e and pout == 1:
      typeIndex = 6
      stepIndex = 3
      userTypeCounter[userIndex, 6] += 1
      print ("index 6 step 3")
    elif code == 0x79 and pin == 1:
      typeIndex = 7
      stepIndex = 0
      userTypeCounter[userIndex, 7] += 1
      print ("index 7 step 0")
    elif code == 0x79 and pout == 1:
      typeIndex = 7
      stepIndex = 1
      userTypeCounter[userIndex, 7] += 1
      print ("index 7 step 1")
    elif code == 0x7f and pin == 1:
      typeIndex = 7
      stepIndex = 2
      userTypeCounter[userIndex, 7] += 1
      print ("index 7 step 2")
    elif code == 0x7f and pout == 1:
      typeIndex = 7
      stepIndex = 3
      userTypeCounter[userIndex, 7] += 1
      print ("index 7 step 3")
    elif code == 0x7a and pin == 1:
      typeIndex = 8
      stepIndex = 0
      userTypeCounter[userIndex, 8] += 1
      print ("index 8 step 0")
    elif code == 0x7a and pout == 1:
      typeIndex = 8
      stepIndex = 1
      userTypeCounter[userIndex, 8] += 1
      print ("index 8 step 1")
    elif code == 0x80 and pin == 1:
      typeIndex = 8
      stepIndex = 2
      userTypeCounter[userIndex, 8] += 1
      print ("index 8 step 2")
    elif code == 0x80 and pout == 1:
      typeIndex = 8
      stepIndex = 3
      userTypeCounter[userIndex, 8] += 1
      print ("index 8 step 3")
    elif code == 0x7b and pin == 1:
      typeIndex = 9
      stepIndex = 0
      userTypeCounter[userIndex, 9] += 1
      print ("index 9 step 0")
    elif code == 0x7b and pout == 1:
      typeIndex = 9
      stepIndex = 1
      userTypeCounter[userIndex, 9] += 1
      print ("index 9 step 1")
    elif code == 0x81 and pin == 1:
      typeIndex = 9
      stepIndex = 2
      userTypeCounter[userIndex, 9] += 1
      print ("index 9 step 2")
    elif code == 0x81 and pout == 1:
      typeIndex = 9
      stepIndex = 3
      userTypeCounter[userIndex, 9] += 1
      print ("index 9 step 3")
    elif code == 0x7c and pin == 1:
      typeIndex = 10
      stepIndex = 0
      userTypeCounter[userIndex, 10] += 1
      print ("index 10 step 0")
    elif code == 0x7c and pout == 1:
      typeIndex = 10
      stepIndex = 1
      userTypeCounter[userIndex, 10] += 1
      print ("index 10 step 1")
    elif code == 0x82 and pin == 1:
      typeIndex = 10
      stepIndex = 2
      userTypeCounter[userIndex, 10] += 1
      print ("index 10 step 2")
    elif code == 0x82 and pout == 1:
      typeIndex = 10
      stepIndex = 3
      userTypeCounter[userIndex, 10] += 1
      print ("index 10 step 3")
    else:
      print ("Unhandled case!")
    timeArray[userIndex, typeIndex, stepIndex] = pkt.time
    if  len (hexArray) - ofLengthInt[0] < 27:
      break;
    else:
      print ("content lenth is " + str(len (hexArray)))
      print ("oflength is " + str ( ofLengthInt[0]))
      content = content [ofLengthInt[0]:]
      print ("new content length is " + str (len (content)))
noOfUsers = 10000
processed = {}
typeCounter = defaultdict(int)
delaySum = defaultdict(float)
for u in range(0, noOfUsers):
  for t in range (1, 11):
    if userTypeCounter[u,t] % 4 == 0 and userTypeCounter[u,t] > 0:
      for s in range (0, 3):
        sys.stdout.write(str(u) + " ")
        sys.stdout.write(str(t) + " ")
        sys.stdout.write(str(s) + " ")
        try:
	  print (timeArray [u,t,s+1] - timeArray[u,t,s])
	  if timeArray [u,t,s+1] - timeArray[u,t,s] >= 0:
	    typeCounter[t] += 1
	    delaySum[t,s] += timeArray [u,t,s+1] - timeArray[u,t,s]
	  else:
	    print ("something can be wrong! why the time difference is negative?")
	except:
	  print ("some out of index happened! it is better to not happen!find the reason!")
#TODO: not related to this line, but just last sample of each transaction is stored
#probably we can at least store their average.
allAverage = defaultdict(float)
for t in range (1, 11):
#TODO: add check for not have zero az typecountT
  print ( str(delaySum[t,0] / typeCounter[t]) + " " + str(delaySum[t,1]/typeCounter[t]) + " " + str (delaySum[t,2]/typeCounter[t]))
  allAverage[0] += delaySum[t,0] / typeCounter[t]
  allAverage[1] += delaySum[t,1] / typeCounter[t]
  allAverage[2] += delaySum[t,2] / typeCounter[t]
print ("first part avg: " + str(allAverage[0] / 10))
print ("second part avg: " + str (allAverage[1] / 10))
print ("third part avg: " + str (allAverage[2]/10 ))


