import pyshark as ps
import matplotlib.pyplot as plt
import numpy as np

Cap = [0,0,0,0,0]
Cap[0] = ps.FileCapture("Paquets/demarrage_signal.pcapng")
Cap[1] = ps.FileCapture("Paquets/message_recu.pcapng")
Cap[2] = ps.FileCapture("Paquets/message_2_sens.pcapng")
Cap[3] = ps.FileCapture("Paquets/message_vocal.pcapng")
Cap[4] = ps.FileCapture("Paquets/appel.pcapng")
"""
Qry_name = []

for cap in Cap:
    Qry_name.append([pkt.dns.qry_name for pkt in cap if 'dns' in pkt])

"""
Qry_name = [['chat.signal.org', 'chat.signal.org', 'chat.signal.org', 'chat.signal.org', 
  'chat.signal.org', 'chat.signal.org', 'chat.signal.org', 'chat.signal.org', 'chat.signal.org', 
  'chat.signal.org', 'chat.signal.org', 'chat.signal.org', 'storage.signal.org', 'storage.signal.org', 
  'storage.signal.org', 'storage.signal.org', 'storage.signal.org', 'storage.signal.org', 'storage.signal.org', 
  'storage.signal.org', 'cdn2.signal.org', 'cdn2.signal.org', 'cdn2.signal.org', 'cdn2.signal.org', 'cdn2.signal.org', 
  'cdn2.signal.org', 'cdn2.signal.org', 'cdn2.signal.org'], 
  
  [], 
  
  ['chat.signal.org', 'chat.signal.org', 'chat.signal.org','chat.signal.org', 'chat.signal.org', 'chat.signal.org'], 
  
  ['cdn.signal.org', 'cdn.signal.org', 'cdn.signal.org', 'cdn.signal.org', 'cdn.signal.org', 'cdn.signal.org', 'cdn.signal.org', 'cdn.signal.org'], 
  
  ['chat.signal.org', 'chat.signal.org', 'chat.signal.org', 'chat.signal.org', 'chat.signal.org', 'chat.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 
'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'turn3.voip.signal.org', 'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 
'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 
'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 
'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 
'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 'turn3.voip.signal.org', 
'turn3.voip.signal.org', 'turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 
'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'ipv6.turn3.voip.signal.org', 'connectivity-check.ubuntu.com', 
'connectivity-check.ubuntu.com', 'connectivity-check.ubuntu.com', 'connectivity-check.ubuntu.com']]


from collections import Counter

fig, ax = plt.subplots(1,1)


for i in range(5):
    Compteurs = Counter(Qry_name[i])

    ax.bar(Compteurs.keys, Compteurs.values)
    print(Compteurs.keys)


plt.show()