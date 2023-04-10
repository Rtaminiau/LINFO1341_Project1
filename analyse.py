import pyshark as ps
import matplotlib.pyplot as plt

Cap1 = ps.FileCapture("Paquets/demarrage_signal.pcapng")  # First Capture (4 messages send by CC)
Cap2 = ps.FileCapture("Paquets/message_recu.pcapng")
Cap3 = ps.FileCapture("Paquets/message_2_sens.pcapng")
Cap4 = ps.FileCapture("Paquets/message_vocal.pcapng")
Cap5 = ps.FileCapture("Paquets/appel.pcapng")

def analyses(Cap):
    echangeTCP = {}
    DmnNameDNs = {}
    TypeRequestDNS = {}
    countVersionIP = {}
    countTCP = 0
    countTLS = 0
    countUDP = 0
    countDNS = 0
    countsll = 0
    count = 0
    countIPV6 = 0
    destIP = {}
    destIPv6 = {}
    versTLS = []
    for pkt in Cap:
        count += 1
        if "tcp" in pkt:
            echangeTCP[(pkt.tcp.srcport, pkt.tcp.dstport)] = echangeTCP.get((pkt.tcp.srcport, pkt.tcp.dstport), 0) + 1
            countTCP += 1
        if "dns" in pkt: 
            countDNS += 1
            DmnNameDNs[pkt.dns.qry_name] = DmnNameDNs.get(pkt.dns.qry_name, 0) + 1
            TypeRequestDNS[pkt.dns.qry_type] = TypeRequestDNS.get(pkt.dns.qry_type, 0) + 1
            
            
            """
            if int(pkt.dns.count_add_rr) > 0:
                print(f"Paquet DNS avec {pkt.dns.count_add_rr} enregistrement(s) additionnel(s):")
                # Boucle sur les enregistrements additionnels
                for rr in pkt.dns.additionals:
                    # Récupération des champs de l'enregistrement DNS
                    name = rr.get('dns.resp_name')
                    rtype = rr.get('dns.resp_type')
                    rdata = rr.get('dns.resp_data')
                    print(f"    {name} {rtype} {rdata}")
    """

        if "ip" in pkt:
            vers = pkt.ip.version
            countVersionIP[vers] = countVersionIP.get(vers, 0) + 1
            dest = pkt.ip.dst
            destIP[dest] = destIP.get(dest, 0) + 1 
        if "ipv6" in pkt:
            countIPV6 +=1
            dest = pkt.ipv6.dst
            destIPv6[dest] = destIPv6.get(dest, 0) + 1 
        if "tls" in pkt:
            countTLS +=1
            #vers = pkt.tls.handshake_extensions_server_name
            #versTLS.append(vers) if vers not in versTLS else 0
            countUDP += 1
        
        if "sll" in pkt:
            countsll +=1
    
    return echangeTCP, DmnNameDNs, TypeRequestDNS, countVersionIP, countTCP, countTLS,countUDP ,countDNS,countsll ,count ,countIPV6, destIP, destIPv6, versTLS


print("ananlyse Demarrage ")

echangeTCP, DmnNameDNs, TypeRequestDNS, countVersionIP, countTCP, countTLS,countUDP ,countDNS,countsll ,count ,countIPV6, destIP, destIPv6, versTLS = analyses(Cap1)
print( str(count) + " paquets au total")
print("nombre de paquets TCP :" + str(countTCP))
print("liste des échange source destination differentes : " + str(echangeTCP)) # [443, 50308, 51648, 42092, 48968]

print("nombre de paquet dns : " + str(countDNS))
print( "nom de domaine DNS : " + str(DmnNameDNs))
print("type de requetes dns : " + str(TypeRequestDNS))
print("compte des differentes verions IP  " + str(countVersionIP))
print(str(countIPV6) + " acces IPV6")
print("destination des appels IP : "+str(destIP))
print("destination des appaels IPV6" + str(destIPv6))

print("nombre de paquets TLS : " + str(countTLS))
print("verion TLS : " + str(versTLS))
print("nombre de paquets UDP : " + str(countUDP))
print("nombre de paquets SLL : " + str(countsll))

print("\nanalyse message recu")
echangeTCP, DmnNameDNs2, TypeRequestDNS, countVersionIP, countTCP, countTLS,countUDP ,countDNS,countsll ,count ,countIPV6, destIP, destIPv6 , versTLS= analyses(Cap2)
print( str(count) + " paquets au total")
print("nombre de paquets TCP :" + str(countTCP))
print("liste des échange source destination differentes : " + str(echangeTCP)) # [443, 50308, 51648, 42092, 48968]

print("nombre de paquet dns : " + str(countDNS))
print( "nom de domaine DNS : " + str(DmnNameDNs2))
print("type de requetes dns : " + str(TypeRequestDNS))
print("compte des differentes verions IP  " + str(countVersionIP))
print(str(countIPV6) + " acces IPV6")
print("destination des appels IP : "+str(destIP))
print("destination des appaels IPV6" + str(destIPv6))
print("nombre de paquets TLS : " + str(countTLS))
print("verion TLS : " + str(versTLS))
print("nombre de paquets UDP : " + str(countUDP))
print("nombre de paquets SLL : " + str(countsll))

print("\nanalyse message 2 sens")
echangeTCP, DmnNameDNs3, TypeRequestDNS, countVersionIP, countTCP, countTLS,countUDP ,countDNS,countsll ,count ,countIPV6, destIP, destIPv6, versTLS = analyses(Cap3)
print( str(count) + " paquets au total")
print("nombre de paquets TCP :" + str(countTCP))
print("liste des échange source destination differentes : " + str(echangeTCP)) # [443, 50308, 51648, 42092, 48968]

print("nombre de paquet dns : " + str(countDNS))
print( "nom de domaine DNS : " + str(DmnNameDNs3))
print("type de requetes dns : " + str(TypeRequestDNS))
print("compte des differentes verions IP  " + str(countVersionIP))
print(str(countIPV6) + " acces IPV6")
print("destination des appels IP : "+str(destIP))
print("destination des appaels IPV6" + str(destIPv6))
print("nombre de paquets TLS : " + str(countTLS))
print("verion TLS : " + str(versTLS))
print("nombre de paquets UDP : " + str(countUDP))
print("nombre de paquets SLL : " + str(countsll))


print("\nanalyse message vocal")
echangeTCP, DmnNameDNs4, TypeRequestDNS, countVersionIP, countTCP, countTLS,countUDP ,countDNS,countsll ,count ,countIPV6, destIP, destIPv6, versTLS = analyses(Cap4)
print( str(count) + " paquets au total")
print("nombre de paquets TCP :" + str(countTCP))
print("liste des échange source destination differentes : " + str(echangeTCP)) # [443, 50308, 51648, 42092, 48968]

print("nombre de paquet dns : " + str(countDNS))
print( "nom de domaine DNS : " + str(DmnNameDNs4))
print("type de requetes dns : " + str(TypeRequestDNS))
print("compte des differentes verions IP  " + str(countVersionIP))
print(str(countIPV6) + " acces IPV6")
print("destination des appels IP : "+str(destIP))
print("destination des appaels IPV6" + str(destIPv6))
print("nombre de paquets TLS : " + str(countTLS))
print("verion TLS : " + str(versTLS))
print("nombre de paquets UDP : " + str(countUDP))
print("nombre de paquets SLL : " + str(countsll))



print("\nanalyse appel")
echangeTCP, DmnNameDNs5, TypeRequestDNS, countVersionIP, countTCP, countTLS,countUDP ,countDNS,countsll ,count ,countIPV6, destIP, destIPv6, versTLS = analyses(Cap5)
print( str(count) + " paquets au total")
print("nombre de paquets TCP :" + str(countTCP))
print("liste des échange source destination differentes : " + str(echangeTCP)) # [443, 50308, 51648, 42092, 48968]

print("nombre de paquet dns : " + str(countDNS))
print( "nom de domaine DNS : " + str(DmnNameDNs5))
print("type de requetes dns : " + str(TypeRequestDNS))
print("compte des differentes verions IP  " + str(countVersionIP))
print(str(countIPV6) + " acces IPV6")
print("destination des appels IP : "+str(destIP))
print("destination des appaels IPV6" + str(destIPv6))
print("nombre de paquets TLS : " + str(countTLS))
print("verion TLS : " + str(versTLS))

print("nombre de paquets UDP : " + str(countUDP))
print("nombre de paquets SLL : " + str(countsll))


"""
fig, ax = plt.subplots(1,1, layout = "constrained")
ax.set_ylabel("nombres de requêtes")
for keys in DmnNameDNs:
    ax.bar(keys, DmnNameDNs[keys])
    
for key in DmnNameDNs3:
    ax.bar(key, DmnNameDNs3[key])

for keys in DmnNameDNs4:
    ax.bar(keys, DmnNameDNs4[keys])
    
for key in DmnNameDNs5:
    ax.bar(key, DmnNameDNs5[key])

labels=['chat.signal.org','storage.signal.org','cdn2.signal.org','cdn.signal.org','turn3.voip.signal.org','ipv6.turn3.voip.signal.org','connectivity-check.ubuntu.com']

ax.set_xticklabels(labels,rotation=45)

fig.savefig("dnsdomain.pdf")
plt.show()


field_names
srcport

field DNS
['id', 'flags', 'flags_response', 'flags_opcode', 'flags_truncated', 'flags_recdesired', 
'flags_z', 'flags_authenticated', 'flags_checkdisable', 'count_queries', 'count_answers', 
'count_auth_rr', 'count_add_rr', '', 'qry_name', 'qry_name_len', 'count_labels', 'qry_type', 
'qry_class', 'resp_name', 'resp_type', 'rr_udp_payload_size', 'resp_ext_rcode', 'resp_edns0_version', '
resp_z', 'resp_z_do', 'resp_z_reserved', 'resp_len']

['id', 'flags', 'flags_response', 'flags_opcode', 'flags_authoritative', 'flags_truncated', 'flags_recdesired', 
'flags_recavail', 'flags_z', 'flags_authenticated', 'flags_checkdisable', 'flags_rcode', 'count_queries', 'count_answers', 
'count_auth_rr', 'count_add_rr', '', 'qry_name', 'qry_name_len', 'count_labels', 'qry_type', 'qry_class', 'resp_name', 'resp_type', 
'resp_class', 'resp_ttl', 'resp_len', 'cname', 
'a', 'rr_udp_payload_size', 'resp_ext_rcode', 'resp_edns0_version', 'resp_z', 'resp_z_do', 'resp_z_reserved', 'response_to', 'time']

field TCP
['srcport', 'dstport', 'port', 'stream', 'completeness', 'len', 'seq', 'seq_raw', 'nxtseq', 'ack', 
'ack_raw', 'hdr_len', 'flags', 'flags_res', 'flags_ae', 'flags_cwr', 'flags_ece', 'flags_urg', 'flags_ack', 
'flags_push', 'flags_reset', 'flags_syn', '_ws_expert', 'connection_syn', '_ws_expert_message', '_ws_expert_severity', 
'_ws_expert_group', 'flags_fin', 'flags_str', 'window_size_value', 'window_size', 'checksum', 'checksum_status', 'urgent_pointer', 
'options', 'options_mss', 'option_kind', 'option_len', 'options_mss_val', 'options_sack_perm', 'options_timestamp', 'options_timestamp_tsval', 
'options_timestamp_tsecr', 'options_nop', 'options_wscale', 'options_wscale_shift', 'options_wscale_multiplier', '', 'time_relative', 'time_delta']

field IP
['version', 'hdr_len', 'dsfield', 'dsfield_dscp', 'dsfield_ecn', 'len', 'id', 'flags', 'flags_rb', 'flags_df', 'flags_mf', 'frag_offset', 'ttl', 'proto', 
'checksum', 'checksum_status', 'src', 'addr', 'src_host', 'host', 'dst', 'dst_host']

field IPV6
['version', 'ip_version', 'tclass', 'tclass_dscp', 'tclass_ecn', 'flow', 'plen', 'nxt', 'hlim', 'src', 'addr', 'src_host', 'host', 'dst', 'dst_host']


field tls
['record', 'record_content_type', 'record_version', 'record_length', 'handshake', 'handshake_type', 'handshake_length', 'handshake_version', 'handshake_random', 
'handshake_random_time', 'handshake_random_bytes', 'handshake_session_id_length', 'handshake_session_id', 'handshake_cipher_suites_length', 'handshake_ciphersuites', 
'handshake_ciphersuite', 'handshake_comp_methods_length', 'handshake_comp_methods', 'handshake_comp_method', 'handshake_extensions_length', '', 'handshake_extension_type', 
'handshake_extension_len', 'handshake_extensions_server_name_list_len', 'handshake_extensions_server_name_type', 'handshake_extensions_server_name_len', 
'handshake_extensions_server_name', 'handshake_extensions_reneg_info_len', 'handshake_extensions_supported_groups_length', 'handshake_extensions_supported_groups', 
'handshake_extensions_supported_group', 'handshake_extensions_ec_point_formats_length', 'handshake_extensions_ec_point_formats', 'handshake_extensions_ec_point_format', 
handshake_extension_data', 'handshake_sig_hash_alg_len', 'handshake_sig_hash_algs', 'handshake_sig_hash_alg', 'handshake_sig_hash_hash', 'handshake_sig_hash_sig', 
'handshake_extensions_key_share_client_length', 'handshake_extensions_key_share_group', 'handshake_extensions_key_share_key_exchange_length', 
'handshake_extensions_key_share_key_exchange', 'extension_psk_ke_modes_length', 'extension_psk_ke_mode', 'handshake_extensions_supported_versions_len', 
'handshake_extensions_supported_version', 'handshake_ja3_full', 'handshake_ja3']

"""
