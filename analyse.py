import pyshark as ps

Cap1 = ps.FileCapture("Paquets/demarrage_signal.pcapng")  # First Capture (4 messages send by CC)

echangeTCP = {}
countTCP = 0
countDNS = 0
for pkt in Cap1:
    if "tcp" in pkt:
        
        if (pkt.tcp.srcport, pkt.tcp.dstport) not in echangeTCP:
            echangeTCP[(pkt.tcp.srcport, pkt.tcp.dstport)] = 1
        else:
            echangeTCP[(pkt.tcp.srcport, pkt.tcp.dstport)] += 1
        countTCP += 1

        
    
    if "dns" in pkt: 
        countDNS += 1
    

print("nombre de paquets TCP :" + str(countTCP))
print("liste des échange source destination differentes : " + str(echangeTCP)) # [443, 50308, 51648, 42092, 48968]

print("nombre de paquet dns : " + str(countDNS))



"""
field_names
srcport

field DNS
['id', 'flags', 'flags_response', 'flags_opcode', 'flags_truncated', 'flags_recdesired', 
'flags_z', 'flags_authenticated', 'flags_checkdisable', 'count_queries', 'count_answers', 
'count_auth_rr', 'count_add_rr', '', 'qry_name', 'qry_name_len', 'count_labels', 'qry_type', 
'qry_class', 'resp_name', 'resp_type', 'rr_udp_payload_size', 'resp_ext_rcode', 'resp_edns0_version', '
resp_z', 'resp_z_do', 'resp_z_reserved', 'resp_len']


field TCP
['srcport', 'dstport', 'port', 'stream', 'completeness', 'len', 'seq', 'seq_raw', 'nxtseq', 'ack', 
'ack_raw', 'hdr_len', 'flags', 'flags_res', 'flags_ae', 'flags_cwr', 'flags_ece', 'flags_urg', 'flags_ack', 
'flags_push', 'flags_reset', 'flags_syn', '_ws_expert', 'connection_syn', '_ws_expert_message', '_ws_expert_severity', 
'_ws_expert_group', 'flags_fin', 'flags_str', 'window_size_value', 'window_size', 'checksum', 'checksum_status', 'urgent_pointer', 
'options', 'options_mss', 'option_kind', 'option_len', 'options_mss_val', 'options_sack_perm', 'options_timestamp', 'options_timestamp_tsval', 
'options_timestamp_tsecr', 'options_nop', 'options_wscale', 'options_wscale_shift', 'options_wscale_multiplier', '', 'time_relative', 'time_delta']
"""
