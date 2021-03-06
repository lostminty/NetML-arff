from collections import defaultdict

import numpy as np
import json
from networkml.parsers.pcap.pcap_utils import extract_macs
from networkml.parsers.pcap.pcap_utils import get_ip_port
from networkml.parsers.pcap.pcap_utils import get_source
from networkml.parsers.pcap.pcap_utils import is_external
from networkml.parsers.pcap.pcap_utils import is_private
from networkml.parsers.pcap.pcap_utils import is_protocol


def extract_features(session_dict, capture_source=None, max_port=1024):
    '''
    Extracts netflow level features from packet capture.

    Args:
        pcap_path: path to the packet capture to process into features
        max_port:  Maximum port to get features on (default to reading config)

    Returns:
        feature_vector: Vector containing the featurized representation
                        of the input pcap.
    '''
#    print(session_dict)
    address_type = 'MAC'
    print(capture_source)

    #capture_source_string = get_source(session_dict, address_type=address_type)
    if capture_source is None:
        capture_source = get_source(session_dict, address_type=address_type)
        #print("!")
    capture_ip_source = get_source(session_dict, address_type='IP')

#    print(capture_source+ " : "+capture_ip_source)
    # Initialize some counter variables
    num_sport_init = [0]*max_port
    num_dport_init = [0]*max_port
    num_sport_rec = [0]*max_port
    num_dport_rec = [0]*max_port
    protocols = [0]*537

    num_sessions_init = 0
    num_external_init = 0
    num_tcp_sess_init = 0
    num_udp_sess_init = 0
    num_icmp_sess_init = 0

    num_sessions_rec = 0
    num_external_rec = 0
    num_tcp_sess_rec = 0
    num_udp_sess_rec = 0
    num_icmp_sess_rec = 0
    stats_median =[list()]*21
    stats_mean=[0.0]*21
    # Iterate over all sessions and aggregate the info
    other_ips = defaultdict(int)
    for key, session in session_dict.items():
        
        session = session[1]
        address_1, port_1 = get_ip_port(key[0])
        address_2, port_2 = get_ip_port(key[1])
#        print(tr(session)+ " ! ")
        [x.append(int(y)) for x,y in zip(stats_median,session[8:29])]
        [x+float(y) for x,y in zip(stats_mean,session[8:29])]
        # Get the first packet and grab the macs from it
        #sum_packets_size_sent += int(session[10])
        
       # sum_packets_size_recv += int(session[11])
        source_mac, destination_mac = session[0],session[1]
#        print(source_mac)
      #  print(sousession[0][1]rce_mac+","+destination_mac+ "  :  " + capture_source)

        protocols[int(session[6])] += 1
        # If the source is the cpature source
        if (source_mac == capture_source
                or address_1 == capture_source):

            if is_private(address_2):
                other_ips[address_2] += 1

            num_sessions_init += 1
            num_external_init += is_external(address_1, address_2)
            num_tcp_sess_init += is_protocol(session, '06')
            num_udp_sess_init += is_protocol(session, '11')
            num_icmp_sess_init += is_protocol(session, '01')
            if int(port_1) < max_port:
                num_sport_init[int(port_1)] += 1

            if int(port_2) < max_port:
                num_dport_init[int(port_2)] += 1

        # If the destination is the capture source
        if (destination_mac == capture_source
                or address_2 == capture_source):
            if is_private(address_1):
                other_ips[address_1] += 1

            num_sessions_rec += 1
            num_external_rec += is_external(address_2, address_1)
            num_tcp_sess_rec += is_protocol(session, '06')
            num_udp_sess_rec += is_protocol(session, '11')
            num_icmp_sess_rec += is_protocol(session, '01')

            if int(port_1) < max_port:
                num_sport_rec[int(port_1)] += 1
            if int(port_2) < max_port:
                num_dport_rec[int(port_2)] += 1

    num_port_sess = np.concatenate(
        (
            num_sport_init,
            num_dport_init,
            num_sport_rec,
            num_dport_rec
        ),
        axis=0
    )

    
    if num_sessions_init == 0:
        num_sessions_init += 1
    if num_sessions_rec == 0:
        num_sessions_rec += 1

    num_port_sess = np.asarray(num_port_sess) / \
        (num_sessions_init+num_sessions_rec)
    
  #  with open("/home/bccc1/output.json", 'a+') as output_file:
   #         json.dump(num_port_sess.tolist(), output_file)
    protocols = np.asarray(protocols) / (num_sessions_init+num_sessions_rec)
    stats_mean = np.asarray(stats_mean) / (num_sessions_init+num_sessions_rec)
    stats_med = []
    for lst in stats_median:
      lst.sort()
      stats_med.append(lst[int(len(lst)/2)])

    # print(num_port_sess)
    extra_features = [0]*8
    extra_features[0] = num_external_init/num_sessions_init
    extra_features[1] = num_tcp_sess_init/num_sessions_init
    extra_features[2] = num_udp_sess_init/num_sessions_init
    extra_features[3] = num_icmp_sess_init/num_sessions_init

    extra_features[4] = num_external_rec/num_sessions_rec
    extra_features[5] = num_tcp_sess_rec/num_sessions_rec
    extra_features[6] = num_udp_sess_rec/num_sessions_rec
    extra_features[7] = num_icmp_sess_rec/num_sessions_rec
#    extra_features[8] = sum_packets_size_sent / (num_sessions_init+num_sessions_rec)
#    extra_features[9] = sum_packets_size_recv / (num_sessions_init+num_sessions_rec)
    feature_vector = np.concatenate((num_port_sess,extra_features), axis=0)
    return feature_vector, capture_source, list(other_ips.keys()), capture_ip_source
