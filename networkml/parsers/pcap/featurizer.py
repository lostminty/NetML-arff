from collections import defaultdict

import numpy as np
<<<<<<< HEAD
from scipy import stats
=======
>>>>>>> parallel_sessionizer

from networkml.parsers.pcap.pcap_utils import extract_macs
from networkml.parsers.pcap.pcap_utils import get_ip_port
from networkml.parsers.pcap.pcap_utils import get_source
from networkml.parsers.pcap.pcap_utils import is_external
from networkml.parsers.pcap.pcap_utils import is_private
from networkml.parsers.pcap.pcap_utils import is_protocol


<<<<<<< HEAD
def extract_features(session_dict,lpi_data, capture_source=None, max_port=1024):
=======
def extract_features(session_dict, capture_source=None, max_port=1024):
>>>>>>> parallel_sessionizer
    '''
    Extracts netflow level features from packet capture.

    Args:
        pcap_path: path to the packet capture to process into features
        max_port:  Maximum port to get features on (default to reading config)

    Returns:
        feature_vector: Vector containing the featurized representation
                        of the input pcap.
    '''

    address_type = 'MAC'

    # If the capture source isn't specified, default to the most used address
    if capture_source is None:
        capture_source = get_source(session_dict, address_type=address_type)
    capture_ip_source = get_source(session_dict, address_type='IP')

    # Initialize some counter variables
    num_sport_init = [0]*max_port
    num_dport_init = [0]*max_port
    num_sport_rec = [0]*max_port
    num_dport_rec = [0]*max_port
<<<<<<< HEAD
#    lpi_stats_source_init =[list()]*21
    lpi_stats_src = [[list()]*21]*max_port
    lpi_stats_dest = [[list()]*21]*max_port
    lpi_stats_extras = [list()]*21
    protocols = [0]*537
=======

>>>>>>> parallel_sessionizer
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

    # Iterate over all sessions and aggregate the info
    other_ips = defaultdict(int)
    for key, session in session_dict.items():
        address_1, port_1 = get_ip_port(key[0])
        address_2, port_2 = get_ip_port(key[1])

        # Get the first packet and grab the macs from it
        first_packet = session[0][1]
        source_mac, destination_mac = extract_macs(first_packet)

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

<<<<<<< HEAD

    src_bool = False
    dst_bool = False
    for data in lpi_data:
#      print(data)
      protocols[int(data[6])]+=1 
#      print(capture_source + " "+ data[0])
      if data[0] == capture_source and int(data[4]) < max_port or int(data[5]) < max_port:
#         src_bool = True
         [x.append(int(y)) for x,y in zip(lpi_stats_src[int(data[4])],data[8:29])]
      elif int(data[5]) < max_port or int(data[4]) < max_port:
#         dst_bool = True
         [x.append(int(y)) for x,y in zip(lpi_stats_dest[int(data[5])],data[8:29])]
      else:
         [x.append(int(y)) for x,y in zip(lpi_stats_extras,data[8:29])]


#    print(lpi_stats_src)
    mega_stats = [0]*(21*2*max_port+21*6)
    pos = 0
    empty_set = [0]*21
    for stat_bank_src,stat_bank_dest in zip(lpi_stats_src,lpi_stats_dest):
       
       if len(stat_bank_src[0])>1:
          #desc_src = stats.describe(lpi_stats_src,axis=1)
          try:
            l =np.median(stat_bank_src,axis = 1)
          except:
            l =np.array(empty_set)
          mega_stats[pos:(pos+21)]=l.tolist()
       else:
          mega_stats[pos:(pos+21)]=empty_set
       if len(stat_bank_dest[0])>1:
          try:
            l =np.median(stat_bank_src,axis = 1)
          except:
            l = np.array(empty_set)
          mega_stats[2*pos:2*pos+21]=l.tolist()
       else:
          mega_stats[2*pos:2*pos+21]=empty_set
       pos+=1

    if len(lpi_stats_extras[0]) >1:
      try:
         desc_extra = stats.median(lpi_stats_extras,axis=1)
      except:
         desc_extra = [0]*21*6
#      src_stdesc_extra.minmax[0],desc_extra.minmax[1],desc_extra.mean,desc_extra.variance,desc_extra.skewness,desc_extra.kurtosisats = np.concatenate((desc_extra.minmax[0],desc_extra.minmax[1],desc_extra.mean,desc_extra.variance,desc_extra.skewness,desc_extra.kurtosis),axis=0).tolist()
      l = np.concatenate((desc_extra.minmax[0],desc_extra.minmax[1],desc_extra.mean,desc_extra.variance,desc_extra.skewness,desc_extra.kurtosis),axis=0)
      mega_stats[21*2*max_port:]=l.tolist()
    else:
      mega_stats[21*2*max_port:]=[0]*21*6



    protocols=np.asarray(protocols) / len(lpi_data)
    
=======
>>>>>>> parallel_sessionizer
    extra_features = [0]*8
    extra_features[0] = num_external_init/num_sessions_init
    extra_features[1] = num_tcp_sess_init/num_sessions_init
    extra_features[2] = num_udp_sess_init/num_sessions_init
    extra_features[3] = num_icmp_sess_init/num_sessions_init

    extra_features[4] = num_external_rec/num_sessions_rec
    extra_features[5] = num_tcp_sess_rec/num_sessions_rec
    extra_features[6] = num_udp_sess_rec/num_sessions_rec
    extra_features[7] = num_icmp_sess_rec/num_sessions_rec

<<<<<<< HEAD
    feature_vector = np.concatenate((num_port_sess,extra_features,protocols,mega_stats), axis = 0)
#    print(feature_vector.shape)
#    feature_vector = np.concatenate((num_port_sess,extra_features,protocols,arff_stats_src.minmax[0],arff_stats_src.minmax[1],arff_stats_src.mean,arff_stats_src.variance,arff_stats_src.skewness,arff_stats_src.kurtosis,arff_stats_dest.minmax[0],arff_stats_dest.minmax[1],arff_stats_dest.mean,arff_stats_dest.variance,arff_stats_dest.skewness,arff_stats_dest.kurtosis), axis = 0)
=======
    feature_vector = np.concatenate((num_port_sess, extra_features), axis=0)
>>>>>>> parallel_sessionizer
    return feature_vector, capture_source, list(other_ips.keys()), capture_ip_source
