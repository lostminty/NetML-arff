'''
Utilities for preparing sessions for input into models
'''
import os
from collections import Counter
from collections import defaultdict
from collections import OrderedDict

import numpy as np


def is_private(address):
    '''
    Checks if an address is private and if so returns True.  Otherwise returns
    False.
    Args:
        address: Address to check. Can be list or string
    Returns:
        True or False
    '''
    if '.' in address:  # ipv4
        pairs = address.split('.')
    elif ':' in address:  # ipv6
        pairs = address.split(':')
    else:  # unknown
        pairs = []

    private = False
    if pairs:
        if pairs[0] == '10':
            private = True
        elif pairs[0] == '192' and pairs[1] == '168':
            private = True
        elif pairs[0] == '172' and 16 <= int(pairs[1]) <= 31:
            private = True
        elif pairs[0] == 'fe80':
            private = True
        elif pairs[0].startswith('fd'):
            private = True

    return private


def extract_macs(packet):
    '''
    Takes in hex representation of a packet header and extracts the
    source and destination mac addresses

    returns:
        source_mac: Destination MAC address
        destination_mac: Destination MAC address
    '''

    source_mac = packet[1]
    dest_mac = packet[0]

    return source_mac, dest_mac


def get_indiv_source(sessions, address_type='MAC'):
    '''
    Gets the source MAC address from an individual session dictionary.
    Also computes the number of sessions to and from this source.
    The source is defined to be the IP address with the most sessions
    associated with it.

    Inputs:
        sessions: A dictionary of hex sessions from the sessionizer
        address_type: Type of address to report as the source
    Returns:
        capture_source: Address of the capture source
        ip_mac_pairs: Counts of appearances of ip:mac pairs
    '''
   
    # Number of sessions involving the address
    ip_mac_pairs = defaultdict(int)

    # Count the incoming/outgoing sessions for all addresses
    for key in sessions:
        
        source_address, _ = get_ip_port(key[0])
        destination_address, _ = get_ip_port(key[1])

        # Get the first packet and grab the macs from it
        first_packet = sessions[key][1]
        
        source_mac, destination_mac = extract_macs(first_packet)
#        print(source_mac+ " " + destination_mac)
        # Compute the IP/MAC address pairs
        if os.environ.get('POSEIDON_PUBLIC_SESSIONS'):
            pair_1 = source_address + '-' + source_mac
            pair_2 = destination_address + '-' + destination_mac
            ip_mac_pairs[pair_1] += 1
            ip_mac_pairs[pair_2] += 1
        else:
            # Only look at sessions with an internal IP address
            # This shouldn't actually be necessary at this stage
            if is_private(source_address) or is_private(destination_address):
                pair_1 = source_address + '-' + source_mac
                pair_2 = destination_address + '-' + destination_mac
                if is_private(source_address):
                    ip_mac_pairs[pair_1] += 1
                if is_private(destination_address):
                    ip_mac_pairs[pair_2] += 1

    # The address with the most sessions is the capture source
    if len(sessions) == 0:
        return None, ip_mac_pairs

    sorted_sources = sorted(
        ip_mac_pairs.keys(),
        key=(lambda k: ip_mac_pairs[k]),
        reverse=True
    )
  #  print(sorted_sources)
 #   input()
    if address_type == 'MAC':
        capture_source = '00:00:00:00:00:00'
    else:
        capture_source = '0.0.0.0'

    if len(sorted_sources) > 0:
        if address_type == 'MAC':
            capture_source = sorted_sources[0].split('-')[1]
        else:
            capture_source = sorted_sources[0].split('-')[0]

    return capture_source, ip_mac_pairs


def get_source(sessions, address_type='MAC'):
    '''
    Gets the source MAC for all the session dicts given.  This is the majority
    vote across all session dicts if sessions is a list.

    Args:
        sessions: either a single session dict or a list of session dicts
        address_type: Type of address to return as source identifer
    Returns
        capture_source: Majority MAC address across all sessions in input
    '''
    c= Counter([])
    if address_type=='MAC':
#    print(sessions)
      if isinstance(sessions,list):
        for item in sessions:
      # print(type(item))
         for key,data in item.items():
#      print(type(key))
#      print(len(data))#
#      print(data)
#    input()
           c.update({data[1][0]:1})
           c.update({data[1][1]:1})
      else:
        for key,data  in sessions.items():
           c.update({data[1][0]:1})
           c.update({data[1][1]:1})
    else:
      if isinstance(sessions,list):
        for item in sessions:
      # print(type(item))
         for key,data in item.items():
#      print(type(key))
#      print(len(data))#
#      print(data)
#    input()
           c.update({data[1][2]:1})
           c.update({data[1][3]:1})
      else:
        for key,data  in sessions.items():
           c.update({data[1][2]:1})
           c.update({data[1][3]:1})


    best=c.most_common(1)[0][0] if c else None
    print(c)
    return best

def packet_size(packet):
    '''
    Extracts the size of a packet in bytes from the hex header.

    Args:
        packet: Hex header of the packet

    Returns:
        size: Size in bytes of the IP packet, including data
    '''

    size = packet[1][32:36]
    try:
        size = int(size, 16)
    except ValueError:  # pragma: no cover
        size = 0
    return size


def extract_session_size(session):
    '''
    Extracts the total size of a session in bytes.

    Args:
        session: session list containing all the packets of the session

    Returns:
        session_size: Size of the session in bytes
    '''

    session_size = sum([packet_size(p) for p in session])
    return session_size


def extract_protocol(session):
    '''
    Extracts the protocol used in the session from the first packet

    Args:
        session: session tuple containing all the packets of the session

    Returns:
        protocol: Protocol number used in the session
    '''

    protocol = session[0][1][46:48]
    return protocol


def is_external(address_1, address_2):
    '''
    Checks if a session is between two sources within the same network.
    For now this is defined as two IPs with the first octet matching.

    Args:
        address_1: Address of source participant
        address_2: Address of destination participant

    Returns:
        is_external: True or False if this is an internal session
    '''

    if is_private(address_1) and is_private(address_2):
        return False

    return True


def is_protocol(session, protocol):
    '''
    Checks if a session is of the type specified

    Args:
        session: List of packets in the session
        protocol: Protocol to check

    Returns:
        is_protocol: True or False indicating if this is a TCP session
    '''
    
    p = int(session[7])
   # print(p+":"+protocol)
    if int(protocol) == p:
        return True
    return False


def strip_macs(packet):
    '''
    Strip the mac addresses out of a packet
    '''
    return packet[24:]


def strip_ips(stripped_packet):
    '''
    Strip the IP addresses out of a packet that has had its mac addresses
    stripped out
    '''
    return stripped_packet[0:28] + stripped_packet[44:]


def clean_packet(packet):
    '''
    Remove both mac and ip addresses from a packet
    '''
    no_macs = strip_macs(packet)
    no_ips = strip_ips(no_macs)
    return no_ips


def clean_session_dict(sessions, source_address=None):
    '''
    return sessions of packets with no mac or ip addresses from the source
    '''
    if source_address is None:
        source_address = get_source(sessions, address_type='IP')

    def clean_dict(sessions, source_address):
        cleaned_sessions = OrderedDict()
        for key, packets in sessions.items():
            # TODO: Removing port_1 and port_2 (i.e., returned val [1])
            # due to unuse, but I'm a little surprised we aren't using
            # this... O_o
            address_1 = get_ip_port(key[0])[0]
            address_2 = get_ip_port(key[1])[0]

            first_packet = sessions[key][0][1]
            source_mac, destination_mac = extract_macs(first_packet)

            if (address_1 == source_address
                or source_mac == source_address
                or address_2 == source_address
                    or destination_mac == source_address):
                if os.environ.get('POSEIDON_PUBLIC_SESSIONS'):
                    cleaned_sessions[key] = [
                        (ts, clean_packet(p))
                        for ts, p in packets[0:8]
                    ]
                else:
                    if is_private(address_1) or is_private(address_2):
                        cleaned_sessions[key] = [
                            (ts, clean_packet(p))
                            for ts, p in packets[0:8]
                        ]
        return cleaned_sessions

    if isinstance(sessions, list):
        cleaned_sessions = []
        for sess in sessions:
            cleaned_sessions.append(clean_dict(sess, source_address))
    else:
        cleaned_sessions = clean_dict(sessions, source_address)

    return cleaned_sessions, source_address


def get_length(packet):
    """
    Gets the total length of the packet
    """
    hex_str = '0123456789abcdef'
    hex_length = packet[32:36]
    length = 0
    for i, c in enumerate(hex_length[::-1]):
        length += pow(16, i)*hex_str.index(c)
    return length


def featurize_session(key, packets, source=None):

    mac_1, mac_2 = extract_macs(packets[1])
    protocol = extract_protocol(packets[1])
    packets=packets[1]
    address_1, _ = get_ip_port(key[0])
    address_2, _ = get_ip_port(key[1])
    external = is_external(address_1, address_2)
    if address_1 == source or address_2 == source or source == None:
         initiated_by_source = None
         if address_1 == source:
             initiated_by_source = True
         if address_2 == source:
             initiated_by_source = False
         external = is_external(address_1, address_2)
         time_elapsed = int(packets[28])
         if time_elapsed  == 0:
           time_elapsed = 1
         freq_1 =int(packets[8])/time_elapsed
         freq_2 =int(packets[10])/time_elapsed

        # Netflow-like session info
         session_info = {
            'start time': packets[29],
            'initiated by source': initiated_by_source,
            'external session': external,
            'source': key[0],
            'destination': key[1],
            'protocol': packets[6],
            'data to source': int(packets[11]),
            'data to destination': int(packets[9]),
            'packets to source': int(packets[10]),
            'packets to destination': int(packets[8]),
            'source frequency': freq_1,
            'destination frequency': freq_2,
         }
         return session_info
    else:
       return None

def get_ip_port(socket_str):
    """
    Returns ip and port
    :param socket_str: ipv4/6:port
    :return:
    address, port
    """
    splitter_index = socket_str.rindex(':')
    address = socket_str[0:splitter_index]
    port = socket_str[splitter_index + 1:]

    return address, port