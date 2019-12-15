from datetime import datetime
import os
import subprocess
from collections import OrderedDict


def parse_packet_head(data):
   source_str = data[2]+":"+data[4]
   destination_str = data[3]+":"+data[5]
   date = datetime.fromtimestamp(float(data[29]))
   return date,source_str, destination_str


def parse_packet_data(line):
    '''
    Parses the hex data from a line in the packet and returns it as a
    string of characters in 0123456789abcdef.

    Args:
        line: Hex output from tcpdump

    Returns:
        packet_data: String containing the packet data
    '''
    raw_data = line.decode('utf-8')
    try:
        _, data = raw_data.split(':', 1)
    except ValueError:  # pragma: no cover
        return None
    packet_data = data.strip().replace(' ', '')

    return packet_data


def packetizer(path):
    '''
    Reads a pcap specified by the path and parses out the packets.
    Packets will be stored with a tuple key formatted as follows:
    (datetime, sIP:sPort, dIP:dPort, protocol, length)

    Args:
        path: Path to pcap to read

    Returns:
        packet_dict: Dictionary of packets with keys formatted as above
    '''

    # Read get the pcap info with tcpdump
    FNULL = open(os.devnull, 'w')
    # TODO: yikes @ the shell=True + unvalidated user input
    proc = subprocess.Popen(
        '$LPI_PATH ' + path,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=FNULL
    )
    head = None
    packet_dict = OrderedDict()
    # Go through all the lines of the output
    for line in proc.stdout:
        data = line.decode('utf-8').split(",")
#        print(data)
        head = parse_packet_head(data)
        packet_dict[head[1:]] = head[0],data
    return packet_dict


def sessionizer(path, duration=None, threshold_time=None):
    '''
    Reads a pcap specified by the path and parses out the sessions.
    Sessions are defined as flows with matching sourceIP:sourcePort
    and destinationIP:destinationPorts. The sessions can also be binned
    in time according to the optional duration parameter.

    Args:
        path: Path to pcap to read
        duration: Duration of session bins. None uses a single bin for
                  the entire pcap.

    Returns:
        session_dict: Dictionary of sessions with keys as tuples of
                      (sourceIP:sourcePort, destIP:destPort)
    '''

    # Get the packets from the pcap
    packet_dict = packetizer(path)

    # Go through the packets one by one and add them to the session dict
    sessions = []



    sessions.append(packet_dict)
    return sessions
