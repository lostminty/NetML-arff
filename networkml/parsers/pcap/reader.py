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
        packet_dict[head[1:]] = head[0],data,data[30]
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
    start_time = None
    working_dict = None

    first_packet_time = None
    session_starts = OrderedDict()

    if not threshold_time or threshold_time < 1:
        cfg_threshold = None
        threshold_time = cfg_threshold if cfg_threshold and cfg_threshold > 0 else 120

    for head, payload in packet_dict.items():
        time = payload[0]

        # Get the time of the first observed packet
        if first_packet_time is None:
            first_packet_time = time

        # Start off the first bin when the first packet is seen
        if start_time is None:
            start_time = time
            working_dict = OrderedDict()

        # If duration has been specified, check if a new bin should start
        if duration is not None:
            if (time-start_time).total_seconds() >= duration:
                sessions.append(working_dict)
                working_dict = OrderedDict()
                start_time = time


        # Add the session to the session dict if it's start time is after
        # the cutoff
        
        working_dict[head]=(payload[0], payload[1])

    if duration is not None and working_dict is not None:
        if len(working_dict) > 0:
            sessions.append(working_dict)
    if duration is None:
        sessions.append(working_dict)
    return sessions
