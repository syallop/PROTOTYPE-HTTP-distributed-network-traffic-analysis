function showUnrecognisedByServer() {
    return 'Unrecognised by server';
}

function showUnrecognisedByClient() {
    return 'Unrecognised by client';
}

//Return a string representing a complete set of packets
function showJsonPackets(packets) {
    var output;
    $.each(packets, function(i,packet){output+='<br>'+showJsonPacket(packet);});
    return output;
}

//Return a string representing a complete packet
function showJsonPacket(packet) {
    var output =  'PCAP. Number: '+packet.number
                 +' Size: '+packet.size
                 +' Seconds: '+packet.seconds+'.'+packet.useconds
                 +'</br>'
                 + showJsonDatalink(packet.datalink);
    return output;
}

//Return a string representing a datalink level packet
function showJsonDatalink(datalink) {
    var output = 'Datalink. ';
    switch (datalink.type) {
        case    'ethernet': output+=showJsonEthernet(datalink); break;
        case    'UNKNOWN' : output+=showUnrecognisedByServer;   break;
        default           : output+=showUnrecognisedByClient;   break;
    }
    return output;
};

//Return a string representing a network level packet
function showJsonNetwork(network) {
    var output = 'Network. ';
    switch (network.type) {
        case    'IP'     : output+=showJsonIP(network);      break;
        case    'IPv6'   : output+=showJsonIPv6(network);    break;
        case    'UNKNOWN': output+=showUnrecognisedByServer; break;
        default:           output+=showUnrecognisedByClient; break;
    }
    return output;
}

//Return a string representing a transport level packet
function showJsonTransport(transport) {
    var output = 'Transport. ';
    switch (transport.type) {
        case    'TCP'    : output+=showJsonTCP(transport);   break;
        case    'UDP'    : output+=showJsonUDP(transport);   break;
        case    'UNKNOWN': output+=showUnrecognisedByServer; break;
        default          : output+=showUnrecognisedByClient; break
    }
    return output;
}


/*Datalink layer parsers******************************************************/

//Return a string representing an ethernet packet
function showJsonEthernet(ethernet) {
    var output =  'Ethernet '
                 +'Src: '+ethernet.macSrc
                 +' Dst: '+ethernet.dst
                 +'<br>'
                 + showJsonNetwork(ethernet.network);
    return output;
}
/*****************************************************************************/

/*Network layer parsers*******************************************************/

//Return a string representing a ip packet
function showJsonIP(ip) {
    var output =  'IP '
                 +'Src: '+ip.ipSrc
                 +' Dst: '+ip.ipDst
                 +'<br>'
                 + showJsonTransport(ip.transport);
    return output;
}

//Return a string representing an ipv6 packet
function showJsonIPv6(ipv6) {
    var output = 'IPv6'
                 +'<br>';
    return output;
}

/*****************************************************************************/


/*Transport layer parsers*****************************************************/

//Return a string representing a TCP packet
function showJsonTCP(tcp) {
    var output =  'TCP '
                 +'Src: ' +tcp.srcPort
                 +' Dst: '+tcp.dstPort
                 +'<br>';
    return output;
}

//Return a string representing a UDP packet
function showJsonUDP(udp) {
    var output =  'UDP '
                 +'Src: ' +udp.srcPort
                 +' Dst: '+udp.dstPort
                 +'<br>';
    return output;
}


/*****************************************************************************/
