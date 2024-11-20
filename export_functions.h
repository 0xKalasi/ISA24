/*
    [ISA project] - PCAP NetFlow v5 exporter (p2nprobe)
    Date: 18.11.2024

    Author: Tomáš Bordák [xborda01]
*/

#ifndef PCAP_FUNCTIONS_H

/*
    exports NetFlow flow records to collector
    flows for export have to be in flowsToExport array

    sets NetFlows packet header and payload, then sends it via UDP to collector
*/
void exportFlows();

/*
    move flows that expired to flowsToExport array

    also watches for overflow, so if there already is 30 flows to export, it calls exportFlows()

    PARAM: index of flow which expired from flows array
*/
void moveToExport(int index);

/*
    this function gets called after pcap_loop() finished

    uses moveToExport to move all flows that didnt expired yet and then exports them with exportFlows()
 */
void exportRemaining();

/*
    resolves hostname to IPv4 address if needed

    creates a socket for IPv4 UDP
 */
void initCollector();

#endif