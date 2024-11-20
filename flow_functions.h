/*
    [ISA project] - PCAP NetFlow v5 exporter (p2nprobe)
    Date: 18.11.2024

    Author: Tomáš Bordák [xborda01]
*/

#ifndef FLOW_FUNCTIONS_H
#include <stdbool.h>
#include "structures.h"

/*
    takes a packet and creates new flow out of the packet data

    reallocates space for more flows if needed
 */
void addFlow(packet_t packet);

/*
    takes packet data and updates existing flow (bytes count and timestamp)
*/
void updateFlow(packet_t packet, flow_t *existingFlow);

/*
    takes current packet and from its timestamp

    calculates active timeout and inactive timeout for every flow

    if flow is expired -> moves it to the export array
*/
void checkTimeouts(packet_t packet);

/*
    returns true if packet should be added to existing flow
    returns false otherwise
*/
bool flowMatchPacket(flow_t *existingFlow, packet_t *packet);

/*
    // THIS FUNCTION IS INSPIRED FROM SOFTFLOWD SOURCE CODE (softflowd/softflowd.c - timeval_sub_ms() line 686 [16.11.2024])
    // https://github.com/irino/softflowd/blob/master/softflowd.c

    (c) 2002 Damien Miller

    function for substracting 2 struct timeval variables:

    sysUptime in NetFlow header
    First and Last in NetFlow flow record
*/
/*
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
uint32_t timeDiff(const struct timeval *one, const struct timeval *two);

#endif