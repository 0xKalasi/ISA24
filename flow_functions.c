#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flow_functions.h"
#include "export_functions.h"

extern flow_t *flows;
extern int flowsLength;
extern config_t config;

void addFlow(packet_t packet)
{

    // reallocating flow_t * 30 everytime flowLength is 30 / 60 / 90 etc.
    if (flowsLength % 30 == 0)
    {
        flows = realloc(flows, (flowsLength + 30) * sizeof(flow_t));

        if (!flows)
        {
            fprintf(stderr, "Error: memory reallocation failed. Function addFlow.\n");
            exit(1);
        }
    }

    flows[flowsLength] = (flow_t){
        .srcPORT = packet.srcPORT,
        .destPORT = packet.destPORT,
        .bytesCount = packet.bytes,
        .packetCount = 1,
        .first = packet.timestamp,
        .last = packet.timestamp};

    strcpy(flows[flowsLength].srcIP, packet.srcIP);
    strcpy(flows[flowsLength].destIP, packet.destIP);

    // increment length, bcs we added new flow
    flowsLength++;
}

void updateFlow(packet_t packet, flow_t *existingFlow)
{
    existingFlow->bytesCount += packet.bytes;
    existingFlow->packetCount++;
    existingFlow->last = packet.timestamp;
}

// check active and inactive timeout
// move flow to export if atleast one of the timeouts got triggered
void checkTimeouts(packet_t packet)
{
    for (int i = 0; i < flowsLength; i++)
    {
        flow_t *flow = &flows[i];

        // active timeout
        // (current - first) >= activeTimeout
        uint32_t active = packet.timestamp.tv_sec - flow->first.tv_sec;

        // inactive timeout
        // (current - last) >= inactiveTimeout
        uint32_t inactive = packet.timestamp.tv_sec - flow->last.tv_sec;

        if (active >= (uint32_t)config.activeTimeout || inactive >= (uint32_t)config.inactiveTimeout)
            moveToExport(i);
    }
}

bool flowMatchPacket(flow_t *existingFlow, packet_t *packet)
{
    return (strcmp(existingFlow->srcIP, packet->srcIP) == 0 && strcmp(existingFlow->destIP, packet->destIP) == 0 && existingFlow->srcPORT == packet->srcPORT && existingFlow->destPORT == packet->destPORT);
}

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
// THIS FUNCTION IS INSPIRED FROM SOFTFLOWD SOURCE CODE (softflowd/softflowd.c - timeval_sub_ms() line 686 [16.11.2024])
// https://github.com/irino/softflowd/blob/master/softflowd.c
uint32_t timeDiff(const struct timeval *one, const struct timeval *two)
{
    struct timeval result;
    result.tv_sec = one->tv_sec - two->tv_sec;
    result.tv_usec = one->tv_usec - two->tv_usec;

    if (result.tv_usec < 0)
    {
        result.tv_usec += 1000000L;
        result.tv_sec--;
    }

    return ((uint32_t)result.tv_sec * 1000 + (uint32_t)result.tv_usec / 1000);
}
