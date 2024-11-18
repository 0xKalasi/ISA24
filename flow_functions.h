#ifndef FLOW_FUNCTIONS_H
#include <stdbool.h>
#include "structures.h"

void addFlow(packet_t packet);
void updateFlow(packet_t packet, flow_t *existingFlow);
void checkTimeouts(packet_t packet);
bool flowMatchPacket(flow_t *existingFlow, packet_t *packet);
uint32_t timeDiff(const struct timeval *one, const struct timeval *two);

#endif