#include "flow_functions.h"

/* void addFlow(flow_t packetInfo, flow_t *allFlowsArray, int *allFlowsArrayLength)
{
    // take first empty place in allFlowsArray
    flow_t *newFlow = &allFlowsArray[*allFlowsArrayLength];

    memcpy(newFlow, &packetInfo, sizeof(flow_t));

    // increment length, bcs we added newFlow
    (*allFlowsArrayLength)++;
}

void updateFlow(flow_t packetInfo, flow_t *existingFlow)
{
    existingFlow->bytesCount += packetInfo.bytesCount;
    existingFlow->packetCount++;
}

void exportFlows(flow_t *allFlowsArray, int *allFlowsArrayLength)
{
    printf("Exporting %d flows:\n", allFlowsArrayLength);
    for (int i = 0; i < allFlowsArrayLength; i++)
    {
        flow_t *flow = &allFlowsArray[i];

        printf("Flow %d: %s:%d -> %s:%d, packets: %u, bytes: %u\n",
               i + 1,
               flow->srcIP,
               flow->srcPORT,
               flow->destIP,
               flow->destPORT,
               flow->packetCount,
               flow->bytesCount);
    }

    *allFlowsArrayLength = 0;
}
 */
