/*
 * UDP Pairing Skeleton Module
 * A more or less well commented example how to subscribe to a certain UDP port and get pairings.
 *
 * $Id: skeleton-udp-subscription.cpp 102 2005-09-23 17:14:04Z oxff $
 *
 */
 
#include "skeleton-udp.h"

void SkeletonSubscription::incomingData(unsigned char * pucData, unsigned int nLength)
{
	g_pLogManager->log(LT_LEVEL_LOW | LT_DEBUG, "We've got %u bytes of data, joe!", nLength);
	
	m_pSocket->sendData((unsigned char *) "yay\n", 4);
}

void SkeletonSubscription::connectionEtablished()
{
	g_pLogManager->log(LT_LEVEL_LOW | LT_DEBUG, "New skeleton pairing!");
}

void SkeletonSubscription::connectionClosed()
{
	g_pLogManager->log(LT_LEVEL_LOW | LT_DEBUG, "Skeleton pairing lost.");
}

ConsumptionLevel SkeletonSubscription::consumptionLevel()
{
	if(rand() % 7)
		return CL_UNSURE;

	return CL_DROP;
}
