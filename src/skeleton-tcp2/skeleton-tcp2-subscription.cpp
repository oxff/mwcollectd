/*
 * TCP Client Skeleton Module
 * A more or less well commented example how to connect to a host and work on the data via a subscription.
 *
 * $Id: skeleton-tcp2-subscription.cpp 102 2005-09-23 17:14:04Z oxff $
 *
 */
 
#include "skeleton-tcp2.h"

void SkeletonSubscription::incomingData(unsigned char * pucData, unsigned int nLength)
{
	g_pLogManager->log(LT_LEVEL_LOW | LT_DEBUG, "We've got %u bytes of data, joe!", nLength);
}

void SkeletonSubscription::connectionEtablished()
{
	g_pLogManager->log(LT_LEVEL_LOW | LT_DEBUG, "Skeleton connected!");
	
	m_pSocket->sendData((unsigned char *) "Hello!\n", 7);
}

void SkeletonSubscription::connectionClosed()
{
	g_pLogManager->log(LT_LEVEL_LOW | LT_DEBUG, "The skeleton died much more deadly.");
}

ConsumptionLevel SkeletonSubscription::consumptionLevel()
{
	return CL_OVERTAKE; // for self etablished connections, this is always the only senseful thing
}
