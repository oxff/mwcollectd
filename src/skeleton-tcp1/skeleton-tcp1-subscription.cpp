/*
 * TCP Server Skeleton Module
 * A more or less well commented example how to subscribe to a certain port and accept traffic there.
 *
 * $Id: skeleton-tcp1-subscription.cpp 81 2005-08-28 16:51:43Z oxff $
 *
 */
 
#include "skeleton-tcp1.h"

void SkeletonSubscription::incomingData(unsigned char * pucData, unsigned int nLength)
{
	g_pLogManager->log(LT_LEVEL_LOW | LT_DEBUG, "We've got %u bytes of data, joe!", nLength);
	
	m_pSocket->sendData((unsigned char *) "yay\n", 4);
}

void SkeletonSubscription::connectionEtablished()
{
	g_pLogManager->log(LT_LEVEL_LOW | LT_DEBUG, "New skeleton connection!");
}

void SkeletonSubscription::connectionClosed()
{
	g_pLogManager->log(LT_LEVEL_LOW | LT_DEBUG, "The skeleton lost a bone.");
}

ConsumptionLevel SkeletonSubscription::consumptionLevel()
{
	if(rand() % 7)
		return CL_UNSURE;

	return CL_DROP;
}
