/*
 * TCP Client Skeleton Module
 * A more or less well commented example how to connect to a host and work on the data via a subscription.
 *
 * $Id: skeleton-tcp2.h 114 2005-09-24 16:29:50Z oxff $
 *
 */
 
#ifndef __MWCMOD_SKELETONTCP2_H
#define __MWCMOD_SKELETONTCP2_H

#include <mwcollect/core.h>

using namespace mwccore;


class SkeletonModule : public Module, NetworkSubscriptionFactory
{
public:
	SkeletonModule();
	~SkeletonModule();
	
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfiguration = pConfig; };
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; };
	
	virtual bool start();
	virtual void stop();
	
	virtual NetworkSubscription * createNetworkSubscription(Socket * pSocket);
	virtual void freeNetworkSubscription(NetworkSubscription * pSubscription);
	
protected:
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
};


class SkeletonSubscription : public NetworkSubscription
{
public:
	SkeletonSubscription(Socket * pSocket) { m_pSocket = pSocket; }
	
	virtual void incomingData(unsigned char * pucData, unsigned int nLength);
	
	virtual ConsumptionLevel consumptionLevel();
	virtual void connectionEtablished();
	virtual void connectionClosed();
	
	virtual void subscriptionSuperseeded() { assert(false); }
	
protected:
	Socket * m_pSocket;
};

#endif // __MWCMOD_SKELETONTCP2_H
