/*
 * UDP Pairing Skeleton Module
 * A more or less well commented example how to subscribe to a certain UDP port and get pairings.
 *
 * $Id: skeleton-udp.h 114 2005-09-24 16:29:50Z oxff $
 *
 */
 
#ifndef __MWCMOD_SKELETONUDP_H
#define __MWCMOD_SKELETONUDP_H

#include <mwcollect/core.h>

using namespace mwccore;


class SkeletonModule : public Module, public NetworkSubscriptionFactory
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

#endif // __MWCMOD_SKELETONUDP_H
