/*
 * TCP Client Skeleton Module
 * A more or less well commented example how to connect to a host and work on the data via a subscription.
 *
 * $Id: skeleton-tcp2-module.cpp 114 2005-09-24 16:29:50Z oxff $
 *
 */
 
#include "skeleton-tcp2.h"

extern "C"
{
	// wrappers around constructor and deconstructor to have nice dll interface
	
	void * CreateInstance()
	{
		return new SkeletonModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (SkeletonModule *) pInstance;
	}
}


SkeletonModule::SkeletonModule()
{
	// initialize all member variables
}

SkeletonModule::~SkeletonModule()
{
	// free allocated memory
}


bool SkeletonModule::start()
{
	// intialize module stuff
	
	LOG(LT_LEVEL_LOW | LT_STATUS, "Skeleton started: %s", __FILE__);
	
	unsigned long ulAddress;
	unsigned short usPort;
	
	{
		const char * szHost = m_pConfiguration->getString("remote-host", "localhost");
		
		ulAddress = m_pCollector->getNetworkCore()->resolveHostname(szHost);
		usPort = (unsigned short) m_pConfiguration->getLong("remote-port", 45678);
	}
	
	if(!m_pCollector->getNetworkCore()->connectSocket(this, ulAddress, usPort))
	{
		LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Skeleton connection refused.");
		
		return false;
	}
	
	// loading successful?
	return true;
}

void SkeletonModule::stop()
{
	LOG(LT_LEVEL_LOW | LT_STATUS, "Skeleton stoped: %s", __FILE__);
}

NetworkSubscription * SkeletonModule::createNetworkSubscription(Socket * pSocket)
{
	DEBUG("Lady create!");
	
	return new SkeletonSubscription(pSocket);
}

void SkeletonModule::freeNetworkSubscription(NetworkSubscription * pSubscription)
{
	delete (SkeletonSubscription *) pSubscription;
}
