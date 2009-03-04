/*
 * UDP Pairing Skeleton Module
 * A more or less well commented example how to subscribe to a certain UDP port and get pairings.
 *
 * $Id: skeleton-udp-module.cpp 114 2005-09-24 16:29:50Z oxff $
 *
 */
 
#include "skeleton-udp.h"

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
	
	m_pCollector->getNetworkCore()->registerSubscriber(m_pConfiguration->getLong("listen-port", 4401), this, true);
	
	// loading successful?
	return true;
}

void SkeletonModule::stop()
{
	m_pCollector->getNetworkCore()->unregisterSubscriber(m_pConfiguration->getLong("listen-port", 4401), this);
	
	LOG(LT_LEVEL_LOW | LT_STATUS, "Skeleton stoped: %s", __FILE__);
}


NetworkSubscription * SkeletonModule::createNetworkSubscription(Socket * pSocket)
{
	LOG(LT_DEBUG, "Created NetworkSubscription for skeleton: %s", __FILE__);
	
	return new SkeletonSubscription(pSocket);
}

void SkeletonModule::freeNetworkSubscription(NetworkSubscription * pSubscription)
{
	delete (SkeletonSubscription *) pSubscription;
}
