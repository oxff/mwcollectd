/*
 * Da real networking core!
 * $Id: network.cpp 312 2006-02-07 23:54:22Z oxff $
 *
 * `Over the hills and far away!'
 * HardStyle && HappyHardcore Uber-Hengst
 *
 * `Bebey sieh es nicht so eng, fang jetzt endlich an zu bangen!'
 *
 */
 
#include <mwcollect/core.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <assert.h>

namespace mwccore
{
	char * ip_helper(unsigned long u)
	{
		in_addr addr;
		
		addr.s_addr = u;
		return inet_ntoa(addr);
	}

	NetworkCore::NetworkCore()
	{
		m_pInterface = 0;
		
		m_naActivity = NA_SILENT_SENSOR;
		m_ulBindAddress = INADDR_ANY;
		m_ulTimeout = 0;
	}
	
	NetworkCore::~NetworkCore()
	{
	}
	
	
	bool NetworkCore::registerNetworkInterface(NetworkInterface * p, NetworkInterfaceClassification nicClassification, Module * pAssocModule)
	{
		if(m_pInterface)
			return false;
			
		m_pInterface = p;
		m_pInterfaceModule = pAssocModule;
		
		return true;
	}
	
	bool NetworkCore::unregisterNetworkInterface(NetworkInterface * p)
	{
		if(p != m_pInterface)
			return false;
			
		m_pInterface = 0;
		return true;
	}
	
	
	bool NetworkCore::setActivityLevel(NetworkActivity na)
	{
		if(m_pInterface)
			return false;
			
		m_naActivity = na;
		return true;
	}
	
	bool NetworkCore::setBindAddress(unsigned long ulAddress)
	{			
		m_ulBindAddress = ulAddress;
		return true;
	}
	
	
	bool NetworkCore::waitForEvents()
	{
		// we check every second to allow more or less a one second resolution of timeouts
		return m_pInterface->waitForEvents(1000) || m_ulTimeout != 0;
	}
	
	
	// the real important code in this file: the abstraction layer implentation
	
	bool NetworkCore::registerSubscriber(unsigned short usPort, NetworkSubscriptionFactory * pFactory, bool bUDP, Socket * * ppSocket, bool bExclusive)
	{
		if(!bUDP && !usPort)
			return false;
	
		if(usPort)
		{	
			for(std::list<PortBinding>::iterator i = m_lpbBindings.begin(); i != m_lpbBindings.end(); ++i)
			{
				if(i->usPort != usPort || i->bUDP != bUDP)
					continue;
					
				if(bExclusive)
					return false;
				
				i->lpFactories.push_back(pFactory);
				
				if(ppSocket && bUDP)
					* ppSocket = i->pDatagramSocket;
				
				return true;
			}
		}
		
		return createPortBinding(usPort, pFactory, bUDP, ppSocket);
	}
	
	bool NetworkCore::unregisterSubscriber(unsigned short usPort, NetworkSubscriptionFactory * pFactory, bool bUDP)
	{	
		for(std::list<PortBinding>::iterator i = m_lpbBindings.begin(); i != m_lpbBindings.end(); ++i)
		{
			if(i->usPort != usPort || i->bUDP != bUDP)
				continue;
			
			i->lpFactories.remove(pFactory);
			
			if(i->lpFactories.empty())
			{ // there is no subscriber associated anymore, close the socket and free the binding
				m_pInterface->closeSocket(i->iSocket);
				
				if(i->pDatagramSocket)
				{
					assert(i->bUDP);
					delete i->pDatagramSocket;
				}
				
				m_lpbBindings.erase(i);
			}
			
			return true;
		}
		
		return false;
	}
	
	Socket * NetworkCore::connectSocket(NetworkSubscriptionFactory * pSubscriptionFactory, unsigned long ulRemoteAddress, unsigned short usRemotePort, void * pUser)
	{
		int iSocket = m_pInterface->createStreamClient(ulRemoteAddress, usRemotePort);
		ActiveConnection acConnection;
		SubscriptionTuple stTuple;
		
		if(iSocket <= 0)
			return 0;
		
		acConnection.iSocket = iSocket;
		acConnection.bUDP = false;
		acConnection.ulSourceHost = ulRemoteAddress;
		acConnection.usSourcePort = usRemotePort;
		acConnection.ulDestinationHost = 0;
		acConnection.usDestinationPort = 0;
		acConnection.ulTimeout = m_ulTimeout;
		acConnection.ulLastData = time(0);
		acConnection.pSender = 0;
		
		stTuple.pAssociatedSocket = new Socket(this, acConnection.iSocket, 0, 0);
		stTuple.pSubscription = pSubscriptionFactory->createNetworkSubscription(stTuple.pAssociatedSocket);
		stTuple.pAssociatedSocket->setOwner(stTuple.pSubscription);
		stTuple.pFactory = pSubscriptionFactory;
		stTuple.ulTimeout = 0;
		acConnection.lstSubscriptions.push_back(stTuple);
		
		if(pUser)
			stTuple.pSubscription->setUserData(pUser);
		
		m_lacConnections.push_back(acConnection);		
		stTuple.pSubscription->connectionEtablished();
		
		return stTuple.pAssociatedSocket;
	}	
	
	PortBinding * NetworkCore::createPortBinding(unsigned short usPort, NetworkSubscriptionFactory * pFactory, bool bUDP, Socket * * ppSocket, unsigned short * pusLocalPort, int * piSocket, bool bAgressiveUDP)
	{
		PortBinding pbBinding;
		
		if(!m_pInterface)
		{
			LOG(LT_LEVEL_CRITICAL | LT_STATUS, "No Network Interface Module registered!");
			exit(0);
		}
		
		if(!bUDP)
		{
			if((pbBinding.iSocket = m_pInterface->createStreamServer(m_ulBindAddress, usPort)) < 0)
				return 0; // creating the socket failed
		}
		else
		{
			if((pbBinding.iSocket = m_pInterface->createDatagramSocket(m_ulBindAddress, usPort)) < 0)
				return 0; // creation failed...
		}
		
		pbBinding.lpFactories.push_back(pFactory);
		pbBinding.bUDP = bUDP;
		pbBinding.bAgressiveUDP = bAgressiveUDP;
		m_pInterface->getLocalName(pbBinding.iSocket, &pbBinding.ulAddress, &pbBinding.usPort);
		pbBinding.nDatagramRefCounter = 1;
		
		if(pusLocalPort)
			* pusLocalPort = pbBinding.usPort;
			
		if(piSocket)
			* piSocket = pbBinding.iSocket;
		
		if(bUDP)
		{
			pbBinding.pDatagramSocket = new Socket(this, pbBinding.iSocket, 0, 0);
			
			if(ppSocket)
				* ppSocket = pbBinding.pDatagramSocket;
		}
		else
			pbBinding.pDatagramSocket = 0;
		
		m_lpbBindings.push_back(pbBinding);
		return &(* --m_lpbBindings.end());
	}
	
	bool NetworkCore::setSubscriptionTimeout(NetworkSubscription * pSubscription, unsigned long ulTimeout)
	{
		DEBUG("Set Subscription Timeout of %p to %u.", pSubscription, ulTimeout);
		
		for(std::list<ActiveConnection>::iterator i = m_lacConnections.begin(); i != m_lacConnections.end(); ++i)
		{
			for(std::list<SubscriptionTuple>::iterator j = i->lstSubscriptions.begin(); j != i->lstSubscriptions.end(); ++j)
			{
				if(j->pSubscription != pSubscription)
					continue;
					
				j->ulTimeout = ulTimeout;				
				return true;
			}
		}
		
		return false;
	}
	
	
	// the actual big beast doing all the network coordination every main loop iteration:
	// (now actually split into different subroutines)
	
	void NetworkCore::loop()
	{
		{ // check listening stream servers for incoming connections
			std::list<PortBinding>::iterator iNext;
						
			for(std::list<PortBinding>::iterator i = m_lpbBindings.begin(); i != m_lpbBindings.end(); i = iNext)
			{
				Connection cConnection;
				
				iNext = i;
				++iNext;
				
				if(!i->bUDP)
				{					
					if(!m_pInterface->acceptConnection(i->iSocket, &cConnection))
						continue;
					
					addStreamConnection(&cConnection, &(* i));
				}
				else
				{
					if(m_pInterface->isReadable(i->iSocket))
					{					
						processDatagramConnection(i);
					}
				}
			}
		}
		
		{ // check active stream connections for data and errors
			std::list<ActiveConnection>::iterator next;
			
			for(std::list<ActiveConnection>::iterator i = m_lacConnections.begin(); i != m_lacConnections.end();)
			{
				next = i;
				++next;
				
				if(!i->bUDP)
					processStreamConnection(i);
					
				i = next;
			}
		}
		
		{ // check timeouts
			std::list<ActiveConnection>::iterator next;
			unsigned long ulNow = time(0);
			bool bCheckOverall;
			
			for(std::list<ActiveConnection>::iterator i = m_lacConnections.begin(); i != m_lacConnections.end();)
			{
				bCheckOverall = true;
				next = i;
				++next;
				
				{ // check per subscription timeouts		
					std::list<SubscriptionTuple>::iterator jnext;
					
					for(std::list<SubscriptionTuple>::iterator j = i->lstSubscriptions.begin(); j != i->lstSubscriptions.end(); j = jnext)
					{
						jnext = j;
						++jnext;
						
						if(j->ulTimeout)
						{
							bCheckOverall = false;
							
							if(ulNow > i->ulLastData + j->ulTimeout)
							{
								DEBUG("Dropping subscription from :%hu due to timeout of %u seconds.", i->usSourcePort, j->ulTimeout);

								j->pSubscription->connectionLost();
								j->pFactory->freeNetworkSubscription(j->pSubscription);	
								delete j->pAssociatedSocket;
								
								if(i->pSender == j->pSubscription)
									i->pSender = 0;
								
								i->lstSubscriptions.erase(j);
							}
						}
					}
				}
								
				if(bCheckOverall && i->ulTimeout && ulNow > i->ulLastData + i->ulTimeout)
				{
					DEBUG("Dropping connection from :%hu due to timeout of %u seconds.", i->usSourcePort, i->ulTimeout);
					
					for(std::list<SubscriptionTuple>::iterator j = i->lstSubscriptions.begin(); j != i->lstSubscriptions.end(); ++j)
					{
						j->pSubscription->connectionLost();
						j->pFactory->freeNetworkSubscription(j->pSubscription);	
						delete j->pAssociatedSocket;					
					}
					
					if(!i->bUDP)
						m_pInterface->closeSocket(i->iSocket);
					else
					{
						DEBUG("Timeout on UDP socket, reference counter is %u.", i->pBinding->nDatagramRefCounter);
															
						if(i->pBinding->bUDP && i->pBinding->nDatagramRefCounter <= 1)
						{
							unsigned short usThePort = i->pBinding->usPort;
							
							std::list<PortBinding>::iterator next;							
							m_pInterface->closeSocket(i->pBinding->iSocket);
							
							for(std::list<PortBinding>::iterator a = m_lpbBindings.begin(); a != m_lpbBindings.end(); a = next)
							{
								next = a;
								++next;
								
								if(a->usPort == usThePort && a->bUDP)
								{
									delete a->pDatagramSocket;
									m_lpbBindings.erase(a);
									DEBUG("Erased PortBinding (UDP) because of Timeout.");
								}
							}
						}
						else
						{
							--(i->pBinding->nDatagramRefCounter);
							
							DEBUG("Decremented Reference counter!");
						}
					}
											
					m_lacConnections.erase(i);
				}
					
				i = next;
			}
		}
	}
	
	void NetworkCore::addStreamConnection(Connection * pConnection, PortBinding * pBinding)
	{
		ActiveConnection acConnection;
		
		acConnection.iSocket = pConnection->iSocket;
		acConnection.ulSourceHost = pConnection->ulSourceHost;
		acConnection.ulDestinationHost = pConnection->ulDestinationHost;
		acConnection.usSourcePort = pConnection->usSourcePort;
		acConnection.usDestinationPort = pConnection->usDestinationPort;
		acConnection.bUDP = false;
		acConnection.ulTimeout = m_ulTimeout;
		acConnection.ulLastData = time(0);
		acConnection.pSender = 0;
		acConnection.pBinding = 0;
		
		LOG(LT_LEVEL_LOW | LT_NETWORK, "Got incoming stream connection to :%hu from %s:%hu.", pConnection->usDestinationPort, ip_helper(pConnection->ulSourceHost), pConnection->usSourcePort);
		
		for(std::list<NetworkSubscriptionFactory *>::iterator i = pBinding->lpFactories.begin(); i != pBinding->lpFactories.end(); ++i)
		{
			SubscriptionTuple stTuple;
			stTuple.pAssociatedSocket = new Socket(this, acConnection.iSocket, 0, 0);
			stTuple.pSubscription = (* i)->createNetworkSubscription(stTuple.pAssociatedSocket);
			stTuple.pSubscription->m_ulRemoteHost = acConnection.ulSourceHost;
			stTuple.pSubscription->m_usRemotePort = acConnection.usSourcePort;
			stTuple.pFactory = * i;
			stTuple.ulTimeout = 0;
			stTuple.pAssociatedSocket->setOwner(stTuple.pSubscription);
			
			acConnection.lstSubscriptions.push_back(stTuple);	
		}
		
		m_lacConnections.push_back(acConnection);
		
		for(std::list<SubscriptionTuple>::iterator i = acConnection.lstSubscriptions.begin(); i != acConnection.lstSubscriptions.end(); ++i)
			i->pSubscription->connectionEtablished();
	}
	
	
	unsigned char g_pucBuffer[4096];
	
	void NetworkCore::processStreamConnection(std::list<ActiveConnection>::iterator itConnection)
	{
		int iRead;
		std::list<SubscriptionTuple>::iterator iNext;
		NetworkSubscription * pOvertaker = 0;
		unsigned long ulNow = time(0);
		
		if(m_pInterface->isErroneous(itConnection->iSocket))
			iRead = -1;
		else if(m_pInterface->isClosed(itConnection->iSocket))
			iRead = 0;
		else if(m_pInterface->isReadable(itConnection->iSocket))
			iRead = m_pInterface->receiveData(itConnection->iSocket, g_pucBuffer, sizeof(g_pucBuffer));
		else
			return;
			
		if(iRead > 0)
			itConnection->ulLastData = time(0);
		
		for(std::list<SubscriptionTuple>::iterator i = itConnection->lstSubscriptions.begin(); i != itConnection->lstSubscriptions.end(); i = iNext)
		{
			iNext = i;
			++iNext;
			
			if(iRead < 0)
				i->pSubscription->connectionLost();
			else if(iRead == 0)
				i->pSubscription->connectionClosed();
			else
			{
				ConsumptionLevel clLevel;
				
				i->pSubscription->incomingData(g_pucBuffer, iRead);
				clLevel = i->pSubscription->consumptionLevel();
				
				if(clLevel == CL_DROP)
				{
					LOG(LT_LEVEL_LOW | LT_NETWORK, "Stream subscription to :%hu from %s:%hu dropped.", itConnection->usDestinationPort, ip_helper(itConnection->ulSourceHost), itConnection->usSourcePort);
					
					if(itConnection->pSender == i->pSubscription)
						itConnection->pSender = 0;
					
					i->pSubscription->subscriptionSuperseded();
					i->pFactory->freeNetworkSubscription(i->pSubscription);
					delete i->pAssociatedSocket;
					
					itConnection->lstSubscriptions.erase(i);
				}
				else if(clLevel == CL_OVERTAKE)
				{
					if(!pOvertaker)
						pOvertaker = i->pSubscription;
					else
						LOG(LT_STATUS | LT_LEVEL_MEDIUM, "Stream connection to :%hu from %s:%hu wanted by more than one subscriber!", itConnection->usDestinationPort, ip_helper(itConnection->ulSourceHost), itConnection->usSourcePort);
				}
			}
				
			if(iRead <= 0)
			{
				i->pFactory->freeNetworkSubscription(i->pSubscription);
				delete i->pAssociatedSocket;
				itConnection->lstSubscriptions.erase(i);
			}
		}
		
		if(pOvertaker && itConnection->lstSubscriptions.size() > 1)
		{
			DEBUG("Stream connection to :%hu from %s:%hu taken over by %p.", itConnection->usDestinationPort, ip_helper(itConnection->ulSourceHost), itConnection->usSourcePort, pOvertaker);
			
			for(std::list<SubscriptionTuple>::iterator i = itConnection->lstSubscriptions.begin(); i != itConnection->lstSubscriptions.end(); i = iNext)
			{
				iNext = i;
				++iNext;
				
				if(i->pSubscription == pOvertaker)
					continue;
					
				if(i->pSubscription->consumptionLevel() != CL_SNIFF)
				{					
					i->pSubscription->subscriptionSuperseded();
					
					i->pFactory->freeNetworkSubscription(i->pSubscription);
					delete i->pAssociatedSocket;
					itConnection->lstSubscriptions.erase(i);
				}
			}
		}
		
		if(iRead <= 0 || itConnection->lstSubscriptions.empty())
		{
			if(iRead <= 0)
				LOG(LT_LEVEL_LOW | LT_NETWORK, "Stream connection to :%hu from %s:%hu died out (%i).", itConnection->usDestinationPort, ip_helper(itConnection->ulSourceHost), itConnection->usSourcePort, itConnection->lstSubscriptions.size());
			
			m_pInterface->closeSocket(itConnection->iSocket);
			
			m_lacConnections.erase(itConnection);
		}
	}
	

	Socket * NetworkCore::associateSocket(NetworkSubscriptionFactory * pSubscriptionFactory, unsigned long ulRemoteAddress, unsigned short usRemotePort, unsigned long ulTimeout, bool bAgressive, void * pUserData)
	{
		ActiveConnection acNewConnection;
		unsigned short usLocalPort;
		int iSocket;
		Socket * pSocket;
		
		if(!(acNewConnection.pBinding = createPortBinding(0, pSubscriptionFactory, true, 0, &usLocalPort, &iSocket, bAgressive)))
			return 0;
			
		acNewConnection.iSocket = 0; // UDP connections don't have an own socket
		acNewConnection.bUDP = true;
		
		acNewConnection.usSourcePort = usRemotePort;
		acNewConnection.ulSourceHost = ulRemoteAddress;
		acNewConnection.usDestinationPort = usLocalPort;
		acNewConnection.ulDestinationHost = 0; // do we need that info? if so, requires extra network iface call
		acNewConnection.ulTimeout = m_ulTimeout;
		acNewConnection.ulLastData = time(0);
		acNewConnection.bAgressiveUDP = bAgressive;
		acNewConnection.pSender = 0;
		
		pSocket = new Socket(this, iSocket, ulRemoteAddress, usRemotePort);
		
		{
			SubscriptionTuple stTuple;
			
			stTuple.pAssociatedSocket = pSocket;
			stTuple.pSubscription = pSubscriptionFactory->createNetworkSubscription(stTuple.pAssociatedSocket);
			stTuple.pSubscription->m_ulRemoteHost = ulRemoteAddress;
			stTuple.pSubscription->m_usRemotePort = usRemotePort;
			stTuple.pFactory = pSubscriptionFactory;
			stTuple.ulTimeout = 0;
			stTuple.pAssociatedSocket->setOwner(stTuple.pSubscription);		
			
			stTuple.pSubscription->connectionEtablished();
			acNewConnection.lstSubscriptions.push_back(stTuple);
			
			if(pUserData)
				stTuple.pSubscription->setUserData(pUserData);
		}
		
		LOG(LT_LEVEL_LOW | LT_NETWORK, "Associated pairing to :%hu from %s:%hu.", usLocalPort, ip_helper(ulRemoteAddress), usRemotePort);
		
		m_lacConnections.push_back(acNewConnection);
		return pSocket;
	}
	
	void NetworkCore::processDatagramConnection(std::list<PortBinding>::iterator itConnection)
	{
		int iRead;
		unsigned long ulAddress;
		unsigned short usPort;
		ActiveConnection * pacConnection = 0;
		ActiveConnection acNewConnection;
		
		if(m_pInterface->isErroneous(itConnection->iSocket))
			iRead = -1;
		else if(m_pInterface->isClosed(itConnection->iSocket))
			iRead = 0;
		else		
			iRead = m_pInterface->receiveData(itConnection->iSocket, g_pucBuffer, sizeof(g_pucBuffer), &ulAddress, &usPort);
			
		// udp `connections' cannot be `closed'
		if(!iRead)
			LOG(LT_LEVEL_MEDIUM | LT_STATUS, "Unexpected behaviour of network interface: UDP socket %i was found in `closed' state.", itConnection->iSocket);
		
		for(std::list<ActiveConnection>::iterator i = m_lacConnections.begin(); i != m_lacConnections.end(); ++i)
		{
			if(i->bUDP && (i->usSourcePort == usPort || i->bAgressiveUDP) && i->ulSourceHost == ulAddress && i->usDestinationPort == itConnection->usPort)
			{
				pacConnection = &(* i);
				
				break;
			}
		}
		
		if(!pacConnection)
		{			
			acNewConnection.iSocket = 0; // UDP connections don't have an own socket
			acNewConnection.bUDP = true;
			acNewConnection.bAgressiveUDP = itConnection->bAgressiveUDP;
			
			acNewConnection.usSourcePort = usPort;
			acNewConnection.ulSourceHost = ulAddress;
			acNewConnection.usDestinationPort = itConnection->usPort;
			acNewConnection.ulDestinationHost = 0; // do we need that info? if so, requires extra network iface call
			acNewConnection.ulTimeout = m_ulTimeout;
			acNewConnection.ulLastData = time(0);
			acNewConnection.pSender = 0;
			acNewConnection.pBinding = &(* itConnection);
			DEBUG("Assigned %p to new UDP connection!", acNewConnection.pBinding);
			++(acNewConnection.pBinding->nDatagramRefCounter);
			
			for(std::list<NetworkSubscriptionFactory *>::iterator i = itConnection->lpFactories.begin(); i != itConnection->lpFactories.end(); ++i)
			{
				SubscriptionTuple stTuple;
				
				stTuple.pAssociatedSocket = new Socket(this, itConnection->iSocket, ulAddress, usPort);
				stTuple.pSubscription = (* i)->createNetworkSubscription(stTuple.pAssociatedSocket);
				stTuple.pSubscription->m_ulRemoteHost = ulAddress;
				stTuple.pSubscription->m_usRemotePort = usPort;
				stTuple.pFactory = * i;
				stTuple.ulTimeout = 0;
				stTuple.pAssociatedSocket->setOwner(stTuple.pSubscription);		
				
				stTuple.pSubscription->connectionEtablished();
				acNewConnection.lstSubscriptions.push_back(stTuple);
			}
			
			LOG(LT_LEVEL_LOW | LT_NETWORK, "Got new datagram pairing to :%hu from %s:%hu.", itConnection->usPort, ip_helper(ulAddress), usPort);
			
			m_lacConnections.push_back(acNewConnection);
			pacConnection = &acNewConnection;
		}
		
		if(iRead)
			pacConnection->ulLastData = time(0);
		
		for(std::list<SubscriptionTuple>::iterator i = pacConnection->lstSubscriptions.begin(); i != pacConnection->lstSubscriptions.end(); ++i)
		{
			if(iRead < 0)
				i->pSubscription->connectionLost();
			else if(iRead == 0)
				i->pSubscription->connectionClosed();
			else
			{			
				i->pSubscription->m_usRemotePort = usPort;
				i->pSubscription->incomingData(g_pucBuffer, iRead);
			}
				
			if(iRead <= 0)
				i->pFactory->freeNetworkSubscription(i->pSubscription);
		}
		
		{
			std::list<SubscriptionTuple>::iterator iNext;
			NetworkSubscription * pOvertaker = 0;
			ConsumptionLevel clLevel;
			
			for(std::list<SubscriptionTuple>::iterator i = pacConnection->lstSubscriptions.begin(); i != pacConnection->lstSubscriptions.end(); i = iNext)
			{
				iNext = i;
				++iNext;
				
				clLevel = i->pSubscription->consumptionLevel();
				
				if(clLevel == CL_DROP)
				{
					i->pSubscription->subscriptionSuperseded();
					
					i->pFactory->freeNetworkSubscription(i->pSubscription);
					pacConnection->lstSubscriptions.erase(i);
				}
				else if(clLevel == CL_OVERTAKE && !pOvertaker)
					pOvertaker = i->pSubscription;
			}
			
			if(pOvertaker && pacConnection->lstSubscriptions.size() > 1)
			{
				for(std::list<SubscriptionTuple>::iterator i = pacConnection->lstSubscriptions.begin(); i != pacConnection->lstSubscriptions.end(); i = iNext)
				{
					iNext = i;
					++iNext;
				
					if(pOvertaker == i->pSubscription)
						continue;
						
					i->pSubscription->subscriptionSuperseded();
					
					i->pFactory->freeNetworkSubscription(i->pSubscription);
					pacConnection->lstSubscriptions.erase(i);	
				}
			}
			
			if(!pacConnection->lstSubscriptions.size())
			{
				for(std::list<ActiveConnection>::iterator i = m_lacConnections.begin(); i != m_lacConnections.end(); ++i)
					if(i->bUDP && (i->usSourcePort == pacConnection->usSourcePort || i->bAgressiveUDP) && i->ulSourceHost == pacConnection->ulSourceHost && i->usDestinationPort == pacConnection->usDestinationPort)
					{
						m_lacConnections.erase(i);
						break;
					}
					
				m_pInterface->closeSocket(itConnection->iSocket);
				m_lpbBindings.erase(itConnection);
			}
		}
		
		if(iRead <= 0)
		{
			assert(itConnection->pDatagramSocket);
			delete itConnection->pDatagramSocket;
			
			m_lpbBindings.erase(itConnection);
		}
	}
	
	bool NetworkCore::closeSubscription(NetworkSubscription * pSubscription)
	{
		for(std::list<ActiveConnection>::iterator i = m_lacConnections.begin(); i != m_lacConnections.end(); ++i)
		{
			for(std::list<SubscriptionTuple>::iterator j = i->lstSubscriptions.begin(); j != i->lstSubscriptions.end(); ++j)
			{
				if(j->pSubscription != pSubscription)
					continue;
					
				j->pSubscription->connectionClosed();
				j->pFactory->freeNetworkSubscription(j->pSubscription);
				delete j->pAssociatedSocket;
				
				i->lstSubscriptions.erase(j);
				
				if(i->lstSubscriptions.empty())
				{
					m_pInterface->closeSocket(i->iSocket);
			
					m_lacConnections.erase(i);
				}
				
				return true;
			}
		}
		
		return false;
	}
	
	bool NetworkCore::sendData(NetworkSubscription * pOrigin, int iSocket, const unsigned char * pucData, unsigned int nLength, unsigned long ulHost, unsigned short usPort)
	{
		if(pOrigin)
		{
			for(std::list<ActiveConnection>::iterator i = m_lacConnections.begin(); i != m_lacConnections.end(); ++i)
			{
				if(i->iSocket != iSocket)
					continue;
					
				if(!i->pSender)
					i->pSender = pOrigin;
				else if(i->pSender != pOrigin)
					return false;
					
				i->ulLastData = time(0);
			}
		}
		
		return m_pInterface->sendData(iSocket, pucData, nLength, ulHost, usPort);
	}
	
	
	unsigned long NetworkCore::resolveHostname(const char * szHostName)
	{
		return m_pInterface->resolveHostname(szHostName);
	}
	
	
	void NetworkCore::getLocalAddress(NetworkSubscription * pSubscription, unsigned long * pulHost, unsigned short * pusPort)
	{
		for(std::list<ActiveConnection>::iterator i = m_lacConnections.begin(); i != m_lacConnections.end(); ++i)	
		{
			for(std::list<SubscriptionTuple>::iterator j = i->lstSubscriptions.begin(); j != i->lstSubscriptions.end(); ++j)
				if(j->pSubscription == pSubscription)
				{
					* pulHost = i->ulDestinationHost;
					* pusPort = i->usDestinationPort;
					
					return;
				}
		}
	}
}
