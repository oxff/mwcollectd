/*
 * $Id: network.h 289 2006-02-02 15:01:36Z oxff $
 *
 * the NetworkInterface is the abstraction layer between a NetworkInterface and a NetworkSubscription, enables multiple NetworkSubscriptions
 * per port and so on. this ideas was already used in nepenthes -- and no, this is not a copy of the idea but we worked it out together some time ago
 */
 
 
#ifndef __MWCCORE_NETWORK_H
#define __MWCCORE_NETWORK_H

#include "module.h"

#include <list>
 
namespace mwccore
{
	class Socket;
	
	enum NetworkActivity
	{
		NA_INTERACTIVE = 0,
		NA_DOWNLOADING_SENSOR,
		NA_SILENT_SENSOR,
	};
	
	enum ConsumptionLevel
	{
		CL_UNSURE = 0,
		
		CL_DROP,
		CL_OVERTAKE,
		
		CL_SNIFF,
	};
	
	struct Connection
	{
		int iSocket;
		
		unsigned long ulSourceHost, ulDestinationHost;
		unsigned short usSourcePort, usDestinationPort;
		
		// source = remote, destination = local
	};
	
	
	
	enum NetworkInterfaceClassification
	{
		NIC_NORMAL = 0,
		NIC_SNIFFER,
	};
	
	class NetworkInterface
	{
	public:
		virtual int createDatagramSocket(unsigned long ulBindAddress, unsigned short usLocalPort) = 0;
		virtual int createStreamServer(unsigned long ulBindAddress, unsigned short usPort) = 0;
		virtual int createStreamClient(unsigned long ulRemoteAddress, unsigned short usRemotePort) = 0;
		virtual bool closeSocket(int iSocket) = 0;
		
		virtual int receiveData(int iSocket, unsigned char * pucBuffer, int iBufferSize)
		{ return receiveData(iSocket, pucBuffer, iBufferSize, 0, 0); }
		
		virtual int sendData(int iSocket, const unsigned char * pucBuffer, int iBufferSize)
		{ return sendData(iSocket, pucBuffer, iBufferSize, 0, 0); }
		
		virtual int receiveData(int iSocket, unsigned char * pucBuffer, int iBufferSize, unsigned long * pulSourceAddress, unsigned short * pusSourcePort) = 0;
		virtual int sendData(int iSocket, const unsigned char * pucBuffer, int iBufferSize, unsigned long ulToHost, unsigned short usToPort) = 0;
		virtual bool acceptConnection(int iSocket, Connection * pConnection) = 0;
		
		virtual bool isReadable(int iSocket) = 0;
		virtual bool isWriteable(int iSocket) = 0;
		virtual bool isClosed(int iSocket) = 0;
		virtual bool isErroneous(int iSocket) = 0;
		
		virtual bool waitForEvents(int iWait) = 0;
		
		virtual void getLocalName(int iSocket, unsigned long * pulHost, unsigned short * pusPort) = 0;
		
		virtual unsigned long resolveHostname(const char * szHostName) = 0;
	};
	
	
	
	class NetworkSubscription
	{
	public:		
		virtual void incomingData(unsigned char * pucData, unsigned int nLength) = 0;
		virtual void outgoingData(unsigned char * pucData, unsigned int nLength) { };
		
		virtual ConsumptionLevel consumptionLevel() = 0;
		
		virtual void connectionLost() { connectionClosed(); }
		virtual void connectionClosed() { }
		virtual void connectionEtablished() { }
		
		virtual void subscriptionSuperseded() { }
		
		virtual void setUserData(void * pUserData) { }
		
		unsigned long m_ulRemoteHost;
		unsigned short m_usRemotePort;
	};
	
	class NetworkSubscriptionFactory
	{
	public:
		virtual NetworkSubscription * createNetworkSubscription(Socket * pSocket) = 0;
		virtual void freeNetworkSubscription(NetworkSubscription * pSubscription) = 0;
	};
	
	
	
	// internal NetworkCore data storage structures
	
	struct PortBinding
	{
		bool bUDP, bAgressiveUDP;
		unsigned short usPort;
		unsigned long ulAddress;
		int iSocket;
		
		std::list<NetworkSubscriptionFactory *> lpFactories;
		
		Socket * pDatagramSocket;
		unsigned int nDatagramRefCounter;
	};
	
	struct SubscriptionTuple
	{
		NetworkSubscription * pSubscription;
		NetworkSubscriptionFactory * pFactory;
		
		unsigned long ulTimeout;
		Socket * pAssociatedSocket;
	};
	
	struct ActiveConnection
	{
		std::list<SubscriptionTuple> lstSubscriptions;
		
		int iSocket;
		PortBinding * pBinding;
		bool bUDP, bAgressiveUDP;
		
		unsigned long ulLastData;
		unsigned long ulTimeout;
		
		unsigned long ulSourceHost, ulDestinationHost;
		unsigned short usSourcePort, usDestinationPort;
		
		// source = remote, destination = local
		
		NetworkSubscription * pSender;
	};
	

	class NetworkCore
	{
	public:
		NetworkCore();
		virtual ~NetworkCore();
		
		virtual bool registerNetworkInterface(NetworkInterface * pInterface, NetworkInterfaceClassification nicClassification, Module * pAssocModule);
		virtual bool unregisterNetworkInterface(NetworkInterface * pInterface);
		
		virtual bool setActivityLevel(NetworkActivity naActivity);
		virtual bool setBindAddress(unsigned long ulBindAddress);
		virtual bool setConnectionTimeout(unsigned long ulTimeout)
		{ m_ulTimeout = ulTimeout; }
		
		virtual bool waitForEvents();
		
		virtual unsigned long resolveHostname(const char * szHostName);
		
		
		virtual bool registerSubscriber(unsigned short usPort, NetworkSubscriptionFactory * pFactory, bool bDatagram = false, Socket * * ppSocket = 0, bool bExclusive = false);
		virtual bool unregisterSubscriber(unsigned short usPort, NetworkSubscriptionFactory * pFactory, bool bDatagram = false);
		
		virtual Socket * associateSocket(NetworkSubscriptionFactory * pSubscriptionFactory, unsigned long ulRemoteAddress, unsigned short usRemotePort, unsigned long ulTimeout = 0, bool bAgressive = false, void * pUser = 0);
		virtual Socket * connectSocket(NetworkSubscriptionFactory * pSubscriptionFactory, unsigned long ulRemoteAddress, unsigned short usRemotePort, void * pUser = 0);
		virtual bool closeSubscription(NetworkSubscription * pSubscription);		
		virtual bool setSubscriptionTimeout(NetworkSubscription * pSubscription, unsigned long ulTimeout);
		
		void loop(); // looks pretty unimpressive, doesn't it? :)
		
		bool interfaceModule(Module * pModule) { return pModule == m_pInterfaceModule; }
		
		void getLocalAddress(NetworkSubscription * pSubscription, unsigned long * pulAddress, unsigned short * pusPort);
				
		
	protected:
		PortBinding * createPortBinding(unsigned short usPort, NetworkSubscriptionFactory * pFactory, bool bUDP = false, Socket * * ppSocket = 0, unsigned short * pusEffectiveLocalPort = 0, int * piSocket = 0, bool bAgressiveUDP = false);
		
		void addStreamConnection(Connection * pConnection, PortBinding * pBinding);
		
		void processStreamConnection(std::list<ActiveConnection>::iterator itConnection);
		void processDatagramConnection(std::list<PortBinding>::iterator itConnection);
			
		bool sendData(NetworkSubscription * pOrigin, int iSocket, const unsigned char * pucData, unsigned int nLength, unsigned long ulHost, unsigned short usPort); 
		
	private:
		NetworkInterface * m_pInterface;
		Module * m_pInterfaceModule;
		
		NetworkActivity m_naActivity;
		unsigned long m_ulBindAddress;
		
		std::list<PortBinding> m_lpbBindings;
		std::list<ActiveConnection> m_lacConnections;
		
		unsigned long m_ulTimeout;
		
		friend class Socket;
	};
};

#include "socket.h"

#endif // __MWCCORE_NETWORK_H
