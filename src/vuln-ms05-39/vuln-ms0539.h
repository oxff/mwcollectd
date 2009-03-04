/*
 * Simulates MS05-39 (Remote Code Execution in Plug and Play Services).
 *
 * $Id: vuln-ms0539.h 208 2005-11-05 13:30:19Z oxff $
 *
 */
 
#ifndef __MWCMOD_MS0539_H
#define __MWCMOD_MS0539_H

#include <mwcollect/core.h>
using namespace mwccore;

#include <string>
using namespace std;

#include <assert.h>


class VulnerabilityModule : public Module, public NetworkSubscriptionFactory, public ShellcodeParser
{
public:
	VulnerabilityModule();
	~VulnerabilityModule();
	
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfiguration = pConfig; };
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; };
	
	virtual bool start();
	virtual void stop();
	
	virtual bool parseShellcode(const unsigned char * pucShellcode, unsigned int nLength, unsigned long ulHost, CorrelationId cid);
	
	virtual NetworkSubscription * createNetworkSubscription(Socket * pSocket);
	virtual void freeNetworkSubscription(NetworkSubscription * pSubscription);
		
protected:
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
};


class VulnerabilitySubscription : public NetworkSubscription
{
public:
	VulnerabilitySubscription(MalwareCollector * pCollector, Socket * pSocket)
	{ m_pCollector = pCollector; m_pSocket = pSocket; }
	
	virtual void incomingData(unsigned char * pucData, unsigned int nLength);
	
	virtual ConsumptionLevel consumptionLevel();
	virtual void connectionEtablished();
	virtual void connectionClosed();
	
	virtual void subscriptionSuperseeded() { assert(false); }
	
protected:
	MalwareCollector * m_pCollector;
	Socket * m_pSocket;
	
	ConsumptionLevel m_clLevel;
	string m_sBuffer;
	
	int m_iStage;
	int m_iPacketLength;
};

#endif // __MWCMOD_MS0539_H
