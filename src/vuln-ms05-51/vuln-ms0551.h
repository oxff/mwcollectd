/*
 * Simulates MS05-51 (Remote Code Execution in MSDTC).
 *
 * $Id: vuln-ms0551.h 260 2005-12-16 01:21:09Z oxff $
 *
 * If Jovanka's not the one... ;>
 *
 */
 
#ifndef __MWCMOD_MS0551_H
#define __MWCMOD_MS0551_H

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

#endif // __MWCMOD_MS0551_H
