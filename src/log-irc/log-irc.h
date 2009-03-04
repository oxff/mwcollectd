/*
 * IRC Logging module: lets you log into a chosen IRC network and provides basic control commands.
 * Ever dreamed of a mwcollect v3 botnet? ;)
 *
 * $Id: log-irc.h 155 2005-10-11 18:46:02Z oxff $
 *
 */
 
#ifndef __MWCMOD_LOG_IRC_H
#define __MWCMOD_LOG_IRC_H

#include <mwcollect/core.h>
using namespace mwccore;

#include <string>
using namespace std;



class IrcSubscription;

class IrcModule : public Module, NetworkSubscriptionFactory, LogFacility
{
public:
	IrcModule() { }
	
	virtual bool start();
	virtual void loop();
	virtual void stop();
	
	virtual void assignConfiguration(Configuration * pConfiguration) { m_pConfiguration = pConfiguration; }
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; }
	
	virtual NetworkSubscription * createNetworkSubscription(Socket * pSocket);
	virtual void freeNetworkSubscription(NetworkSubscription * pSubscription);
	
	virtual void log(LogTag ltLevel, LogMessage * pMessage);
	bool setTag(const char * szTag);
	
	void connectionLost();
	
protected:
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
	
	IrcSubscription * m_pSubscription;
	
	LogTagPattern m_ltpLimit;
	
	unsigned long m_ulNextConnect;
};

class IrcSubscription : public NetworkSubscription
{
public:
	IrcSubscription(Socket * pSocket, IrcModule * pIrcFactory, Configuration * pConfig, MalwareCollector * pCollector)
	{ m_pSocket = pSocket; m_pIrcFactory = pIrcFactory; m_pConfiguration = pConfig; m_pInChannel = false; m_pCollector = pCollector; }
	
	virtual void connectionClosed();
	virtual void connectionEtablished();
	virtual void incomingData(unsigned char * pucData, unsigned int nLength);
	
	virtual ConsumptionLevel consumptionLevel() { return CL_OVERTAKE; }
	
	void quitServer();
	void log(LogTag ltTag, const char * szMessage);
	
protected:
	void parseTraffic();
	void parseLine(const char * szLine);
	void parseMessage(const char * szOrigin, const char * szDestination, const char * szMessage);
	
protected:
	Socket * m_pSocket;
	IrcModule * m_pIrcFactory;
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
	
	string sBuffer;
	
	bool m_pInChannel;
};

#endif // __MWCMOD_LOG_IRC_H
