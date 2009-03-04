/*
 * Prelude IDS Sensor module
 * This module forwards special log messages asynchronously to a prelude-manager.
 *
 * $Id: log-prelude.h 235 2005-11-10 18:05:33Z oxff $
 *
 */
 
#ifndef __MWCMOD_LOGPRELUDE_H
#define __MWCMOD_LOGPRELUDE_H

#include <mwcollect/core.h>
using namespace mwccore;

#include <libprelude/prelude.h>
#include <map>
#include <list>



struct CorrelationIdComparator
{
	bool operator()(const CorrelationId a, const CorrelationId b) const
	{
		return a < b;
	}
};

struct CorrelationEntity
{
	std::list<unsigned long long> lullPreludeIds;
	
	unsigned long ulLastAction;
};

class PreludeCorrelator
{
public:
	PreludeCorrelator(unsigned long ulTimeout);

	void addMessage(CorrelationId cid, unsigned long long ullPreludeId);
	void flushChain(CorrelationId cid, prelude_client_t * pClient);
	
	void checkTimeouts(prelude_client_t * pClient);
	
protected:
	inline void writeCorrelationAlert(prelude_client_t * pClient, CorrelationEntity * pEntity);
	
private:
	std::map<CorrelationId, CorrelationEntity, CorrelationIdComparator> m_mChains;
	unsigned long m_ulTimeout;
};



class PreludeMessage : public GenericClassfulReceiver
{
public:
	PreludeMessage(prelude_client_t * pPreludeClient);
	~PreludeMessage();
	
	virtual void setProperty(const char * szProperty, const unsigned char * pucValue, unsigned int nValueLength);
	virtual void setCorrelationIdentifier(CorrelationId cid)
	{ m_cid = cid; }
	
	CorrelationId getCorrelationIdentifier()
	{ return m_cid; }
	unsigned long long getPreludeIdentifier()
	{ return m_ullPreludeId; }
	
	
	idmef_message_t * getIDMEF()
	{ return m_pMessage; }
	
protected:
	void prepareAlert();
	
private:
	idmef_message_t * m_pMessage;
	idmef_alert_t * m_pAlert;
	prelude_client_t * m_pPreludeClient;
	CorrelationId m_cid;
	unsigned long long m_ullPreludeId;
};

class PreludeModule : public Module, public LogFacility
{
public:
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfiguration = pConfig; };
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; };
	
	virtual bool start();
	virtual void stop();
	virtual void loop();
	
	virtual void log(LogTag ltLevel, LogMessage * pMessage);
	
protected:
	bool initializeClientAnalyzer();
	
private:
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
	
	bool m_bCorrelate;
	PreludeCorrelator * m_pCorrelator;
	unsigned long m_ulLastCorrelationCheck;
	
	prelude_client_t * m_pPreludeClient;
};

#endif // __MWCMOD_LOGPRELUDE_H
