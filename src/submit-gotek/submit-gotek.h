/*
 * G.O.T.E.K. Submission Module
 * Submission module that submits files to a gotekd daemon (-> Alliance!).
 *
 * $Id: submit-gotek.h 276 2006-01-07 18:33:36Z oxff $
 *
 * `Here in your arms I gonna stay, there's no better way to stand today.'
 *	-- Rocco - Counting the Days
 *
 */
 
#ifndef __MWCMOD_SUBMITGOTEK_H
#define __MWCMOD_SUBMITGOTEK_H

#include <mwcollect/core.h>
#include <string>
#include <string.h>
#include <assert.h>

using namespace mwccore;


struct GotekSample
{
	unsigned char * pucSample;
	unsigned int nSampleSize;
	
	unsigned long long ullLogID;
	
	unsigned char pucHash[64];
};

typedef struct
{
	unsigned char pucUser[32];
	unsigned char * pucKey;
	unsigned int nKeySize;
} auth_info_t;


class SubmitterModule;

class GotekUploadCoordinator : public NetworkSubscriptionFactory
{
public:
	virtual NetworkSubscription * createNetworkSubscription(Socket * pSocket);
	virtual void freeNetworkSubscription(NetworkSubscription * pSubscription);
	
	void uploadSample(GotekSample * pSample);
	
	MalwareCollector * m_pCollector;
	SubmitterModule * m_pTop;
	
private:
	GotekSample m_gsCurrentSample;
};

// forward declaration for SubmitterModule's friend definition
class GotekControlSubscription;

class SubmitterModule : public Module, Submitter, NetworkSubscriptionFactory
{
public:	
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfiguration = pConfig; };
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; m_gucUpload.m_pCollector = pCollector; };
	
	virtual bool start();
	virtual void loop();
	virtual void stop();
	
	virtual bool submitData(const unsigned char * pData, unsigned int nLength, CorrelationId cid);
	
	virtual NetworkSubscription * createNetworkSubscription(Socket * pSocket);
	virtual void freeNetworkSubscription(NetworkSubscription * pSubscription);
	
	void lostConnection();
	
protected:
	bool connectServer(NetworkSubscriptionFactory * pFactory);
	void connectionClosed();
	
private:
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
	
	unsigned char * m_pucKey;
	unsigned int m_nKeySize;
	
	bool m_bLinkPrelude;
	
	bool m_bConnected;
	unsigned long m_ulNextConnect;
	
	GotekControlSubscription * m_pChild;
	GotekUploadCoordinator m_gucUpload;
	
	auth_info_t m_aiAuthInfo;
	
	friend class GotekControlSubscription;
	friend class GotekUploadCoordinator;
};


typedef enum
{
	GS_VIRGIN = 0,
	GS_PREAUTH,
	GS_INAUTH,
	GS_IDLE,
	
	GSC_AWAITING_RESPONSE,
} gotek_state_t;

class GotekSubscription : public NetworkSubscription
{
public:	
	virtual void incomingData(unsigned char * pucData, unsigned int nLength);
	
	virtual ConsumptionLevel consumptionLevel() { return m_bFaulty ? CL_DROP : CL_OVERTAKE; }
	virtual void connectionEtablished();
	
	virtual void gotekSessionEtablished() = 0;
	virtual bool incomingGotekData() = 0;
	
	virtual void subscriptionSuperseeded() { assert(false); }
	
protected:
	SubmitterModule * m_pTop;
	Socket * m_pSocket;
	auth_info_t m_aiAuthInfo;
	
	bool m_bFaulty;
	gotek_state_t m_gsState;
	
	std::string m_sBuffer;
	
	MalwareCollector * m_pCollector;
};

class GotekControlSubscription : public GotekSubscription
{
public:
	GotekControlSubscription(MalwareCollector * pC, Socket * pSocket, SubmitterModule * pTop, auth_info_t aiAuthInfo)
	{ m_pCollector = pC; m_pSocket = pSocket; m_bFaulty = false; m_pTop = pTop; m_aiAuthInfo = aiAuthInfo; }
	
	virtual void connectionClosed();
	virtual bool incomingGotekData();
	virtual void gotekSessionEtablished();
	
	bool addRequest(GotekSample * pSample);
	
private:
	std::list<GotekSample> m_lgsPendingSamples;
};

class GotekDataSubscription : public GotekSubscription
{
public:
	GotekDataSubscription(MalwareCollector * pC, Socket * pSocket, GotekUploadCoordinator * pTop, auth_info_t aiAuthInfo, GotekSample * pSample)
	{ m_pCollector = pC; m_pSocket = pSocket; m_bFaulty = false; m_pCoordinator = pTop; m_aiAuthInfo = aiAuthInfo; m_gsSample = * pSample; }
	
	virtual void gotekSessionEtablished();
	virtual bool incomingGotekData()
	{ LOG(LT_STATUS | LT_LEVEL_CRITICAL, "G.O.T.E.K. Server sent data on upload connection!"); m_bFaulty = true; }
	
	virtual void connectionLost();
	
private:
	GotekSample m_gsSample;
	GotekUploadCoordinator * m_pCoordinator;
};

#endif // __MWCMOD_SUBMITGOTEK_H
