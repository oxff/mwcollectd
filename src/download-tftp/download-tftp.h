/*
 * Download module for Trivial File Transfer Protocol (TFTP)
 * I hate all those stupid fucking bot authors using TFTP.
 *
 * $Id: download-tftp.h 212 2005-11-06 17:26:33Z oxff $
 *
 */
 
#ifndef __MWCMOD_DOWNLOADTFTP_H
#define __MWCMOD_DOWNLOADTFTP_H

#include <mwcollect/core.h>
using namespace mwccore;

#include <string>

class DownloadTftpModule : public Module, public NetworkSubscriptionFactory, public Downloader
{
public:	
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfiguration = pConfig; };
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; };
	
	virtual bool start();
	virtual void stop();
	
	virtual NetworkSubscription * createNetworkSubscription(Socket * pSocket);
	virtual void freeNetworkSubscription(NetworkSubscription * pSubscription);
	
	virtual bool downloadFile(const char * szUrl, CorrelationId cid);
	
private:
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
	
protected:
	void sendRequest(const char * szHost, const char * szFileName, CorrelationId cid);
};

class TftpSubscription : public NetworkSubscription
{
public:
	TftpSubscription(Socket * pSocket, SubmissionDispatcher * pDispatcher)
	{ m_pSocket = pSocket; m_pSubmissionDispatcher = pDispatcher; m_cid = g_pLogManager->generateCorrelationIdentifier(); }
	
	virtual void incomingData(unsigned char * pucData, unsigned int nLength);
	
	virtual ConsumptionLevel consumptionLevel();
	virtual void connectionEtablished();
	virtual void connectionClosed();
	
	virtual void setUserData(void * pUser);
	
private:
	Socket * m_pSocket;
	SubmissionDispatcher * m_pSubmissionDispatcher;
	
	int m_iBlock;
	bool m_bFinished;
	
	std::string m_sDataBuffer;
	
	CorrelationId m_cid;
	
protected:
	void sendAcknowledgement();
};

#endif // __MWCMOD_DOWNLOADTFTP_H
