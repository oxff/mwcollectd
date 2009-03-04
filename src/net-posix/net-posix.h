/*
 * Definition file for generic POSIX compliant Network Interface providing abstraction to socket(..) and friends.
 *
 * $Id: net-posix.h 127 2005-09-28 05:50:41Z oxff $
 *
 */
 
#ifndef __MWCMOD_NETPOSIX_H
#define __MWCMOD_NETPOSIX_H

#include <mwcollect/core.h>

#include <string>
#include <map>

using namespace mwccore;



#define SF_NONE 0
#define SF_READDATA_PRESENT 1
#define SF_ERROR 2
#define SF_CLOSED 4

struct SocketInfo
{
	SocketInfo() { cFlags = SF_NONE; }
	std::string sSendBuffer;
	
	char cFlags;
};

struct SocketComparator
{
	bool operator()(int a, int b) const
  	{
  		return a < b;
  	}
};


// putting this into two classes is not neccessary by design
// but makes code more readable
class PosixInterface : public NetworkInterface
{
public:
	PosixInterface(Configuration * pConfig);
	~PosixInterface();

	virtual int createDatagramSocket(unsigned long ulBindAddress, unsigned short usLocalPort);
	virtual int createStreamServer(unsigned long ulBindAddress, unsigned short usPort);
	virtual int createStreamClient(unsigned long ulRemoteAddress, unsigned short usRemotePort);
	virtual bool closeSocket(int iSocket);
	
	virtual int receiveData(int iSocket, unsigned char * pucBuffer, int iBufferSize)
	{ return receiveData(iSocket, pucBuffer, iBufferSize, 0, 0); }
	
	virtual int sendData(int iSocket, const unsigned char * pucBuffer, int iBufferSize)
	{ return sendData(iSocket, pucBuffer, iBufferSize, 0, 0); }
	
	virtual int receiveData(int iSocket, unsigned char * pucBuffer, int iBufferSize, unsigned long * pulSourceAddress, unsigned short * pusSourcePort);
	virtual int sendData(int iSocket, const unsigned char * pucBuffer, int iBufferSize, unsigned long ulToHost, unsigned short usToPort);
	virtual bool acceptConnection(int iSocket, Connection * pConnection);
	
	virtual bool isReadable(int iSocket);
	virtual bool isWriteable(int iSocket);
	virtual bool isClosed(int iSocket);
	virtual bool isErroneous(int iSocket);
	
	virtual bool waitForEvents(int iWait);
	
	virtual void getLocalName(int iSocket, unsigned long * pulHost, unsigned short * pusPort);
	
	virtual unsigned long resolveHostname(const char * szHostName);
	
	void flush(); // since we support send buffering, we'll block here until all queues are empty
	
protected:
	Configuration * m_pConfiguration;
	
	std::map<int, SocketInfo> m_msiSocketInfos;
};


class NetPosixModule : public Module
{
public:
	NetPosixModule();
	virtual ~NetPosixModule();
	
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfiguration = pConfig; }
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; }
	
	virtual bool start();
	virtual void stop();
	
protected:
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;
	
	PosixInterface * m_pInterface;
};

#endif
