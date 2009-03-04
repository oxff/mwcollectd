/*
 * Actual Network Interface implementation (wrapper around socket() etc)
 *
 * $Id: interface.cpp 303 2006-02-06 12:15:22Z oxff $
 *
 * `Sie hat nurnoch wenige Tage und weiss es genau, glaub mir, sie kann nicht mehr.'
 * `Sie lieg am Boden und ich lass sie sterben, denn ich weiss, so soll es sein.'
 *	Xavier Naidoo -- Ich lass sie sterben
 *
 */
 
#include "net-posix.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

PosixInterface::PosixInterface(Configuration * pConfig)
{
	m_pConfiguration = pConfig;
}

PosixInterface::~PosixInterface()
{
	// deinitialize yo momma 'ere
}


int PosixInterface::createDatagramSocket(unsigned long ulBindAddress, unsigned short usLocalPort)
{
	int iSocket;
	struct sockaddr_in addrLocal;
	
	addrLocal.sin_family = AF_INET;
	addrLocal.sin_addr.s_addr = ulBindAddress;
	addrLocal.sin_port = htons(usLocalPort);
	
	if((iSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;
	
	if(bind(iSocket, (struct sockaddr *) &addrLocal, sizeof(addrLocal)) < 0)
	{
		close(iSocket);
		
		g_pLogManager->log(LT_STATUS | LT_LEVEL_CRITICAL, "Binding a socket to %s:%u failed: %s!", inet_ntoa(addrLocal.sin_addr), htons(addrLocal.sin_port), strerror(errno));
		
		return -1;
	}
	
	m_msiSocketInfos[iSocket] = SocketInfo();
	
	return iSocket;
}

int PosixInterface::createStreamServer(unsigned long ulBindAddress, unsigned short usLocalPort)
{
	int iSocket, iReuseAddress = 1;
	struct sockaddr_in addrLocal;
	
	addrLocal.sin_family = AF_INET;
	addrLocal.sin_addr.s_addr = ulBindAddress;
	addrLocal.sin_port = htons(usLocalPort);
	
	if((iSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;
		
	if(setsockopt(iSocket, SOL_SOCKET, SO_REUSEADDR, &iReuseAddress, sizeof(iReuseAddress)) < 0)
	{
		close(iSocket);
		
		g_pLogManager->log(LT_STATUS | LT_LEVEL_CRITICAL, "Setting SO_REUSEADDR for %s:%u failed: %s!", inet_ntoa(addrLocal.sin_addr), htons(addrLocal.sin_port), strerror(errno));
		
		return -1;
	}
		
	if(bind(iSocket, (struct sockaddr *) &addrLocal, sizeof(addrLocal)) < 0)
	{
		close(iSocket);
		
		g_pLogManager->log(LT_STATUS | LT_LEVEL_CRITICAL, "Binding a socket to %s:%u failed: %s!", inet_ntoa(addrLocal.sin_addr), htons(addrLocal.sin_port), strerror(errno));
		
		return -1;
	}
	
	if(listen(iSocket, m_pConfiguration->getLong("tcp:server-backlog", 16)) < 0)
	{
		close(iSocket);
		
		return -1;
	}
	
	m_msiSocketInfos[iSocket] = SocketInfo();
	
	return iSocket;
}

int PosixInterface::createStreamClient(unsigned long ulRemoteAddress, unsigned short usRemotePort)
{
	int iSocket;
	struct sockaddr_in addrRemote;
	
	struct timeval tvTimeout = { 2, 500 }; // fairly long enough
	struct timeval tvNoTimeout = { 0, 0 }; // after connection, we handle timing out ourselves
	
	addrRemote.sin_family = AF_INET;
	addrRemote.sin_addr.s_addr = ulRemoteAddress;
	addrRemote.sin_port = htons(usRemotePort);
	
	if((iSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;
		
	if(setsockopt(iSocket, SOL_SOCKET, SO_RCVTIMEO, &tvTimeout, sizeof(tvTimeout)) < 0)
		return -1;
		
	DEBUG("net-posix connecting to %s:%u...", inet_ntoa(addrRemote.sin_addr), htons(addrRemote.sin_port));
		
	if(connect(iSocket, (struct sockaddr *) &addrRemote, sizeof(addrRemote)) < 0)
	{
		LOG(LT_NETWORK | LT_LEVEL_CRITICAL | LT_STATUS, "Failed to connect to %s:%u!", inet_ntoa(addrRemote.sin_addr), htons(addrRemote.sin_port));
		
		close(iSocket);
		
		return -1;
	}
	
	if(setsockopt(iSocket, SOL_SOCKET, SO_RCVTIMEO, &tvNoTimeout, sizeof(tvNoTimeout)) < 0)
		return -1;
	
	m_msiSocketInfos[iSocket] = SocketInfo();
	
	return iSocket;
}

bool PosixInterface::closeSocket(int iSocket)
{
	// calling this for an undefined socket shouldn't be a real problem but is probably caused by a bug
	assert(m_msiSocketInfos.find(iSocket) != m_msiSocketInfos.end());
	
	m_msiSocketInfos.erase(iSocket);
	return close(iSocket) >= 0;
}


int PosixInterface::receiveData(int iSocket, unsigned char * pucBuffer, int iBufferSize, unsigned long * pulSourceAddress, unsigned short * pusSourcePort)
{
	assert(iBufferSize > 0);
	assert(m_msiSocketInfos.find(iSocket) != m_msiSocketInfos.end());
	
	m_msiSocketInfos[iSocket].cFlags &= ~SF_READDATA_PRESENT;
	
	if(pulSourceAddress && pusSourcePort)
	{
		struct sockaddr_in addrFrom;
		socklen_t iFromLen = sizeof(addrFrom);
		int iResult = recvfrom(iSocket, (char *) pucBuffer, iBufferSize, 0, (struct sockaddr *) &addrFrom, &iFromLen);
		
		if(iResult)
		{
			* pulSourceAddress = addrFrom.sin_addr.s_addr;
			* pusSourcePort = ntohs(addrFrom.sin_port);
		}
		
		return iResult;
	}
	else
		return recv(iSocket, (char *) pucBuffer, iBufferSize, 0);
}

int PosixInterface::sendData(int iSocket, const unsigned char * pucBuffer, int iBufferSize, unsigned long ulToHost, unsigned short usToPort)
{
	int iResult;
	
	assert(iBufferSize > 0);
	assert(m_msiSocketInfos.find(iSocket) != m_msiSocketInfos.end());
	
	if(ulToHost && usToPort)
	{
		struct sockaddr_in addrTo;
		
		addrTo.sin_family = AF_INET;
		addrTo.sin_addr.s_addr = ulToHost;
		addrTo.sin_port = htons(usToPort);
		
		iResult = sendto(iSocket, (char *) pucBuffer, iBufferSize, 0, (struct sockaddr *) &addrTo, sizeof(addrTo));
		return iResult; // no send buffering for udp supported since multiple dest addresses may be mixed randomly on one socket
	}
	else
		iResult = send(iSocket, (char *) pucBuffer, iBufferSize, 0);

	if(!iResult)
		return iResult;
	else if(iResult <= -1)
	{
		if(errno == EAGAIN || errno == EWOULDBLOCK)
			m_msiSocketInfos[iSocket].sSendBuffer.append((char *) pucBuffer, iBufferSize);
		else
			return -1;
	}
	else if(iResult < iBufferSize)
	{
		DEBUG("Send buffering took place, buffered %u bytes.", iBufferSize - iResult);
		
		m_msiSocketInfos[iSocket].sSendBuffer.append((char *) pucBuffer + iResult, iBufferSize - iResult);
	}
	
	return iBufferSize;
}

bool PosixInterface::acceptConnection(int iSocket, Connection * pConnection)
{
	int iNewSocket;
	struct sockaddr_in addrAddress;
	socklen_t iAddrSize = sizeof(addrAddress);
	
	assert(m_msiSocketInfos.find(iSocket) != m_msiSocketInfos.end());
	
	if(!m_msiSocketInfos[iSocket].cFlags & SF_READDATA_PRESENT)
		return false;
		
	m_msiSocketInfos[iSocket].cFlags &= ~SF_READDATA_PRESENT;
	
	if((iNewSocket = accept(iSocket, (struct sockaddr *) &addrAddress, &iAddrSize)) < 0)
		return false;
		
	pConnection->iSocket = iNewSocket;
	pConnection->ulSourceHost = (unsigned long) (addrAddress.sin_addr.s_addr);
	pConnection->usSourcePort = htons(addrAddress.sin_port);
	
	iAddrSize = sizeof(addrAddress);
	getsockname(iNewSocket, (struct sockaddr *) &addrAddress, &iAddrSize);	
	pConnection->ulDestinationHost = (unsigned long) (addrAddress.sin_addr.s_addr);
	pConnection->usDestinationPort = ntohs(addrAddress.sin_port);
	
	m_msiSocketInfos[iNewSocket] = SocketInfo();
	
	return true;
}


bool PosixInterface::isReadable(int iSocket)
{
	// this does not create a crash but consumes some memory more that will probably not be free'd
	// so treat it like an error in performance tests :)
	assert(m_msiSocketInfos.find(iSocket) != m_msiSocketInfos.end());
	
	// provoke a call to receiveData if ANY flag is present (return value indicates status to loop)
	return m_msiSocketInfos[iSocket].cFlags != SF_NONE;
}

bool PosixInterface::isWriteable(int iSocket)
{
	return true; // we can write on all sockets due to send buffering
}

bool PosixInterface::isClosed(int iSocket)
{
	assert(m_msiSocketInfos.find(iSocket) != m_msiSocketInfos.end());

	return m_msiSocketInfos[iSocket].cFlags & SF_CLOSED;
}

bool PosixInterface::isErroneous(int iSocket)
{
	assert(m_msiSocketInfos.find(iSocket) != m_msiSocketInfos.end());

	return m_msiSocketInfos[iSocket].cFlags & SF_ERROR;
}


bool PosixInterface::waitForEvents(int iWait)
{
	int iDescriptors = m_msiSocketInfos.size();
	struct pollfd * pDescriptors = (struct pollfd *) malloc(iDescriptors * sizeof(struct pollfd));
	int iResult, n = 0;
	
	for(std::map<int, SocketInfo>::iterator i = m_msiSocketInfos.begin(); i != m_msiSocketInfos.end(); ++i, ++n)
	{
		pDescriptors[n].fd = i->first;
		pDescriptors[n].events = POLLIN | POLLERR;
		
		if(i->second.sSendBuffer.size())
			pDescriptors[n].events |= POLLOUT;
		
		pDescriptors[n].revents = 0;
	}
	
	iResult = poll(pDescriptors, iDescriptors, iWait);
	
	if(iResult <= 0)
	{
		free(pDescriptors);
		
		if(iResult < 0)
			LOG(LT_LEVEL_CRITICAL | LT_ASSERT, "Call to poll failed: %s!", strerror(errno));
		
		return false;
	}
	
	n = 0;
	
	for(std::map<int, SocketInfo>::iterator i = m_msiSocketInfos.begin(); i != m_msiSocketInfos.end(); ++i, ++n)
	{		
		if(pDescriptors[n].revents & POLLERR)
			i->second.cFlags = SF_ERROR;
		else
		{
			i->second.cFlags = SF_NONE;
			
			if(pDescriptors[n].revents & POLLOUT)
			{
				int iResult = send(i->first, i->second.sSendBuffer.data(), i->second.sSendBuffer.size(), 0);
				
				if(iResult < 0)
					i->second.cFlags |= SF_ERROR;
				else if(!iResult)
					i->second.cFlags |= SF_CLOSED;
			}
			
			if(pDescriptors[n].revents & POLLIN)
				i->second.cFlags |= SF_READDATA_PRESENT;
		}
	}
	
	free(pDescriptors);
	
	return true;
}

void PosixInterface::getLocalName(int iSocket, unsigned long * pulHost, unsigned short * pusPort)
{
	struct sockaddr_in addrLocal;
	socklen_t iLength = sizeof(addrLocal);
	
	if(getsockname(iSocket, (struct sockaddr *) &addrLocal, &iLength) < 0)
	{
		DEBUG("getsockname failed.");
		
		return;
	}
		
	* pulHost = addrLocal.sin_addr.s_addr;
	* pusPort = ntohs(addrLocal.sin_port);
}

void PosixInterface::flush()
{
	// TODO implement
}


unsigned long PosixInterface::resolveHostname(const char * szHostName)
{
	struct hostent * pInfo;
	
	if(!(pInfo = gethostbyname(szHostName)))
		return 0;
		
	return * * ((unsigned long * *) pInfo->h_addr_list);	
}
