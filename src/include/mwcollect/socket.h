/*
 * $Id: socket.h 175 2005-10-26 17:52:47Z oxff $
 *
 */
 
#ifndef __MWCCORE_SOCKET_H
#define __MWCCORE_SOCKET_H

namespace mwccore
{
	class NetworkCore;
	class NetworkSubscription;
	
	class Socket
	{
	public:
		Socket(NetworkCore * pCore, int iSocket, unsigned long ulRemoteHost = 0, unsigned short usRemotePort = 0)
		{ m_pCore = pCore; m_iSocket = iSocket; m_ulHost = ulRemoteHost; m_usPort = usRemotePort; m_pOwner = 0; }
	
		virtual bool sendData(const unsigned char * pucData, unsigned int nLength)
		{ return m_pCore->sendData(m_pOwner, m_iSocket, pucData, nLength, m_ulHost, m_usPort); }
		virtual bool sendDatagram(const unsigned char * pucData, unsigned int nLength, unsigned long ulHost, unsigned short usPort)
		{ return m_pCore->sendData(m_pOwner, m_iSocket, pucData, nLength, ulHost, usPort); }
		
		void setOwner(NetworkSubscription * pOwner)
		{ m_pOwner = pOwner; }
		
	private:
		NetworkCore * m_pCore;
		NetworkSubscription * m_pOwner;
		int m_iSocket;
		
		unsigned long m_ulHost;
		unsigned short m_usPort;
	};
}

#endif // __MWCCORE_SOCKET_H
