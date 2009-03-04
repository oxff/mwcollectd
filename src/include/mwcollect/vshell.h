/*
 * Virtual Shell Emulation Definitions.
 *
 * $Id: vshell.h 226 2005-11-08 20:36:26Z oxff $
 */

#ifndef __MWCCORE_VSHELL_H
#define __MWCCORE_VSHELL_H

#include "core.h"

#include <list>
#include <string>
#include <map>
#include <time.h>

namespace mwccore
{
	enum FileType
	{
		FT_UNKNOWN = 0,
		FT_TEXT,
		FT_BINARY,
	};

	#define SHELL_PROMPT "C:\\Documents and Settings\\Administrator> "	
	#define SHELL_BANNER "Microsoft Windows XP [Version 5.1.2600]\n(C) Copyright 1985-2001 Microsoft Corp.\n\n" SHELL_PROMPT
	
	struct ShellFile
	{
		FileType ftType;
		std::string sContent;
		char * szFileName;
	};
	
	
	
	class ShellManager;
	
	class VirtualShell
	{
	public:
		VirtualShell(ShellManager * pManager)
		{ m_pManager = pManager; m_cid = g_pLogManager->generateCorrelationIdentifier(); }
		VirtualShell(ShellManager * pManager, CorrelationId cid)
		{ m_pManager = pManager; m_cid = cid; }
		~VirtualShell();
		
		bool touchFile(const char * szFileName, FileType ftType);
		bool appendFile(const char * szFileName, const char * szData, unsigned int nLength);
		const char * getFileContent(const char * szFileName, unsigned int * pnLength);
		bool purgeFile(const char * szFileName);
		bool hasFile(const char * szFileName);
		
		CorrelationId correlationId()
		{ return m_cid; }
		void setCorrelationId(CorrelationId cid)
		{ m_cid = cid; }
		
	private:
		std::list<ShellFile> m_lsfFiles;
		
		ShellManager * m_pManager;
		CorrelationId m_cid;
		
	protected:
		static bool filenamesEqual(const char * szFileOne, const char * szFileTwo);
	};
	
	class ShellParser
	{
	public:
		virtual bool parseCommand(const char * szLine, VirtualShell * pShell) = 0;
	};
	
	
	struct ShellMapping
	{
		unsigned short usListenPort;
		unsigned long ulRemoteHost;
	};
	
	struct ShellMappingInfo
	{
		CorrelationId cid;
		unsigned long ulTimeout;
	};
	
	struct ShellMappingComparator
	{
		bool operator()(const ShellMapping a, const ShellMapping b)
		{
			if(a.usListenPort != b.usListenPort)
				return a.usListenPort < b.usListenPort;
				
			return a.ulRemoteHost < b.ulRemoteHost;
		}
	};
	
	
	class ShellNetworking : public NetworkSubscriptionFactory, NetworkSubscription
	{
	public:
		ShellNetworking() { m_pShell = 0; }
		ShellNetworking(Socket * pSocket, MalwareCollector * pCollector);
		~ShellNetworking() { if(m_pShell) { delete m_pShell; } }
		
		virtual NetworkSubscription * createNetworkSubscription(Socket * pSocket)
		{ return new ShellNetworking(pSocket, m_pCollector); }
		virtual void freeNetworkSubscription(NetworkSubscription * p)
		{ delete ((ShellNetworking *) p); }
		
		virtual void connectionEtablished();
		virtual void connectionClosed();
		virtual void incomingData(unsigned char * pucData, unsigned int nLength);
		virtual ConsumptionLevel consumptionLevel() { return m_bDrop ? CL_DROP : CL_OVERTAKE; }
		
		void setCollector(MalwareCollector * pCollector)
		{ m_pCollector = pCollector; }
		
		virtual void setUserData(void * pData);
		
	protected:
		void splitCommand(const char * szLong, VirtualShell * pShell);
		
		void checkTimeouts();
		
	private:
		MalwareCollector * m_pCollector;
		Socket * m_pSocket;
		VirtualShell * m_pShell;
		bool m_bDrop;
		
		CorrelationId m_cid;
		std::string m_sBuffer;
		bool m_bReverse;
	
		static std::map<ShellMapping, ShellMappingInfo, ShellMappingComparator> m_mCIDs;
		
		friend class ShellManager;
	};
	
	class ShellManager
	{
	public:
		ShellManager(MalwareCollector * pCollector)
		{ m_pCollector = pCollector; m_lpParsers.begin(); m_snFactory.setCollector(pCollector); m_ulNextTimeoutCheck = time(0); }
		
		void registerParser(ShellParser * pParser);
		void unregisterParser(ShellParser * pParser);
		
		bool bindShell(unsigned short usPort, unsigned long ulRemoteHost, CorrelationId cid);
		bool reverseShell(unsigned long ulHost, unsigned short usReversePort, CorrelationId cid);
		
		bool parseCommand(const char * szLine, VirtualShell * pShell);
		
		void loop();
		
	protected:
		MalwareCollector * m_pCollector;
		ShellNetworking m_snFactory;
		
		unsigned long m_ulNextTimeoutCheck;
		
		std::list<ShellParser *> m_lpParsers;
	};
}

#endif //__MWCCORE_VSHELL_H
