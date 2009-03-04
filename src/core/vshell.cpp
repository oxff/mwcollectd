/*
 * mwcollect Virtual Shell Emulation Coordination Implementation
 * $Id: vshell.cpp 306 2006-02-07 14:04:41Z oxff $
 *
 * `And it's making me wanna dance.'
 *
 */

#include <mwcollect/core.h>
#include <time.h>
#include <string>

namespace mwccore
{
	void ShellManager::registerParser(ShellParser * pParser)
	{
		m_lpParsers.push_back(pParser);
	}
	
	void ShellManager::unregisterParser(ShellParser * pParser)
	{
		m_lpParsers.remove(pParser);
	}
	
	bool ShellManager::parseCommand(const char * szLine, VirtualShell * pShell)
	{
		while(* szLine == ' ')
			++ szLine;
			
		if(!strncasecmp(szLine, "cmd.exe /c ", 11))
			szLine += 11;			
		else if(!strncasecmp(szLine, "cmd.exe /k ", 11))
			szLine += 11;			
		else if(!strncasecmp(szLine, "cmd /c ", 7))
			szLine += 7;			
		else if(!strncasecmp(szLine, "cmd /k ", 7))
			szLine += 7;			
		else if(!strncasecmp(szLine, "START ", 5))
			szLine += 5;
			
		char * szMyLine = strdup(szLine);
		char * szWalk = szMyLine + strlen(szMyLine) - 1;
		
		while(* szWalk == ' ' && szWalk > szMyLine)
		{
			* szWalk = 0;
			--szWalk;
		}
			
		for(std::list<ShellParser *>::iterator i = m_lpParsers.begin(); i != m_lpParsers.end(); ++i)
			if((* i)->parseCommand(szMyLine, pShell))
			{
				free(szMyLine);
				
				return true;
			}
	
		LOG(LT_STATUS | LT_LEVEL_CRITICAL | LT_INTHEWILD, "Unknown shell command \"%s\"!", szMyLine);
		free(szMyLine);
		
		return false;
	}
	
	bool ShellManager::bindShell(unsigned short usPort, unsigned long ulRemoteHost, CorrelationId cid)
	{
		ShellMapping smMapping;
		ShellMappingInfo smiInfo;
		
		smMapping.ulRemoteHost = ulRemoteHost;
		smMapping.usListenPort = usPort;
		
		smiInfo.cid = cid;
		smiInfo.ulTimeout = time(0) + 30;
		
		m_snFactory.m_mCIDs[smMapping] = smiInfo;
		
		return m_pCollector->getNetworkCore()->registerSubscriber(usPort, &m_snFactory, false, 0, true);
	}
	
	bool ShellManager::reverseShell(unsigned long ulHost, unsigned short usReversePort, CorrelationId cid)
	{
		void * pCID = malloc(sizeof(cid));
		
		memcpy(pCID, &cid, sizeof(cid));		
		return m_pCollector->getNetworkCore()->connectSocket(&m_snFactory, ulHost, usReversePort, pCID);		
	}
	
	void ShellManager::loop()
	{
		unsigned long ulTime = time(0);
		
		if(m_ulNextTimeoutCheck >= ulTime)
		{
			m_snFactory.checkTimeouts();
			
			m_ulNextTimeoutCheck += 15;
		}
	}
	
	
	
	bool VirtualShell::touchFile(const char * szFileName, FileType ftType)
	{
		for(std::list<ShellFile>::iterator i = m_lsfFiles.begin(); i != m_lsfFiles.end(); ++i)
			if(filenamesEqual(szFileName, i->szFileName))
				return false;
	
		ShellFile sfFile;
		
		sfFile.ftType = ftType;
		sfFile.szFileName = strdup(szFileName);
		
		m_lsfFiles.push_back(sfFile);
		return true;
	}
	
	bool VirtualShell::appendFile(const char * szFileName, const char * szData, unsigned int nLength)
	{
		for(std::list<ShellFile>::iterator i = m_lsfFiles.begin(); i != m_lsfFiles.end(); ++i)
			if(filenamesEqual(szFileName, i->szFileName))
			{
				i->sContent.append(szData, nLength);
				
				return true;
			}
			
		return false;
	}
	
	const char * VirtualShell::getFileContent(const char * szFileName, unsigned int * pnLength)
	{
		for(std::list<ShellFile>::iterator i = m_lsfFiles.begin(); i != m_lsfFiles.end(); ++i)
			if(filenamesEqual(szFileName, i->szFileName))
			{
				if(pnLength)
					* pnLength = i->sContent.size();
				
				return i->sContent.c_str();
			}
			
		return 0;
	}
	
	bool VirtualShell::purgeFile(const char * szFileName)
	{
		for(std::list<ShellFile>::iterator i = m_lsfFiles.begin(); i != m_lsfFiles.end(); ++i)
			if(filenamesEqual(szFileName, i->szFileName))
			{
				free(i->szFileName);
				m_lsfFiles.erase(i);
				
				return true;
			}
			
		return false;
	}
	
	bool VirtualShell::hasFile(const char * szFileName)
	{
		for(std::list<ShellFile>::iterator i = m_lsfFiles.begin(); i != m_lsfFiles.end(); ++i)
			if(filenamesEqual(szFileName, i->szFileName))				
				return true;
			
		return false;
	}
	
	bool VirtualShell::filenamesEqual(const char * szOne, const char * szTwo)
	{
		// TODO FIXME improve
		
		while(* szOne && * szTwo)
		{
			if(* szOne == ' ' || * szOne == '/' || * szOne == '\\')
			{
				++ szOne;
				continue;
			}
			
			if(* szTwo == ' ' || * szTwo == '/' || * szTwo == '\\')
			{
				++ szTwo;
				continue;
			}
			
			if(* szTwo != * szOne)
				return false;
				
			++ szOne; ++ szTwo;
		}
		
		if(* szOne || * szTwo)
			return false;
		
		return true;
	}
	
	VirtualShell::~VirtualShell()
	{
		for(std::list<ShellFile>::iterator i = m_lsfFiles.begin(); i != m_lsfFiles.end(); ++i)
			free(i->szFileName);
	}
	
	
	
	ShellNetworking::ShellNetworking(Socket * pSocket, MalwareCollector * pCollector)
	{
		m_pCollector = pCollector;
		m_pSocket = pSocket;
		m_pShell = new VirtualShell(m_pCollector->getShellManager());
		m_cid = g_pLogManager->generateCorrelationIdentifier();
		
		m_bDrop = false;
		
		m_bReverse = false;
	}
	
	void ShellNetworking::setUserData(void * pData)
	{
		memcpy(&m_cid, pData, sizeof(m_cid));
		free(pData);
		
		m_bReverse = true;
	}
	
	
	
	std::map<ShellMapping, ShellMappingInfo, ShellMappingComparator> ShellNetworking::m_mCIDs;
	
	void ShellNetworking::connectionEtablished()
	{
		m_pSocket->sendData((unsigned char *) SHELL_BANNER, sizeof(SHELL_BANNER));
		
		{
			std::map<ShellMapping, ShellMappingInfo, ShellMappingComparator>::iterator iMatch;
			unsigned long ulLocalHost;
			unsigned short usLocalPort = 0;
			ShellMapping smMapping;
			
			m_pCollector->getNetworkCore()->getLocalAddress(this, &ulLocalHost, &usLocalPort);
			
			smMapping.usListenPort = usLocalPort;
			smMapping.ulRemoteHost = m_ulRemoteHost;

			if((iMatch = m_mCIDs.find(smMapping)) != m_mCIDs.end())
			{
				m_pShell->setCorrelationId(iMatch->second.cid);
				m_cid = iMatch->second.cid;
				
				m_mCIDs.erase(iMatch);
			}
			else
			{
				m_pShell->setCorrelationId(m_cid);
				
				DEBUG("Found no CID mapping for bindshell on :%hu from %08x, using new CID.", usLocalPort, m_ulRemoteHost);
			}
		}
		
		if(!m_bReverse)		
		{			
			GenericClassfulLogMessage lmMessage = GenericClassfulLogMessage("New shell connection to bind shell!", m_cid);
			
			lmMessage.setString("classification.text", "New shell connection to bind shell");
			
			lmMessage.setAddress("source(0).node.address(0).address", m_ulRemoteHost);
			lmMessage.setInteger("source(0).service.port", m_usRemotePort);
			
			lmMessage.setString("assessment.impact.severity", "medium");
			lmMessage.setString("assessment.impact.completion", "succeeded");
			lmMessage.setString("assessment.impact.type", "admin");
			
			{
				unsigned long ulAddress;
				unsigned short usPort;
				
				m_pCollector->getNetworkCore()->getLocalAddress(this, &ulAddress, &usPort);					
				lmMessage.setAddress("target(0).node.address(0).address", ulAddress);
				lmMessage.setInteger("target(0).service.port", usPort);
			}
			
			g_pLogManager->log(LT_STATUS | LT_NETWORK, &lmMessage);
		}
	}
	
	void ShellNetworking::connectionClosed()
	{
	}
	
	void ShellNetworking::incomingData(unsigned char * pucData, unsigned int nLength)
	{
		m_sBuffer.append((char *) pucData, nLength);
		
		if(m_sBuffer.find("\r") != m_sBuffer.npos)
		{
			if(!strcmp(m_sBuffer.substr(0, m_sBuffer.find("\r")).c_str(), "exit"))
				m_bDrop = true;
			else
			{
				splitCommand(m_sBuffer.substr(0, m_sBuffer.find("\r")).c_str(), m_pShell);
				
				m_pSocket->sendData((unsigned char *) SHELL_PROMPT, sizeof(SHELL_PROMPT));
			}
				
			m_sBuffer.erase(0, m_sBuffer.find("\r") + 1);
			
			if(m_sBuffer[0] == '\n')
				m_sBuffer.erase(0, 1);
		}
		else if(m_sBuffer.find("\n") != m_sBuffer.npos)
		{
			if(!strcmp(m_sBuffer.substr(0, m_sBuffer.find("\n")).c_str(), "exit"))
				m_bDrop = true;
			else
			{
				splitCommand(m_sBuffer.substr(0, m_sBuffer.find("\n")).c_str(), m_pShell);
				
				m_pSocket->sendData((unsigned char *) SHELL_PROMPT, sizeof(SHELL_PROMPT));
			}
				
			m_sBuffer.erase(0, m_sBuffer.find("\n") + 1);
		}
	}
	
	void ShellNetworking::splitCommand(const char * szLong, VirtualShell * pShell)
	{
		std::string sCommand;
		
		while(* szLong)
		{
			if(* szLong == '^' && * (szLong + 1) == '&')
			{
				sCommand.push_back('&');
				++ szLong;			
			}
			else if(* szLong == '&')
			{
				if(sCommand.size())
					m_pCollector->getShellManager()->parseCommand(sCommand.c_str(), pShell);
				
				sCommand.clear();
			}
			else
				sCommand.push_back(* szLong);
				
			++ szLong;
		}
		
		if(sCommand.size())
			m_pCollector->getShellManager()->parseCommand(sCommand.c_str(), pShell);
	}
	
	void ShellNetworking::checkTimeouts()
	{
		unsigned long ulTime = time(0);
		
		std::map<ShellMapping, ShellMappingInfo, ShellMappingComparator>::iterator next;
		
		for(std::map<ShellMapping, ShellMappingInfo, ShellMappingComparator>::iterator i = m_mCIDs.begin(); i != m_mCIDs.end(); i = next)
		{
			next = i;
			++next;
			
			if(i->second.ulTimeout > ulTime)
				m_mCIDs.erase(i);
		}
	}
}
