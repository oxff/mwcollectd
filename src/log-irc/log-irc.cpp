/*
 * IRC Logging module: lets you log into a chosen IRC network and provides basic control commands.
 * Ever dreamed of a mwcollect v3 botnet? ;)
 *
 * $Id: log-irc.cpp 299 2006-02-06 01:08:36Z oxff $
 *
 */
 
#include "log-irc.h"

#include <fnmatch.h>
#include <time.h>
#include <unistd.h>

extern "C"
{
	void * CreateInstance()
	{
		return new IrcModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (IrcModule *) pInstance;
	}
}


bool IrcModule::start()
{
	m_pSubscription = 0;
	m_ulNextConnect = 0;
	
	if(!m_ltpLimit.parsePattern(m_pConfiguration->getString(":pattern", "all")))
	{
		LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Could not parse log tag pattern \"%s\"!", m_pConfiguration->getString(":pattern", "all"));

		return false;
	}		
	
	if(!m_pCollector->getNetworkCore()->connectSocket(this, m_pCollector->getNetworkCore()->resolveHostname(m_pConfiguration->getString(":connection:host", "irc.freenode.org")), (unsigned short) m_pConfiguration->getLong(":connection:port", 6667)))
	{
		LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Connecting to IRC server failed.");
		
		return false;
	}
	
	g_pLogManager->registerLogFacility(this);
	
	return true;
}

void IrcModule::stop()
{
	g_pLogManager->unregisterLogFacility(this);
	
	if(m_pSubscription)
	{
		m_pSubscription->quitServer();
		m_pCollector->getNetworkCore()->closeSubscription(m_pSubscription);
	}
}


void IrcModule::freeNetworkSubscription(NetworkSubscription * pSubscription)
{
	if(m_pSubscription == pSubscription)
		connectionLost();
		
	delete (IrcSubscription *) pSubscription;
}

NetworkSubscription * IrcModule::createNetworkSubscription(Socket * pSocket)
{
	IrcSubscription * pSubscription = new IrcSubscription(pSocket, this, m_pConfiguration, m_pCollector);
	
	m_pSubscription = pSubscription;

	return pSubscription;
}

void IrcModule::loop()
{
	if(!m_pSubscription && time(0) >= m_ulNextConnect)
	{
		if(!m_pCollector->getNetworkCore()->connectSocket(this, m_pCollector->getNetworkCore()->resolveHostname(m_pConfiguration->getString(":connection:host", "irc.freenode.org")), (unsigned short) m_pConfiguration->getLong(":connection:port", 6667)))
		{
			LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Connecting to IRC server failed.");
			
			m_ulNextConnect = time(0) + 60;
		}
	}
}

void IrcModule::connectionLost()
{
	m_pSubscription = 0;
	
	m_ulNextConnect = time(0) + 30;
}



void IrcSubscription::incomingData(unsigned char * szData, unsigned int nLength)
{
	sBuffer.append((char *) szData, nLength);
	
	parseTraffic();
}

void IrcSubscription::connectionEtablished()
{
	DEBUG("Etablished connection to IRC server.");
	
	m_pCollector->getNetworkCore()->setSubscriptionTimeout(this, m_pConfiguration->getLong(":connection:timeout", 900));
	
	{
		char szHostNick[64];
		char * szHeaderBuffer;
		int iLength;
		
		gethostname(szHostNick, sizeof(szHostNick));
		
		iLength = asprintf(&szHeaderBuffer, "NICK %s\r\nUSER mwc-v3 0 0 :mwcollect " MWCD_VERSION "\r\n", m_pConfiguration->getString(":nick", szHostNick));
		m_pSocket->sendData((unsigned char *) szHeaderBuffer, iLength);
		free(szHeaderBuffer);
	}
}

void IrcSubscription::connectionClosed()
{
	LOG(LT_STATUS | LT_LEVEL_MEDIUM, "Lost connection to IRC server.");
	
	m_pIrcFactory->connectionLost();
}

void IrcSubscription::parseTraffic()
{
	int iPos = sBuffer.find("\r\n");
	
	if(iPos == sBuffer.npos)
		return;
		
	parseLine(sBuffer.substr(0, iPos).c_str());
	sBuffer.erase(0, iPos + 2);
	
	parseTraffic();
}

void IrcSubscription::parseLine(const char * szLine)
{
	char * szOrigin = 0;
	
	if(* szLine == ':')
	{
		int iLength = 0;
		const char * szWalk = szLine + 1;
		
		while(* szWalk != ' ' && * szWalk++)
			++ iLength;
			
		szOrigin = (char *) malloc(iLength + 1);
		strncpy(szOrigin, szLine + 1, iLength);
		szOrigin[iLength] = 0;
		
		szLine += iLength + 2;
	}
	
	if(!strncmp(szLine, "PING ", 5))
	{
		char * szResponse;
		int iLength;
		
		iLength = asprintf(&szResponse, "PONG %s\r\n", szLine + 5);
		m_pSocket->sendData((unsigned char *) szResponse, iLength);
		free(szResponse);
	}
	else if(!strncmp(szLine, "004 ", 4) || !strncmp(szLine, "005 ", 4) || !strncmp(szLine, "KICK ", 5))
	{
		char * szResponse;
		int iLength;
		
		if(!strncmp(szLine, "KICK ", 5))
		{
			m_pInChannel = false;
			
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Got kicked from IRC channel, reason: \"%s\"!", strchr(szLine + 5, ':') + 1);
		}
		
		if(m_pConfiguration->leafExists(":connection:channelkey"))
			iLength = asprintf(&szResponse, "JOIN %s %s\r\n", m_pConfiguration->getString(":connection:channel", "#mwcollect-demo"), m_pConfiguration->getString(":connection:channelkey", 0));
		else		
			iLength = asprintf(&szResponse, "JOIN %s\r\n", m_pConfiguration->getString(":connection:channel", "#mwcollect-demo"));
		m_pSocket->sendData((unsigned char *) szResponse, iLength);
		free(szResponse);
	}
	else if(!strncmp(szLine, "353 ", 4))
		m_pInChannel = true;
	else if(!strncmp(szLine, "PRIVMSG ", 8))
	{
		char * szDestination;
		
		{
			const char * szWork = szLine + 8;
			int iLength = 0;
			
			while(* szWork != ' ' && * szWork++)
				++iLength;
				
			szDestination = (char *) malloc(iLength + 1);
			memcpy(szDestination, szLine + 8, iLength);
			szDestination[iLength] = 0;
			
			parseMessage(szOrigin, szDestination, szLine + iLength + 8 + 2);
			free(szDestination);
		}
	}
	
	if(szOrigin)
		free(szOrigin);
}

void IrcSubscription::parseMessage(const char * szOrigin, const char * szDestination, const char * szMessage)
{
	char * szOriginNick;
	const char * szSendTo;
	
	{
		const char * szWalk = szOrigin;
		int iLength = 0;
		
		while(* szWalk != '!' && * szWalk++)
			++iLength;
			
		szOriginNick = (char *) malloc(iLength + 1);
		memcpy(szOriginNick, szOrigin, iLength);
		szOriginNick[iLength] = 0;
	}
	
	if(* szDestination == '#')
		szSendTo = szDestination;
	else
		szSendTo = szOriginNick;
	
	if(!strcmp(szMessage, "\x01VERSION\x01"))
	{
		char * szResponse;
		int iLength;
		
		iLength = asprintf(&szResponse, "PRIVMSG %s :\x01VERSION mwcollect " MWCD_VERSION "\x01\r\n", szOriginNick);
		m_pSocket->sendData((unsigned char *) szResponse, iLength);
		free(szResponse);
		
	}
	else if(!strcmp(szMessage, ".version"))
	{
		char * szResponse;
		int iLength;
		
		iLength = asprintf(&szResponse, "PRIVMSG %s :mwcollect " MWCD_VERSION " (" POSIX_FLAVOUR ") developed by Georg 'oxff' Wicherski\r\n", szSendTo);
		m_pSocket->sendData((unsigned char *) szResponse, iLength);
		free(szResponse);
	}
	else if(fnmatch(m_pConfiguration->getString(":admin:usermask", "*!*@*"), szOrigin, FNM_NOESCAPE | FNM_CASEFOLD) == 0)
	{ // requires hostmask match
		if(!strncmp(szMessage, ".op ", 4) && !strcmp(m_pConfiguration->getString(":admin:capabilities:chanop", "yes"), "yes"))
		{
			char * szMode;
			int iLength;
			
			iLength = asprintf(&szMode, "MODE %s +ov %s %s\r\n", szMessage + 4, szOriginNick, szOriginNick);
			m_pSocket->sendData((unsigned char *) szMode, iLength);
			
			free(szMode);
		}
		else if(!strcmp(szMessage, ".quit") && !strcmp(m_pConfiguration->getString(":admin:capabilities:quit-daemon", "yes"), "yes"))
		{
			LOG(LT_LEVEL_MEDIUM | LT_STATUS, "%s ordered mwcollect to quit.", szOrigin);
			
			m_pCollector->shutdown();
		}
		else if(!strncmp(szMessage, ".cto ", 5) && !strcmp(m_pConfiguration->getString(":admin:capabilities:quit-daemon", "yes"), "yes"))
		{
			LOG(LT_LEVEL_MEDIUM | LT_STATUS | LT_NETWORK, "Set overall connection timeout for new connections to %u seconds.", atoi(szMessage + 5));
			
			m_pCollector->getNetworkCore()->setConnectionTimeout(atoi(szMessage + 5));
		}
		else if(!strncmp(szMessage, ".load ", 6) && !strcmp(m_pConfiguration->getString(":admin:capabilities:load-modules", "yes"), "yes"))
		{
			// TODO implement
		}
		else if(!strncmp(szMessage, ".unload ", 8) && !strcmp(m_pConfiguration->getString(":admin:capabilities:load-modules", "yes"), "yes"))
		{
			// TODO implement
		}
		else if(!strncmp(szMessage, ".pattern ", 9))
		{
			char * szRender;
			int iLength;
			
			if(m_pIrcFactory->setTag(szMessage + 9))
				iLength = asprintf(&szRender, "PRIVMSG %s :Successfully set log tag pattern to \"%s\".\r\n", szSendTo, szMessage + 9);
			else
				iLength = asprintf(&szRender, "PRIVMSG %s :Could not parse log tag pattern \"%s\".\r\n", szSendTo, szMessage + 9);
			
			m_pSocket->sendData((unsigned char *) szRender, iLength);
			free(szRender);
		}
		
		// TODO .quit AND .load / .unload
	}
	
	free(szOriginNick);
}

void IrcSubscription::quitServer()
{
	m_pSocket->sendData((unsigned char *) "QUIT :http://www.mwcollect.org/\r\n", 32);
}


void IrcModule::log(LogTag ltTag, LogMessage * pMessage)
{
	if(!m_pSubscription)
		return;
		
	if(!m_ltpLimit.testAgainst(ltTag))
		return;

	char * szMessage = pMessage->renderString();
	
	m_pSubscription->log(ltTag, szMessage);
	free(szMessage);
}

void IrcSubscription::log(LogTag ltTag, const char * szMessage)
{
	if(!m_pInChannel)
		return;
		
	char * szRender;
	int iLength;
	const char * szPrefix = ":";
	
	if(ltTag & LT_INTHEWILD)
		szPrefix = ":\x03\x34";
	else if(ltTag & LT_LEVEL_CRITICAL)
		szPrefix = ":\x02";
	
	iLength = asprintf(&szRender, "PRIVMSG %s %s%s\r\n", m_pConfiguration->getString(":connection:channel", "#mwcollect-demo"), szPrefix, szMessage);
	m_pSocket->sendData((unsigned char *) szRender, iLength);
	free(szRender);
}

bool IrcModule::setTag(const char * szTag)
{
	return m_ltpLimit.parsePattern(szTag);
}
