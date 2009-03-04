/*
 * Transfer Shell Commands Module (`tftp[.exe]', `ftp[.exe]')
 * $Id: shell-transfer.cpp 307 2006-02-07 15:12:05Z oxff $
 *
 * Queen on the left side, Hardcore Heaven (not mine! :D) on the right side.
 */
 
#include "shell-transfer.h"
#include <string>
#include <ctype.h>
#include <stdlib.h>
#include <ctype.h>

extern "C"
{
	// wrappers around constructor and deconstructor to have nice dll interface
	
	void * CreateInstance()
	{
		return new ShellTransferModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (ShellTransferModule *) pInstance;
	}
}

bool ShellTransferModule::start()
{
	const char * szError;
	int iPos;
	
	m_pCollector->getShellManager()->registerParser(this);
	
	m_pTftpPattern = pcre_compile("tftp(.exe)? +(-i +)?(.*) +get +(.*)", PCRE_CASELESS, &szError, &iPos, 0);
	
	return true;
}

void ShellTransferModule::stop()
{
	pcre_free(m_pTftpPattern);
	
	m_pCollector->getShellManager()->unregisterParser(this);
}

bool ShellTransferModule::parseCommand(const char * szLine, VirtualShell * pShell)
{
	int piOutput[5 * 3];
        int iResult;
        char * szURL;
        if(!m_pTftpPattern)
        	return false;

        if((iResult = pcre_exec(m_pTftpPattern, 0, szLine, strlen(szLine), 0, 0, piOutput, 5 * 3)) > 0)
        {
        	const char * szAddress, * szFileName;

        	pcre_get_substring(szLine, piOutput, iResult, iResult - 2, &szAddress);
        	pcre_get_substring(szLine, piOutput, iResult, iResult - 1, &szFileName);
        	
		asprintf(&szURL, "tftp://%s/%s", szAddress, szFileName);

		pcre_free_substring(szFileName);
		pcre_free_substring(szAddress);
		
		m_pCollector->getDownloadManager()->downloadFile(szURL, pShell->correlationId());
		
		free(szURL);
		
		return true;
	}
	else if(!strncmp("ftp ", szLine, 4) || !strncmp("ftp.exe ", szLine, 8))
	{
		char * szInstructionFile = strstr(szLine, "-s:");
		char * szRemoteHost;
		
		if(!szInstructionFile)
			return false;
			
		szInstructionFile += 3;
		
		szRemoteHost = strrchr(szLine, ' ');
		
		if(szRemoteHost && !isalpha(* szRemoteHost))
			szRemoteHost = 0;
		
		DEBUG("Parsing FTP instruction file \"%s\"; remote host: %s", szInstructionFile, szRemoteHost);
			
		return parseFtpFile(pShell->getFileContent(szInstructionFile, 0), pShell->correlationId(), szRemoteHost);
	}

	return false;
}

bool ShellTransferModule::parseFtpFile(const char * szBuffer, CorrelationId cid, const char * szRemoteHost)
{
	std::string sHost;
	unsigned short usPort = 21;
	std::string sUserName, sPassword;
	std::string sFileName;
	std::string sLine;
	const char * szLine;
	bool bAwaitingUser = false, bAwaitingPassword = false;
	bool bUserKeyword = false;
	
	if(!szBuffer)
		return true;
	
	sLine.clear();
	
	if(szRemoteHost)
		sHost = szRemoteHost;
	
	while(* szBuffer)
	{
		if(* szBuffer == '\n')
		{
			szLine = sLine.c_str();
			
			if(bAwaitingPassword)
			{
				while(* szLine && !isspace(* szLine))
					sPassword.push_back(* (szLine++));
					
				bAwaitingPassword = false;
			}
			else if(!strncmp(szLine, "open ", 5))
			{
				szLine += 5;
				
				while(* szLine && isspace(* szLine))
					++szLine;
					
				while(* szLine && !isspace(* szLine))
					sHost.push_back(* (szLine++));
					
				while(* szLine && isspace(* szLine))
					++ szLine;
					
				if(* szLine)
					usPort = (unsigned short) strtoul(szLine, 0, 10);
					
				bAwaitingUser = true;
			}
			else if(!strncmp(szLine, "user ", 5) || bAwaitingUser)
			{
				if(!strncmp(szLine, "user ", 5))
				{
					szLine += 5;
					bUserKeyword = true;
				}
					
				while(* szLine && isspace(* szLine))
					++szLine;
					
				while(* szLine && !isspace(* szLine))
					sUserName.push_back(* (szLine++));
					
				bAwaitingUser = false;
				
				if(bUserKeyword)
				{
					while(* szLine && isspace(* szLine))
						++szLine;
						
					while(* szLine && !isspace(* szLine))
						sPassword.push_back(* (szLine++));
					
					bAwaitingPassword = sPassword.empty();
				}
				else
					bAwaitingPassword = true;
			}
			else if(!strncmp(szLine, "get ", 4))
			{
				szLine += 4;
				
				while(* szLine && isspace(* szLine))
					++szLine;
					
				while(* szLine && !isspace(* szLine))
					sFileName.push_back(* (szLine++));
	
				{
					char * szURL;
					
					asprintf(&szURL, "ftp://%s:%s@%s:%hu/%s", sUserName.c_str(), sPassword.c_str(), sHost.c_str(), usPort, sFileName.c_str());
					m_pCollector->getDownloadManager()->downloadFile(szURL, cid);
					DEBUG("Parsed FTP Instruction file, download %s", szURL);
					free(szURL);
				}
				
				sFileName.clear();
			}
			else if(strcmp(szLine, "h") && strncmp(szLine, "h ", 2) && strncmp(szLine, "bye",3) && strncmp(szLine, "quit",4))
			{
				while(* szLine && isspace(* szLine))
					++szLine;
					
				if(* szLine)
					LOG(LT_INTHEWILD | LT_LEVEL_CRITICAL, "Unknown FTP command: \"%s\"", szLine);
			}
		
			sLine.clear();
		}
		else if(* szLine != '\r' && (!sLine.empty() || * szLine != ' '))
			sLine.push_back(* szBuffer);
	
		++ szBuffer;
	}	
	
	return true;        
}
