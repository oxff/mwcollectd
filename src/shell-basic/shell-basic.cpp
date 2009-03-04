/*
 * Basic Shell Commands Module (`echo', `*.bat' and `del')
 * $Id: shell-basic.cpp 268 2005-12-17 21:26:53Z oxff $
 *
 * Queen on the left side, Hardcore Heaven (note mine! :D) on the right side.
 */
 
#include "shell-basic.h"
#include <string>

extern "C"
{
	// wrappers around constructor and deconstructor to have nice dll interface
	
	void * CreateInstance()
	{
		return new ShellBasicModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (ShellBasicModule *) pInstance;
	}
}

bool ShellBasicModule::start()
{
	m_pCollector->getShellManager()->registerParser(this);
	
	return true;
}

void ShellBasicModule::stop()
{
	m_pCollector->getShellManager()->unregisterParser(this);
}

bool ShellBasicModule::parseCommand(const char * szLine, VirtualShell * pShell)
{
	if(!strncmp(szLine, "echo ", 5))
	{
		std::string sLine;
		bool bAppend = false;
		
		szLine += 5;
		
		while(* szLine && * szLine != '>')
			sLine.push_back(* (szLine++));
			
		if(!* szLine)
			return true;
					
		++szLine;
		
		if(* szLine == '>')
		{
			bAppend = true;
			++szLine;
		}
		
		while(* szLine == ' ')
			++szLine;
			
		if(!bAppend)
			pShell->purgeFile(szLine);
	
		pShell->touchFile(szLine, FT_TEXT);
		pShell->appendFile(szLine, sLine.data(), sLine.size());
		pShell->appendFile(szLine, "\n", 1);
		
		return true;
	}
	else if(!strncmp(szLine, "del ", 4))
	{
		if(!pShell->purgeFile(szLine + 4))
			LOG(LT_STATUS | LT_LEVEL_MEDIUM | LT_INTHEWILD, "Could not delete virtual shell file \"%s\" due to non-existance.", szLine + 4);

		return true;
	}
	else if(!strchr(szLine, ' ') && strstr(szLine, ".bat") && * (strstr(szLine, ".bat") + 4) == 0) // ends with `.bat' TODO FIXME can be tricked by foo.batbar.bat filename
	{
		if(pShell->hasFile(szLine))
		{
			std::string sFile = std::string(pShell->getFileContent(szLine, 0));
			
			while(sFile.find("\n") != sFile.npos && sFile.find("\n") > 1)
			{
				DEBUG("Invoking command from batch file: \"%s\"", sFile.substr(0, sFile.find("\n")).c_str());
				char * szLong = strdup(sFile.substr(0, sFile.find("\n")).c_str());
				char * szLongFree = szLong;
				
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
				
				free(szLongFree);
				sFile.erase(0, sFile.find("\n"));
			}
			
			return true;
		}
		else
			LOG(LT_STATUS | LT_LEVEL_MEDIUM | LT_INTHEWILD, "Invocation of non-existant batch file \"%s\"!", szLine);
	}
	#ifdef _DEBUG
	else if(!strncmp(szLine, "dprint ", 7))
	{
		DEBUG("File contents: \"%s\"", pShell->getFileContent(szLine + 7, 0));
		return true;
	}
	#endif
	
	return false;
}
