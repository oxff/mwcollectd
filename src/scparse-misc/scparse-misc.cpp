/*
 * Shellcode parser for miscellaneous shellcodes found in the wild.
 * kkuehl was the first to provide one, thank you. Other tickets will be added later on.
 *
 * $Id: scparse-misc.cpp 212 2005-11-06 17:26:33Z oxff $
 *
 */
 
#include "scparse-misc.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern "C"
{
	// wrappers around constructor and deconstructor to have nice dll interface
	
	void * CreateInstance()
	{
		return new ParserModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (ParserModule *) pInstance;
	}
}


ParserModule::ParserModule()
{
}

ParserModule::~ParserModule()
{
}



bool ParserModule::compilePatterns(pcre * * * pppPatterns, const char * * pszPatterns, unsigned int nPatterns)
{
	* pppPatterns = (pcre * *) malloc(sizeof(pcre *) * nPatterns);

	for(unsigned int i = 0; i < nPatterns; ++i)
	{
		const char * szError;
		int iErrorPos;

		if(!((* pppPatterns)[i] = pcre_compile(pszPatterns[i], PCRE_DOTALL, &szError, &iErrorPos, 0)))
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "PCRE Pattern \"%s\" does not compile: %s @ %u", pszPatterns[i], szError, iErrorPos);
			
			return false;
		}
	}
	
	return true;
}


bool ParserModule::start()
{
	const char * pszPatterns[] = {
		"^.*\\xEB.\\xEB.\\xE8.*\\xB1(.).*\\x80..(.).*\\xE2.(.*)$", // generic xor decoder
		"^.*\\x0A\\x65\\x73\\x73.*\\x57\\xE8....(.*)\\x6A.\\xE8....+$", // some generic createprocess shellcode
		"^.*\\xEB.((http|https|ftp):\\/\\/[a-zA-Z0-9\\/\\\\\\.\\+:~]+).*\\xDF+.*$", // generic prepended url shellcode
		"^.*(\\xEB\\x10\\x5B\\x4B\\x33\\xC9\\x66\\xB9\\x25\\x01\\x80\\x34\\x0B\\x99\\xE2\\xFA\\xEB\\x05\\xE8\\xEB\\xFF\\xFF\\xFF\\x70\\x62\\x99\\x99\\x99\\xC6\\xFD.*\\xF9\\x7E\\xE0\\x5F\\xE0).*$", // house of dabus connect_back
		"^.*(\\xEB\\x10\\x5A\\x4A\\x33\\xC9\\x66\\xB9\\x7D\\x01\\x80\\x34\\x0A\\x99\\xE2\\xFA\\xEB\\x05\\xE8\\xEB\\xFF\\xFF\\xFF\\x70\\x95\\x98\\x99\\x99\\xC3\\xFD.*\\x99\\xFA\\xF5\\xF6\\xEA\\xFC\\xEA\\xF6\\xFA\\xF2\\xFC\\xED\\x99).*$", // house of dabus listen_shell
		"\\xEB...\\x33\\xC9\\x66\\xB9(..)\\x80..(.)\\xE2.\\xEB.(.*)$", // generic xor decoder, 2 bytes length 1 byte key
		"cmd.*\\xC7\\x07\\x02\\x00(..)\\xC7\\x47\\x04(....).*ws2_32\\x00WSASocketA\\x00connect\\x00", // kkuehl-1 generic reverse shell
		"\\xEB.\\xB9(....)\\x81\\xF1(....).\\x80...(.)\\xE2.\\xEB.(.*)$", // nasty length xor .. xor decoder, ticket 59
		"\\xEB..\\x31\\xC9\\x81\\xE9(....)\\x81.(....)\\x81\\xEE\\xFC\\xFF\\xFF\\xFF\\xE2.\\xEB.\\xE8....(.*)$", // nasty sub length xor decoder, caught itw by myself (turned out to be linkbot stage 1 decoder)
		"\\x68(....)\\x68..(..).*\\x53\\xBA....\\xFF\\xD6\\xBF(....)\\xFF\\xE5", // linkbot stage 1, analysis taken from http://nepenthes.sourceforge.net/help:dcom:linkbot
		"\\x8B\\xD8\\x57\\x57\\x68\\x02\\x00(..)\\x8B\\xCC.*\\x89\\x66\\x30", // bindshell caught in the wild, cabaj-1
		};

	m_pCollector->getShellcodeDispatcher()->registerParser(this);

	return compilePatterns(&m_ppPatterns, pszPatterns, 11);
}

void ParserModule::stop()
{
	free(m_ppPatterns);
	
	m_pCollector->getShellcodeDispatcher()->unregisterParser(this);
}

bool ParserModule::parseShellcode(const unsigned char * pucShellcode, unsigned int nLength, unsigned long ulHost, CorrelationId cid)
{
	unsigned int nDecodedLength = nLength;
	int piOutput[10 * 3];
	int iResult; // for the whole pcre shit baby :D

        { // decoding (xor et al.)
                if((iResult = pcre_exec(m_ppPatterns[0], 0, (char *) pucShellcode, nLength, 0, 0, piOutput, sizeof(piOutput)/sizeof(int))) > 0)
                { // ok we have generic xor decoder
                        const char * pKey, * pCodeLength;
                        unsigned char * pucDecoded;

                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 1, &pCodeLength);
                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 2, &pKey);                        

                        nDecodedLength = piOutput[7] - piOutput[6];
                        pucDecoded = (unsigned char *) malloc(nDecodedLength);

                        for(unsigned int i = 0; i < nDecodedLength; ++i)
                                pucDecoded[i] = (i < (* ((unsigned char *) pCodeLength)) ? pucShellcode[i + piOutput[6]] ^ * ((unsigned char *) pKey) : pucShellcode[i + piOutput[6]]);

                        LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Detected generic XOR Decoder, key is %xh, code is %xh (%xh) bytes long.", * ((unsigned char *) pKey), * ((unsigned char *) pCodeLength), piOutput[7] - piOutput[6]);

                        pcre_free_substring(pCodeLength);
                        pcre_free_substring(pKey);
                        
                        m_pCollector->getShellcodeDispatcher()->parseShellcode(pucDecoded, nDecodedLength, ulHost, cid);
                        free(pucDecoded);
                        
                        return true;
                }
                
                if((iResult = pcre_exec(m_ppPatterns[5], 0, (char *) pucShellcode, nLength, 0, 0, piOutput, sizeof(piOutput)/sizeof(int))) > 0)
                { // ok we have generic xor decoder
                        const char * pKey, * pCodeLength;
                        unsigned char * pucDecoded;

                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 1, &pCodeLength);
                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 2, &pKey);                        

                        nDecodedLength = piOutput[7] - piOutput[6];
                        pucDecoded = (unsigned char *) malloc(nDecodedLength);

                        for(unsigned int i = 0; i < nDecodedLength; ++i)
                                pucDecoded[i] = (i < (* ((unsigned short *) pCodeLength)) ? pucShellcode[i + piOutput[6]] ^ * ((unsigned char *) pKey) : pucShellcode[i + piOutput[6]]);

                        LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Detected generic XOR Decoder II, key is %xh, code is %hxh (%xh) bytes long.", * ((unsigned char *) pKey), * ((unsigned short *) pCodeLength), piOutput[7] - piOutput[6]);

                        pcre_free_substring(pCodeLength);
                        pcre_free_substring(pKey);
                        
                        m_pCollector->getShellcodeDispatcher()->parseShellcode(pucDecoded, nDecodedLength, ulHost, cid);
                        free(pucDecoded);
                        
                        return true;
                }
                
                if((iResult = pcre_exec(m_ppPatterns[7], 0, (char *) pucShellcode, nLength, 0, 0, piOutput, sizeof(piOutput)/sizeof(int))) > 0)
                { // ok we have generic xor decoder
                        const char * pKey, * pCodeLengthA, * pCodeLengthB;
                        unsigned char * pucDecoded;
                        unsigned int nCodeLength;

                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 1, &pCodeLengthA);
                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 2, &pCodeLengthB);
                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 3, &pKey); 
                        
                        nCodeLength = (* (unsigned int *) pCodeLengthA) ^ (* (unsigned int *) pCodeLengthB);

                        nDecodedLength = piOutput[9] - piOutput[8];
                        pucDecoded = (unsigned char *) malloc(nDecodedLength);

                        for(unsigned int i = 0; i < nDecodedLength; ++i)
                                pucDecoded[i] = (i < nCodeLength ? pucShellcode[i + piOutput[8]] ^ * ((unsigned char *) pKey) : pucShellcode[i + piOutput[6]]);

                        LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Detected generic XOR Decoder III, key is %xh, code is %xh (%xh) bytes long.", * ((unsigned char *) pKey), nCodeLength, piOutput[9] - piOutput[8]);

                        pcre_free_substring(pCodeLengthA);
                        pcre_free_substring(pCodeLengthB);
                        pcre_free_substring(pKey);
                        
                        m_pCollector->getShellcodeDispatcher()->parseShellcode(pucDecoded, nDecodedLength, ulHost, cid);
                        free(pucDecoded);
                        
                        return true;
                }
                
                if((iResult = pcre_exec(m_ppPatterns[8], 0, (char *) pucShellcode, nLength, 0, 0, piOutput, sizeof(piOutput)/sizeof(int))) > 0)
                { // ok we have generic xor decoder
                        const char * pKey, * pCodeLengthA;
                        unsigned char * pucDecoded;
                        unsigned int nCodeLength;

                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 1, &pCodeLengthA);
                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 2, &pKey); 
                        
                        nCodeLength = 0 - (* (unsigned int *) pCodeLengthA);

                        nDecodedLength = piOutput[7] - piOutput[6];
                        pucDecoded = (unsigned char *) malloc(nDecodedLength);
                        
			memcpy(pucDecoded, pucShellcode + piOutput[6], nDecodedLength);
			
			for(int i = 0; i < nCodeLength - 1 && i * 4 < nDecodedLength - 4; ++i)
			{				
				((unsigned int *) pucDecoded)[i] ^= * (unsigned int *) pKey;
			}
			
                        LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Detected generic XOR Decoder IV, key is %xh, code is %xh (%xh) bytes long.", * ((unsigned int *) pKey), nCodeLength * 4, piOutput[7] - piOutput[6]);

                        pcre_free_substring(pCodeLengthA);
                        pcre_free_substring(pKey);
                        
                        m_pCollector->getShellcodeDispatcher()->parseShellcode(pucDecoded, nDecodedLength, ulHost, cid);
                        free(pucDecoded);
                        
                        return true;
                }
        }
        
        { // weird ones like linkbot
        	if((iResult = pcre_exec(m_ppPatterns[9], 0, (char *) pucShellcode, nLength, 0, 0, piOutput, sizeof(piOutput)/sizeof(int))) > 0)
                {
                	const char * pRemoteAddress, * pRemotePort, * pAuthkey;
                	
                	pcre_get_substring((char *) pucShellcode, piOutput, iResult, 1, &pRemoteAddress);
                	pcre_get_substring((char *) pucShellcode, piOutput, iResult, 2, &pRemotePort);
                	pcre_get_substring((char *) pucShellcode, piOutput, iResult, 3, &pAuthkey);
                	
                	LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Detected Linkbot Stage 1, connect to %08x:%hu with authkey %08x.", * (unsigned int *) pRemoteAddress, * (unsigned short *) pRemotePort, * (unsigned int *) pAuthkey);
                	
                	{
                		sockaddr_in addrLinkbot;
                		char * szUrl;
                		
                		addrLinkbot.sin_addr.s_addr = * (unsigned long *) pRemoteAddress;
                		asprintf(&szUrl, "linkbot://%s:%hu/%08x", inet_ntoa(addrLinkbot.sin_addr), ntohs(* (unsigned short *) pRemotePort), * (unsigned int *) pAuthkey);
                	}
                	
                	pcre_free_substring(pRemoteAddress);
                	pcre_free_substring(pRemotePort);
                	pcre_free_substring(pAuthkey);
                }
        }
        
        { // actual parsing
                if((iResult = pcre_exec(m_ppPatterns[1], 0, (char *) pucShellcode, nLength, 0, 0, piOutput, sizeof(piOutput)/sizeof(int))) > 0)
                {
                        const char * pRemoteCommand;

                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 1, &pRemoteCommand);
                        
                        LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Detected generic CreateProcess Shellcode: \"%s\"", pRemoteCommand);

                        {
                        	ShellManager * pManager = m_pCollector->getShellManager();
                        	VirtualShell * pShell = new VirtualShell(pManager, cid);
                        	
                        	pManager->parseCommand(pRemoteCommand, pShell);
                        	
                        	delete pShell;
                        }

                        pcre_free_substring(pRemoteCommand);
                        
                        return true;
                }

                if((iResult = pcre_exec(m_ppPatterns[2], 0, (char *) pucShellcode, nLength, 0, 0, piOutput, sizeof(piOutput)/sizeof(int))) > 0)
                {
                        const char * pUrl;

                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 1, &pUrl);

                        DEBUG("Detected generic prepended unencoded URL Shellcode: \"%s\"", pUrl);
                        m_pCollector->getDownloadManager()->downloadFile(pUrl, cid);

                        pcre_free_substring(pUrl);
                        
                        return true;
                }

                if((iResult = pcre_exec(m_ppPatterns[3], 0, (char *) pucShellcode, nLength, 0, 0, piOutput, sizeof(piOutput)/sizeof(int))) > 0)
                {
                        const char * pCode;
                        unsigned long ulAddress;
                        unsigned short usPort;
                        
                        if(pcre_get_substring((char *) pucShellcode, piOutput, iResult, 1, &pCode) >= (int) (118 + sizeof(unsigned short)))
                        {
                                ulAddress = * ((unsigned long *) &pCode[111]) ^ 0x99999999;
                                usPort = ntohs(* ((unsigned short *) &pCode[118]) ^ 0x9999);

                                LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Detected HoD connectback shellcode, %08X:%u.", ulAddress, usPort);
                                
                                m_pCollector->getShellManager()->reverseShell(ulAddress, usPort, cid);
                        }

                        pcre_free_substring(pCode);

			return true;
                }
                
                if((iResult = pcre_exec(m_ppPatterns[6], 0, (char *) pucShellcode, nLength, 0, 0, piOutput, sizeof(piOutput)/sizeof(int))) > 0)
                {
                        const char * pPort, * pAddress;
                        unsigned short usPort;
                        unsigned long ulAddress;
                        
                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 1, &pPort);
                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 2, &pAddress);
                        
                        usPort = ntohs(* (unsigned short *) pPort);
                        ulAddress = * (unsigned long *) pAddress;
                        
                        LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Detected generic reverse shell (bielefeld / kkuehl-1), 0x%08x:%hu.", ulAddress, usPort);
                        m_pCollector->getShellManager()->reverseShell(ulAddress, usPort, cid);

                        pcre_free_substring(pAddress);
			pcre_free_substring(pPort);

			return true;
                }
                
                if((iResult = pcre_exec(m_ppPatterns[10], 0, (char *) pucShellcode, nLength, 0, 0, piOutput, sizeof(piOutput)/sizeof(int))) > 0)
                {
                        const char * pPort, * pAddress;
                        unsigned short usPort;
                        
                        pcre_get_substring((char *) pucShellcode, piOutput, iResult, 1, &pPort);
                        
                        usPort = ntohs(* (unsigned short *) pPort);
                        
                        LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Detected generic bind shell (adenau / cabaj-1) for :%hu.", usPort);
                        m_pCollector->getShellManager()->bindShell(usPort, ulHost, cid);
                        
			pcre_free_substring(pPort);

			return true;
                }

                if((iResult = pcre_exec(m_ppPatterns[4], 0, (char *) pucShellcode, nLength, 0, 0, piOutput, sizeof(piOutput)/sizeof(int))) > 0)
                {
                        const char * pCode;
                        unsigned short usPort;

                        if(pcre_get_substring((char *) pucShellcode, piOutput, iResult, 1, &pCode) >= (int) (176 + sizeof(unsigned short)))
                        {
                                usPort = ntohs(* ((unsigned short *) &pCode[176]) ^ 0x9999);

                                LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Detected HoD listenshell shellcode, :%hu.", usPort);
                                m_pCollector->getShellManager()->bindShell(usPort, ulHost, cid);
                        }

                        pcre_free_substring(pCode);

			return true;
                }
        }
        
        return false;
}
