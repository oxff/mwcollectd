/*
 * Simulates MS05-39 (Remote Code Execution in Plug and Play Services).
 *
 * $Id: vuln-ms0539-module.cpp 208 2005-11-05 13:30:19Z oxff $
 *
 */
 

#include "vuln-ms0539.h"

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
		
	return m_pCollector->getNetworkCore()->registerSubscriber(m_pConfiguration->getLong("listen-port", 445), this);
}

void VulnerabilityModule::stop()
{
	m_pCollector->getShellcodeDispatcher()->unregisterParser(this);
	m_pCollector->getNetworkCore()->unregisterSubscriber(m_pConfiguration->getLong("listen-port", 445), this);
}


NetworkSubscription * VulnerabilityModule::createNetworkSubscription(Socket * pSocket)
{	
	return new VulnerabilitySubscription(m_pCollector, pSocket);
}

void VulnerabilityModule::freeNetworkSubscription(NetworkSubscription * pSubscription)
{
	delete (VulnerabilitySubscription *) pSubscription;
}


unsigned char HOD_PNP_bind_shellcode[] =
"\x29\xc9\x83\xe9\xb0\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x19"
"\xf5\x04\x37\x83\xeb\xfc\xe2\xf4\xe5\x9f\xef\x7a\xf1\x0c\xfb\xc8"
"\xe6\x95\x8f\x5b\x3d\xd1\x8f\x72\x25\x7e\x78\x32\x61\xf4\xeb\xbc"
"\x56\xed\x8f\x68\x39\xf4\xef\x7e\x92\xc1\x8f\x36\xf7\xc4\xc4\xae"
"\xb5\x71\xc4\x43\x1e\x34\xce\x3a\x18\x37\xef\xc3\x22\xa1\x20\x1f"
"\x6c\x10\x8f\x68\x3d\xf4\xef\x51\x92\xf9\x4f\xbc\x46\xe9\x05\xdc"
"\x1a\xd9\x8f\xbe\x75\xd1\x18\x56\xda\xc4\xdf\x53\x92\xb6\x34\xbc"
"\x59\xf9\x8f\x47\x05\x58\x8f\x77\x11\xab\x6c\xb9\x57\xfb\xe8\x67"
"\xe6\x23\x62\x64\x7f\x9d\x37\x05\x71\x82\x77\x05\x46\xa1\xfb\xe7"
"\x71\x3e\xe9\xcb\x22\xa5\xfb\xe1\x46\x7c\xe1\x51\x98\x18\x0c\x35"
"\x4c\x9f\x06\xc8\xc9\x9d\xdd\x3e\xec\x58\x53\xc8\xcf\xa6\x57\x64"
"\x4a\xa6\x47\x64\x5a\xa6\xfb\xe7\x7f\x9d\x1a\x55\x7f\xa6\x8d\xd6"
"\x8c\x9d\xa0\x2d\x69\x32\x53\xc8\xcf\x9f\x14\x66\x4c\x0a\xd4\x5f"
"\xbd\x58\x2a\xde\x4e\x0a\xd2\x64\x4c\x0a\xd4\x5f\xfc\xbc\x82\x7e"
"\x4e\x0a\xd2\x67\x4d\xa1\x51\xc8\xc9\x66\x6c\xd0\x60\x33\x7d\x60"
"\xe6\x23\x51\xc8\xc9\x93\x6e\x53\x7f\x9d\x67\x5a\x90\x10\x6e\x67"
"\x40\xdc\xc8\xbe\xfe\x9f\x40\xbe\xfb\xc4\xc4\xc4\xb3\x0b\x46\x1a"
"\xe7\xb7\x28\xa4\x94\x8f\x3c\x9c\xb2\x5e\x6c\x45\xe7\x46\x12\xc8"
"\x6c\xb1\xfb\xe1\x42\xa2\x56\x66\x48\xa4\x6e\x36\x48\xa4\x51\x66"
"\xe6\x25\x6c\x9a\xc0\xf0\xca\x64\xe6\x23\x6e\xc8\xe6\xc2\xfb\xe7"
"\x92\xa2\xf8\xb4\xdd\x91\xfb\xe1\x4b\x0a\xd4\x5f\xf6\x3b\xe4\x57"
"\x4a\x0a\xd2\xc8\xc9\xf5\x04\x37";

bool VulnerabilityModule::parseShellcode(const unsigned char * pucShellcode, unsigned int nLength, unsigned long ulHost, CorrelationId cid)
{
	if(nLength < sizeof(HOD_PNP_bind_shellcode) - 1)
		return false;
		
	for(int i = 0; i < sizeof(HOD_PNP_bind_shellcode) - 1; ++i)
		if(pucShellcode[i] != (unsigned char) HOD_PNP_bind_shellcode[i] && (i < 186 || i > 187))
			return false;
			
	LOG(LT_SHELLCODE | LT_LEVEL_LOW, "Got a MS05-39 House of Dabus bind shellcode for port %hu.", ntohs(* ((unsigned short *) (pucShellcode + 186))) ^ 0x0437);
	m_pCollector->getShellManager()->bindShell(ntohs(* ((unsigned short *) (pucShellcode + 186))) ^ 0x0437, ulHost, cid);
	
	return true;
}
