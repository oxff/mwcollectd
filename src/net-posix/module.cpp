/*
 * Module Interface to mwcollect daemon.
 *
 * $Id: module.cpp 85 2005-09-02 14:21:27Z oxff $
 *
 * Sitting in the train from Aachen to Cologne, smelling lots of beer here... O_o
 * `Everything I do, I do it for you!'
 *
 */
 
#include "net-posix.h"

extern "C"
{
	void * CreateInstance()
	{
		return new NetPosixModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (NetPosixModule *) pInstance;
	}
}



NetPosixModule::NetPosixModule()
{
	m_pInterface = 0;
}

NetPosixModule::~NetPosixModule()
{
	stop(); // performs check whether already stopped itself
}

bool NetPosixModule::start()
{
	stop();
	
	m_pInterface = new PosixInterface(m_pConfiguration);
	
	if(!m_pCollector->getNetworkCore()->registerNetworkInterface(m_pInterface, NIC_NORMAL, this))
		return false;
		
	return true;
}

void NetPosixModule::stop()
{
	if(!m_pInterface)
		return;
	
	m_pInterface->flush();
	m_pCollector->getNetworkCore()->unregisterNetworkInterface(m_pInterface);
	
	delete m_pInterface;
	m_pInterface = 0;
}
