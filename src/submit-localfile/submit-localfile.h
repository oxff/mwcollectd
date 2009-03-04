/*
 * TCP Server Skeleton Module
 * A more or less well commented example how to subscribe to a certain port and accept traffic there.
 *
 * $Id: submit-localfile.h 135 2005-10-03 21:28:52Z oxff $
 *
 */
 
#ifndef __MWCMOD_SUBMITLOCALFILE_H
#define __MWCMOD_SUBMITLOCALFILE_H

#include <mwcollect/core.h>

#include <sys/types.h>

using namespace mwccore;


class SubmitterModule : public Module, public Submitter
{
public:	
	virtual void assignConfiguration(Configuration * pConfig) { m_pConfiguration = pConfig; };
	virtual void assignCollector(MalwareCollector * pCollector) { m_pCollector = pCollector; };
	
	virtual bool start();
	virtual void stop();
	
	virtual bool submitData(const unsigned char * pData, unsigned int nLength, CorrelationId cid);
	
protected:
	Configuration * m_pConfiguration;
	MalwareCollector * m_pCollector;

	const char * m_szDirectory;
	uid_t m_uidChown;
	gid_t m_gidChgrp;
	
	int m_iChmod;
	bool m_bPerformHashing;
};

#endif // __MWCMOD_SUBMITLOCALFILE_H
