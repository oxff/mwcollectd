/*
 * Submit Local File Module, saves a collected malware binary on a local filesystem.
 * 
 *
 * $Id: submit-localfile.cpp 137 2005-10-04 16:41:44Z oxff $
 *
 */
 
#include "submit-localfile.h"
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "md5.h"

extern "C"
{
	// wrappers around constructor and deconstructor to have nice dll interface
	
	void * CreateInstance()
	{
		return new SubmitterModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (SubmitterModule *) pInstance;
	}
}


bool SubmitterModule::start()
{
	if(m_pConfiguration->blockExists(":chown"))
	{
		struct group * pGroup;
		struct passwd * pUser;
		
		if(!(pUser = getpwnam(m_pConfiguration->getString(":chown:user", "mwcollectd"))))
		{
			LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Could not resolve username \"%s\" to an UID!", m_pConfiguration->getString(":chown:user", "mwcollectd"));
			return false;
		}
		
		if(!(pGroup = getgrnam(m_pConfiguration->getString(":chown:group", "nogroup"))))
		{
			LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Could not resolve groupname \"%s\" to a GID!", m_pConfiguration->getString(":chown:group", "nogroup"));
			return false;			
		}
		
		m_uidChown = pUser->pw_uid;
		m_gidChgrp = pGroup->gr_gid;
	}
	else
	{
		m_uidChown = 0;
		m_gidChgrp = 0;
	}
	
	m_szDirectory = m_pConfiguration->getString(":directory", "./data/binaries/");
	
	m_iChmod = (int) strtol(m_pConfiguration->getString(":chmod", "0600"), 0, 0);
	m_bPerformHashing = (m_pConfiguration->getLong(":md5sum", 1) != 0);

	m_pCollector->getSubmissionDispatcher()->registerSubmitter(this);
	
	return true;
}

void SubmitterModule::stop()
{
	m_pCollector->getSubmissionDispatcher()->unregisterSubmitter(this);
}


bool SubmitterModule::submitData(const unsigned char * pData, unsigned int nLength, CorrelationId cid)
{
	char * szFileName;
	int iDescriptor;
	
	if(m_bPerformHashing)
	{
		MD5_CTX context;
		unsigned char szDigest[16];
		char szReadableDigest[33];
		
		MD5Init(&context);
		MD5Update(&context, pData, nLength);
		MD5Final(szDigest, &context);
		
		szReadableDigest[0] = 0;
		
		for(int i = 0; i < sizeof(szDigest); ++i)
			sprintf(szReadableDigest + i * 2, "%02x", (unsigned int) szDigest[i]);
		
		szReadableDigest[sizeof(szReadableDigest) - 1] = 0;
		asprintf(&szFileName, "%s/%s", m_szDirectory, szReadableDigest);
		
	}
	else
		asprintf(&szFileName, "%s/r%08X%08X", m_szDirectory, rand(), rand());
		
	if((iDescriptor = open(szFileName, O_WRONLY | O_EXCL | O_CREAT, m_iChmod)) < 0)
	{
		free(szFileName);
		
		return false;
	}
	
	free(szFileName);
		
	if(nLength > write(iDescriptor, pData, nLength))
		return false;
	
	if(m_uidChown || m_gidChgrp)
	{
		if(fchown(iDescriptor, m_uidChown, m_gidChgrp) < 0)
			LOG(LT_LEVEL_CRITICAL | LT_STATUS, "Could not change ownership for written file \"%s\" to %u:%u!", szFileName, m_uidChown, m_gidChgrp);
	}
		
	close(iDescriptor);
	return true;
}
