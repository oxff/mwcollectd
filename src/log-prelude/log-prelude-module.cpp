/*
 * Prelude IDS Sensor module
 * This module forwards special log messages asynchronously to a prelude-manager.
 *
 * $Id: log-prelude-module.cpp 237 2005-11-21 18:25:44Z oxff $
 *
 */
 
#include "log-prelude.h"
#include <libprelude/prelude-log.h>

extern "C"
{
	// wrappers around constructor and deconstructor to have nice dll interface
	
	void * CreateInstance()
	{
		return new PreludeModule();
	}

	void FreeInstance(void * pInstance)
	{
		delete (PreludeModule *) pInstance;
	}
}


bool PreludeModule::start()
{
	{
		char * pszArgV[5] = { "./mwcollectd" };
		int iArgC = 1;
		int iResult;
		
		if(prelude_init(&iArgC, pszArgV) < 0)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Unable to initialize Prelude library!");
			
			return false;
		}		
		
		prelude_log_set_flags(PRELUDE_LOG_FLAGS_QUIET);
		
		iResult = prelude_client_new(&m_pPreludeClient, m_pConfiguration->getString(":profile", "mwcollect"));
		
		if(!m_pPreludeClient)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could not create new prelude client: %s!", prelude_strerror(iResult));
			prelude_deinit();
			
			return false;
		}
		
		if(!initializeClientAnalyzer())
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Failed to initialize ANALYZER information for client.");
			
			prelude_deinit();
			return false;
		}
		
		if((iResult = prelude_client_start(m_pPreludeClient)) < 0)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could not start prelude client: %s!", prelude_strerror(iResult));
			prelude_deinit();
			
			return false;
		}
		
		if((iResult = prelude_client_set_flags(m_pPreludeClient, (prelude_client_flags_t) (PRELUDE_CLIENT_FLAGS_HEARTBEAT | PRELUDE_CLIENT_FLAGS_ASYNC_SEND | PRELUDE_CLIENT_FLAGS_ASYNC_TIMER))) < 0)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could not activate asynchronous mode: %s!", prelude_strerror(iResult));
			prelude_deinit();
			
			return false;
		}
	}
	
	if((m_bCorrelate = m_pConfiguration->getLong(":correlation:correlate", 1)))
	{
		m_pCorrelator = new PreludeCorrelator(m_pConfiguration->getLong(":correlation:timeout", 600));
		
		m_ulLastCorrelationCheck = 0;
	}
	
	g_pLogManager->registerLogFacility(this);
	
	return true;
}

bool PreludeModule::initializeClientAnalyzer()
{
	prelude_string_t * pString;
	idmef_analyzer_t * pAnalyzer;
	
	if(!(pAnalyzer = prelude_client_get_analyzer(m_pPreludeClient)))
		return false;
		
	
	if(idmef_analyzer_new_model(pAnalyzer, &pString) < 0)
		return false;
		
	prelude_string_set_constant(pString, "mwcollect");
	
	
	if(idmef_analyzer_new_version(pAnalyzer, &pString) < 0)
		return false;
		
	prelude_string_set_constant(pString, MWCD_VERSION);
	
	
	if(idmef_analyzer_new_manufacturer(pAnalyzer, &pString) < 0)
		return false;
		
	prelude_string_set_constant(pString, "The Honeynet Project");
	
	
	if(idmef_analyzer_new_class(pAnalyzer, &pString) < 0)
		return false;
		
	prelude_string_set_constant(pString, "Malware Collector");
	
	
	return true;
}

void PreludeModule::loop()
{
	unsigned long ulNow = time(0);
	
	if(!m_bCorrelate || m_ulLastCorrelationCheck >= ulNow)
		return;
		
	m_ulLastCorrelationCheck = ulNow;
	m_pCorrelator->checkTimeouts(m_pPreludeClient);
}

void PreludeModule::stop()
{
	if(m_bCorrelate)
		delete m_pCorrelator;

	g_pLogManager->unregisterLogFacility(this);
	
	prelude_client_destroy(m_pPreludeClient, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
	prelude_deinit();
}


void PreludeModule::log(LogTag ltLevel, LogMessage * pMessage)
{
	PreludeMessage pmMessage = PreludeMessage(m_pPreludeClient);
	
	if(pMessage->copyTo(&pmMessage))
	{
		prelude_client_send_idmef(m_pPreludeClient, pmMessage.getIDMEF());
		
		if(m_bCorrelate)
			m_pCorrelator->addMessage(pmMessage.getCorrelationIdentifier(), pmMessage.getPreludeIdentifier());
	}
}
