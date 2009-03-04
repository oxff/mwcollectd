/*
 * Prelude IDS Sensor module
 * This module forwards special log messages asynchronously to a prelude-manager.
 *
 * $Id: log-prelude-message.cpp 235 2005-11-10 18:05:33Z oxff $
 *
 */
 
#include "log-prelude.h"


PreludeMessage::PreludeMessage(prelude_client_t * pClient)
{
	int iResult;
	
	if((iResult = idmef_message_new(&m_pMessage)) < 0)
	{
		LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Failed to allocate new IDMEF message: %s!", prelude_strerror(iResult));
		
		m_pMessage = 0;
	}
	
	if((iResult = idmef_alert_new(&m_pAlert)) < 0)
	{
		LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Failed to allocate new IDMEF alert: %s!", prelude_strerror(iResult));
		
		m_pAlert = 0;
	}
	
	m_pPreludeClient = pClient;
	
	prepareAlert();
}

PreludeMessage::~PreludeMessage()
{
	if(m_pMessage)
		idmef_message_destroy(m_pMessage);
}


void PreludeMessage::setProperty(const char * szOldName, const unsigned char * pucValue, unsigned int nLength)
{
	if(!m_pMessage)
		return;
	
	int iResult;
	
	if(!strcmp(szOldName, "download.url"))
	{
		idmef_additional_data_t * pData = 0;
		prelude_string_t * pMeaning;
		
		idmef_alert_new_additional_data(m_pAlert, &pData, -1);
		
		if((iResult = idmef_additional_data_set_string_dup_fast(pData, (char *) pucValue, nLength - 1)) < 0)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could not create IDMEF additonal data for %u bytes download URL: %s!", nLength, prelude_strerror(iResult));
			
			return;
		}
		
		idmef_additional_data_new_meaning(pData, &pMeaning);
		prelude_string_set_constant(pMeaning, "Download URL");
	}
	else
	{ // try to just prepend `alert.'
		char * szName;
		idmef_value_t * pValue;
		idmef_path_t * pPath;
		
		asprintf(&szName, "alert.%s", szOldName);
		
		if((iResult = idmef_path_new(&pPath, szName)) < 0)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could not create IDMEF path \"%s\": %s!", szName, prelude_strerror(iResult));

			return;
		}
		
		if((iResult = idmef_value_new_from_path(&pValue, pPath, (char *) pucValue)) < 0)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could not create IDMEF value \"%s\" for \"%s\": %s!", pucValue, szName, prelude_strerror(iResult));
			idmef_path_destroy(pPath);

			return;
		}
		
		if((iResult = idmef_path_set(pPath, m_pMessage, pValue)) < 0)
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Could set value for IDMEF path \"%s\" to \"%s\": %s!", szName, pucValue, prelude_strerror(iResult));

		idmef_value_destroy(pValue);
		idmef_path_destroy(pPath);
		
		free(szName);
	}
}

void PreludeMessage::prepareAlert()
{
	idmef_time_t * pTime;
	
	idmef_alert_set_analyzer(m_pAlert, idmef_analyzer_ref(prelude_client_get_analyzer(m_pPreludeClient)), 0);
	
	
	if(idmef_alert_new_create_time(m_pAlert, &pTime) < 0)
		return;
	
	idmef_time_set_from_gettimeofday(pTime);

	idmef_message_set_alert(m_pMessage, m_pAlert);
	
	{ // we need the idmef message id for correlation, so we create it on our own, bitch!
		prelude_string_t * pID;
		
		if(prelude_string_new(&pID) < 0)
			return;
	
		m_ullPreludeId = prelude_ident_inc(prelude_client_get_unique_ident(m_pPreludeClient));
		prelude_string_sprintf(pID, "%llu", m_ullPreludeId);
		
		idmef_alert_set_messageid(m_pAlert, pID);
	}
}
