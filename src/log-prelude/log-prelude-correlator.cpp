/*
 * Prelude IDS Sensor module
 * This module forwards special log messages asynchronously to a prelude-manager.
 *
 * $Id: log-prelude-correlator.cpp 243 2005-12-01 22:26:39Z oxff $
 *
 */
 
#include "log-prelude.h"
#include <time.h>
#include <libprelude/prelude-inttypes.h>


PreludeCorrelator::PreludeCorrelator(unsigned long ulTimeout)
{
	m_ulTimeout = ulTimeout;
}

void PreludeCorrelator::addMessage(CorrelationId cid, unsigned long long ullPreludeId)
{
	std::map<CorrelationId, CorrelationEntity, CorrelationIdComparator>::iterator i;
	
	if((i = m_mChains.find(cid)) == m_mChains.end())
	{
		CorrelationEntity ceNew;
		
		ceNew.lullPreludeIds.push_back(ullPreludeId);
		ceNew.ulLastAction = time(0);
		
		m_mChains[cid] = ceNew;
		
		DEBUG("New Prelude Chain for CID %016llx: %016llx", cid, ullPreludeId);
	}
	else
	{
		i->second.lullPreludeIds.push_back(ullPreludeId);
		i->second.ulLastAction = time(0);
		
		DEBUG("Extended Prelude Chain for CID %016llx: %016llx", cid, ullPreludeId);
	}
}

void PreludeCorrelator::flushChain(CorrelationId cid, prelude_client_t * pClient)
{
	std::map<CorrelationId, CorrelationEntity, CorrelationIdComparator>::iterator i;
	
	if((i = m_mChains.find(cid)) == m_mChains.end())
	{
		DEBUG("Prelude Correlation flush for non-existant CID!");
		
		return;
	}
	
	writeCorrelationAlert(pClient, &i->second);
	m_mChains.erase(i);
}

void PreludeCorrelator::checkTimeouts(prelude_client_t * pClient)
{
	std::map<CorrelationId, CorrelationEntity, CorrelationIdComparator>::iterator next;
	unsigned long ulExpired = time(0) - m_ulTimeout;
	
	for(std::map<CorrelationId, CorrelationEntity, CorrelationIdComparator>::iterator i = m_mChains.begin(); i != m_mChains.end(); i = next)
	{
		next = i;
		++next;
				
		if(i->second.ulLastAction > ulExpired)
			continue;
		
		writeCorrelationAlert(pClient, &i->second);
		m_mChains.erase(i);
	}
}

void PreludeCorrelator::writeCorrelationAlert(prelude_client_t * pClient, CorrelationEntity * pEntity)
{
	if(pEntity->lullPreludeIds.size() <= 1)
	{
		DEBUG("Discareded one-element correlation alert.");
		
		return;
	}

	idmef_message_t * pMessage;
	idmef_alert_t * pAlert;
	idmef_correlation_alert_t * pCAlert;
	idmef_alertident_t * pIdent;
	prelude_string_t * pIdentString;
	
	int iResult;
	
	{
		if((iResult = idmef_message_new(&pMessage)) < 0)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Failed to allocate new IDMEF message: %s!", prelude_strerror(iResult));
			
			return;
		}
		
		if((iResult = idmef_alert_new(&pAlert)) < 0)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Failed to allocate new IDMEF alert: %s!", prelude_strerror(iResult));
			
			return;
		}
		
		if((iResult = idmef_correlation_alert_new(&pCAlert)) < 0)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Failed to allocate new IDMEF correlation alert: %s!", prelude_strerror(iResult));
			
			return;
		}
	}
	
	{
		idmef_time_t * pTime;
		
		idmef_alert_set_analyzer(pAlert, idmef_analyzer_ref(prelude_client_get_analyzer(pClient)), 0);
		
		
		if(idmef_alert_new_create_time(pAlert, &pTime) < 0)
			return;
		
		idmef_time_set_from_gettimeofday(pTime);

		idmef_message_set_alert(pMessage, pAlert);
		
		idmef_alert_set_correlation_alert(pAlert, pCAlert);
	}
	
	{
		prelude_string_t * pText;
		idmef_classification_t * pClassification;
		
		if(idmef_classification_new(&pClassification) >= 0)
		{	
			idmef_classification_new_text(pClassification, &pText);
			prelude_string_set_constant(pText, "Malware infection aborted");
			
			idmef_alert_set_classification(pAlert, pClassification);
		}
	}
	
	{
		prelude_string_t * pText;
		
		idmef_correlation_alert_new_name(pCAlert, &pText);
		prelude_string_set_constant(pText, "Alert chain timed out");
	}
	
	{
		idmef_assessment_t * pAssessment;
		idmef_impact_t * pImpact;
		
		if(idmef_assessment_new(&pAssessment) >= 0 && idmef_impact_new(&pImpact) >= 0)
		{
			idmef_impact_set_severity(pImpact, IDMEF_IMPACT_SEVERITY_HIGH);
			idmef_impact_set_completion(pImpact, IDMEF_IMPACT_COMPLETION_FAILED);
			
			idmef_assessment_set_impact(pAssessment, pImpact);
			idmef_alert_set_assessment(pAlert, pAssessment);
		}
	}
	
	for(std::list<unsigned long long>::iterator i = pEntity->lullPreludeIds.begin(); i != pEntity->lullPreludeIds.end(); ++i)
	{
		if((iResult = prelude_string_new(&pIdentString)) < 0)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Failed to allocate new Prelude string: %s!", prelude_strerror(iResult));
			
			continue;
		}
		
		if((iResult = idmef_correlation_alert_new_alertident(pCAlert, &pIdent, -1)) < 0)
		{
			LOG(LT_STATUS | LT_LEVEL_CRITICAL, "Failed to allocate new IDMEF alert ident: %s!", prelude_strerror(iResult));
			
			continue;
		}
		
		prelude_string_sprintf(pIdentString, "%llu", * i);
		idmef_alertident_set_alertident(pIdent, pIdentString);
	}
	
	prelude_client_send_idmef(pClient, pMessage);
	idmef_message_destroy(pMessage);
}
