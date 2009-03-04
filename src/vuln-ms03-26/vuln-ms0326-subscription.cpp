/*
 * Simulates MS03-26 (Buffer Overrun In RPC Interface Could Allow Code
 * Execution).
 *
 * $Id: vuln-ms0326-subscription.cpp 243 2005-12-01 22:26:39Z oxff $
 *
 */
 
#include "vuln-ms0326.h"
#include "vuln-ms0326-HDM.h"

#include <string.h>

void VulnerabilitySubscription::incomingData(unsigned char * pucData, unsigned int nLength)
{
	m_sBuffer.append((char *) pucData, nLength);
	
	while(!m_sBuffer.empty())
	{
		switch(m_iStage)
		{
		case 0:
			if(m_sBuffer.size() < sizeof(HDM_bindstr) - 1)
				return;

			if(memcmp(m_sBuffer.data(), HDM_bindstr, sizeof(HDM_bindstr)))
			{
				m_clLevel = CL_DROP;
				return;
			}
			
			m_pSocket->sendData(HDM_Reply, sizeof(HDM_Reply));
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HDM_bindstr));
			break;
		
		case 1:
			if(m_sBuffer.size() < sizeof(HDM_request1) - 1)
				return;
				
			if(memcmp(m_sBuffer.data()+0x194, HDM_request1+0x194, sizeof(HDM_request1) - (1+0x194)))
			{
				m_clLevel = CL_DROP;
				return;
			}
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HDM_request1));
			
			break;
			
		case 2:
			if(m_sBuffer.size() < sizeof(HDM_request2) - 1)
				return;
			
			{
				m_iShellcodeLength = (*(unsigned long *)m_sBuffer.data() - *(unsigned long *)(HDM_request2))*2;
			}

			if(*(unsigned long*)(m_sBuffer.data()+8) != *(unsigned long *)(HDM_request2+8) + m_iShellcodeLength/2)
			{
				m_clLevel = CL_DROP;
				return;
			}
		
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HDM_request2));
			m_clLevel = CL_OVERTAKE;
			
			break;
			
		case 3:
			if(m_sBuffer.size() < m_iShellcodeLength)
				return;
		
			m_sShellcode = m_sBuffer.substr(0,m_iShellcodeLength-1);

			{
				GenericClassfulLogMessage lmMessage = GenericClassfulLogMessage("Got successfully exploited via MS03-26 vulnerability!", m_cid);
				
				lmMessage.setString("classification.text", "Successful MS03-26 Exploitation");
				
				lmMessage.setString("classification.reference(0).name", "OSVDB-2100");
				lmMessage.setString("classification.reference(0).origin", "osvdb");
				lmMessage.setString("classification.reference(0).url", "http://www.osvdb.org/2100");
				
				lmMessage.setString("assessment.impact.severity", "high");
				lmMessage.setString("assessment.impact.completion", "succeeded");
				lmMessage.setString("assessment.impact.type", "admin");

				lmMessage.setAddress("source(0).node.address(0).address", m_ulRemoteHost);
				lmMessage.setInteger("source(0).service.port", m_usRemotePort);
				
				{
					unsigned long ulAddress;
					unsigned short usPort;
					
					m_pCollector->getNetworkCore()->getLocalAddress(this, &ulAddress, &usPort);					
					lmMessage.setAddress("target(0).node.address(0).address", ulAddress);
					lmMessage.setInteger("target(0).service.port", usPort);
				}
				
				g_pLogManager->log(LT_EXPLOIT | LT_LEVEL_MEDIUM, &lmMessage);
			}
			
			++m_iStage;
			m_sBuffer.erase(0, m_iShellcodeLength);
			
			break;
			
		case 4:
			if(m_sBuffer.size() < sizeof(HDM_request3) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HDM_request3, sizeof(HDM_request3) - 1))
			{
				m_clLevel = CL_DROP;
				return;
			}
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HDM_request3));
			
			break;
			
		case 5:
			if(m_sBuffer.size() < sizeof(HDM_request4) - 1)
				return;
			
			m_clLevel = CL_DROP; // we're done now
			m_pCollector->getShellcodeDispatcher()->parseShellcode((unsigned char *) m_sShellcode.c_str(), m_iShellcodeLength, m_ulRemoteHost, m_cid);
			m_sBuffer.erase();
			break;
		}
	}
}

void VulnerabilitySubscription::connectionEtablished()
{
	DEBUG("Connection Established with vuln-ms03-26");
	m_clLevel = CL_UNSURE;
	m_iStage = 0;
	
	m_cid = g_pLogManager->generateCorrelationIdentifier();
}

void VulnerabilitySubscription::connectionClosed()
{
}

ConsumptionLevel VulnerabilitySubscription::consumptionLevel()
{
	if(m_clLevel == CL_DROP)
		DEBUG("vuln-ms0326 decided to be dropped in stage %i.", m_iStage);
	
	return m_clLevel;
}
