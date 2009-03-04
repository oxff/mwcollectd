/*
 * Simulates MS04-11 (Remote Code Execution in LSASS Service).
 *
 * $Id: vuln-ms0411-subscription.cpp 243 2005-12-01 22:26:39Z oxff $
 *
 */
 
#include "vuln-ms0411.h"
#include "vuln-ms0411-hod.h"

#include <string.h>

void VulnerabilitySubscription::incomingData(unsigned char * pucData, unsigned int nLength)
{
	m_sBuffer.append((char *) pucData, nLength);
	
	while(!m_sBuffer.empty())
	{
		switch(m_iStage)
		{
		case 0:
			if(m_sBuffer.size() < sizeof(HOD_req1) - 1)
				return;
	
			if(memcmp(m_sBuffer.data(), HOD_req1, sizeof(HOD_req1) - 1))
			{
				m_clLevel = CL_DROP;
				return;
			}
			
			m_pSocket->sendData(HOD_Positive_Reply, sizeof(HOD_Positive_Reply) - 1);
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_req1) - 1);
			
			break;
		
		case 1:
			if(m_sBuffer.size() < sizeof(HOD_req2) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HOD_req2, sizeof(HOD_req2) - 1))
			{
				m_clLevel = CL_DROP;
				return;
			}
			
			m_pSocket->sendData(HOD_Positive_Reply, sizeof(HOD_Positive_Reply) - 1);
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_req2) - 1);
			
			break;
			
		case 2:
			if(m_sBuffer.size() < sizeof(HOD_req3) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HOD_req3, sizeof(HOD_req3) - 1))
			{
				m_clLevel = CL_DROP;
				return;
			}
			
			{
				const char * szOS = "Windows 5.1 ";
				char szResponse[128];
				
				for(int i = 0; i < 128; ++i)
					szResponse[i] = 'Z';
				
				for(int i = 0; szOS[i]; ++i)
					szResponse[48 + i * 2] = szOS[i];
				
				m_pSocket->sendData((unsigned char *) szResponse, sizeof(szResponse));
			}
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_req3) - 1);
			m_clLevel = CL_OVERTAKE;
			
			break;
			
		case 3:
			if(m_sBuffer.size() < 47)
				return;
				
			if(memcmp(m_sBuffer.data() + 5, HOD_req4 + 5, 44 - 5))
			{
				m_clLevel = CL_DROP;
				return;
			}
			
			m_pSocket->sendData(HOD_Positive_Reply, sizeof(HOD_Positive_Reply) - 1);
			
			++m_iStage;
			m_sBuffer.erase(0, m_sBuffer.data()[3] + 4);
			
			break;
			
		case 4:
			if(m_sBuffer.size() < sizeof(HOD_req5) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HOD_req5, sizeof(HOD_req5) - 1))
			{
				m_clLevel = CL_DROP;
				return;
			}
			
			m_pSocket->sendData(HOD_Positive_Reply, sizeof(HOD_Positive_Reply) - 1);
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_req5) - 1);
			
			break;
			
		case 5:
			if(m_sBuffer.size() < sizeof(HOD_req6) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HOD_req6, sizeof(HOD_req6) - 1))
			{
				m_clLevel = CL_DROP;
				return;
			}
			
			m_pSocket->sendData(HOD_Positive_Reply, sizeof(HOD_Positive_Reply) - 1);
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_req6) - 1);
			
			break;
			
		case 6:
			if(m_sBuffer.size() < sizeof(HOD_req7) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HOD_req7, sizeof(HOD_req7) - 1))
			{
				m_clLevel = CL_DROP;
				return;
			}

			m_pSocket->sendData(HOD_Positive_Reply, sizeof(HOD_Positive_Reply) - 1);
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_req7) - 1);
			
			break;
			
		case 7:
			if(m_sBuffer.size() < 160)
				return;
				
			++m_iStage;
			m_sBuffer.erase(0, 160);
			
			break;
			
		case 8:
			{
				if(m_sBuffer.size() < 1980)
					return;
					
				CorrelationId cid = g_pLogManager->generateCorrelationIdentifier();
					
				{
					GenericClassfulLogMessage lmMessage = GenericClassfulLogMessage("Got successfully exploited via MS04-11 vulnerability!", cid);
					
					lmMessage.setString("classification.text", "Successful MS04-11 Exploitation");
					
					lmMessage.setString("classification.reference(0).name", "OSVDB-5248");
					lmMessage.setString("classification.reference(0).origin", "osvdb");
					lmMessage.setString("classification.reference(0).url", "http://www.osvdb.org/5248");

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
				
				m_clLevel = CL_DROP; // we're done now
				m_pCollector->getShellcodeDispatcher()->parseShellcode((unsigned char *) m_sBuffer.data(), 1980, m_ulRemoteHost, cid);
				m_sBuffer.erase();
				
				++ m_iStage; // prevent misunderstanding of closeEvent issued due to CL_DROP
				
				break;
			}
		}
	}
}

void VulnerabilitySubscription::connectionEtablished()
{
	m_clLevel = CL_UNSURE;
	m_iStage = 0;
	
	
}

void VulnerabilitySubscription::connectionClosed()
{
	if(m_iStage == 8)
	{
		CorrelationId cid = g_pLogManager->generateCorrelationIdentifier();
					
		LOG(LT_LEVEL_MEDIUM | LT_STATUS | LT_EXPLOIT, "Got more-or-less-successfully exploited with MS04-11 vulnerability!");
		
		m_clLevel = CL_DROP; // we're done now
		m_pCollector->getShellcodeDispatcher()->parseShellcode((unsigned char *) m_sBuffer.data(), m_sBuffer.size(), m_ulRemoteHost, cid);
		m_sBuffer.erase();
	}
}

ConsumptionLevel VulnerabilitySubscription::consumptionLevel()
{
	if(m_clLevel == CL_DROP)
		DEBUG("vuln-ms0411 decided to be dropped in stage %i.", m_iStage);
	
	return m_clLevel;
}

