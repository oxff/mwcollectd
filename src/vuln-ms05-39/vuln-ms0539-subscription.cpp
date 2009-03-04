/*
 * Simulates MS05-39 (Remote Code Execution in Plug and Play Services).
 *
 * $Id: vuln-ms0539-subscription.cpp 256 2005-12-16 01:13:07Z oxff $
 *
 */
 
#include "vuln-ms0539.h"
#include "vuln-ms0539-hod.h"

#include <string.h>

void VulnerabilitySubscription::incomingData(unsigned char * pucData, unsigned int nLength)
{
	m_sBuffer.append((char *) pucData, nLength);
	
	while(!m_sBuffer.empty())
	{
		switch(m_iStage)
		{
		case 0:
			if(m_sBuffer.size() < sizeof(HOD_SMB_Negotiate) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HOD_SMB_Negotiate, sizeof(HOD_SMB_Negotiate) - 1))
			{
				m_clLevel = CL_DROP;
				return;
			}
			
			m_pSocket->sendData(HOD_SMB_Positive_Reply, sizeof(HOD_SMB_Positive_Reply) - 1);
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_SMB_Negotiate) - 1);
			
			break;
			
		case 1:
			if(m_sBuffer.size() < sizeof(HOD_SMB_SessionSetupAndX) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HOD_SMB_SessionSetupAndX, sizeof(HOD_SMB_SessionSetupAndX) - 1))
			{
				m_clLevel = CL_DROP;			
				return;
			}
			
			m_pSocket->sendData(HOD_SMB_Positive_Reply, sizeof(HOD_SMB_Positive_Reply) - 1);
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_SMB_SessionSetupAndX) - 1);
			
			break;
			
		case 2:
			if(m_sBuffer.size() < sizeof(HOD_SMB_SessionSetupAndX2) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HOD_SMB_SessionSetupAndX2, sizeof(HOD_SMB_SessionSetupAndX2) - 1))
			{
				m_clLevel = CL_DROP;		
				return;
			}
			
			m_pSocket->sendData(HOD_SMB_Positive_Reply, sizeof(HOD_SMB_Positive_Reply) - 1);
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_SMB_SessionSetupAndX2) - 1);
			
			break;
			
		case 3:	
			if(m_sBuffer.size() < sizeof(HOD_SMB_TreeConnectAndX) - 1)
				return;
				
			if(memcmp(m_sBuffer.data() + 5, HOD_SMB_TreeConnectAndX + 5, sizeof(HOD_SMB_TreeConnectAndX) - 1 - 3 - 5))
			{
				m_clLevel = CL_DROP;	
				return;
			}
			
			++m_iStage;
			m_iPacketLength = (int) * (m_sBuffer.data() + 3) + 4;
			
			break;
			
		case 4:
			if(m_sBuffer.size() < m_iPacketLength)
				return;
				
			++m_iStage;
			m_sBuffer.erase(0, m_iPacketLength);
			
			m_pSocket->sendData(HOD_SMB_Positive_Reply, sizeof(HOD_SMB_Positive_Reply) - 1);
			
			break;
			
		case 5:
			if(m_sBuffer.size() < sizeof(HOD_SMB_PipeRequest_browser) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HOD_SMB_PipeRequest_browser, sizeof(HOD_SMB_PipeRequest_browser) - 1))
			{
				m_clLevel = CL_DROP;		
				return;
			}
			
			m_pSocket->sendData(HOD_SMB_Positive_Reply, sizeof(HOD_SMB_Positive_Reply) - 1);
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_SMB_PipeRequest_browser) - 1);
			
			break;
			
		case 6:
			if(m_sBuffer.size() < sizeof(HOD_SMB_PNPEndpoint) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HOD_SMB_PNPEndpoint, sizeof(HOD_SMB_PNPEndpoint) - 1))
			{
				m_clLevel = CL_DROP;		
				return;
			}
			
			m_pSocket->sendData(HOD_SMB_Positive_Reply, sizeof(HOD_SMB_Positive_Reply) - 1);
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_SMB_PNPEndpoint) - 1);
			
			break;
		
		case 7:
			if(m_sBuffer.size() < sizeof(HOD_RPC_call) - 1)
				return;
				
			if(memcmp(m_sBuffer.data(), HOD_RPC_call, sizeof(HOD_RPC_call) - 1))
			{
				m_clLevel = CL_DROP;		
				return;
			}
			
			++m_iStage;
			m_sBuffer.erase(0, sizeof(HOD_RPC_call) - 1);			
			m_clLevel = CL_OVERTAKE;
			
			break;
			
		case 8:
			{
				if(m_sBuffer.size() < 2197 - sizeof(HOD_RPC_call))
					return;
					
				CorrelationId cid = g_pLogManager->generateCorrelationIdentifier();
					
				{
					GenericClassfulLogMessage lmMessage = GenericClassfulLogMessage("Got successfully exploited via MS05-39 vulnerability!", cid);
					
					lmMessage.setString("classification.text", "Successful MS05-51 Exploitation");
					
					lmMessage.setString("classification.reference(0).name", "OSVDB-18605");
					lmMessage.setString("classification.reference(0).origin", "osvdb");
					lmMessage.setString("classification.reference(0).url", "http://www.osvdb.org/18605");
					
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
				m_pCollector->getShellcodeDispatcher()->parseShellcode((unsigned char *) m_sBuffer.data(), m_sBuffer.size(), m_ulRemoteHost, cid);
				m_sBuffer.erase();
				
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
}

ConsumptionLevel VulnerabilitySubscription::consumptionLevel()
{
	if(m_clLevel == CL_DROP)
		DEBUG("vuln-ms0539 decided to be dropped in stage %i.", m_iStage);
	
	return m_clLevel;
}
