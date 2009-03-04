/*
 * Event Dispatcher
 * Talk to other modules and the core in a dynamich fashion; have a firework of events.
 *
 * `Love's like hot, running water.'
 *
 * $Id: event.h 294 2006-02-02 20:09:11Z oxff $
 */
 
#ifndef __MWCCORE_EVENT_H
#define __MWCCORE_EVENT_H

#include <string.h>
#include <map>
#include <list>

namespace mwccore
{
	struct EventStringComparator
	{
		bool operator()(const char* s1, const char* s2) const
		{
			return strcmp(s1, s2) < 0;
		}
	};
	
	enum EventPropertyType
	{
		EPT_LONG = 0,
		EPT_STRING,
		EPT_FLAG,
	};
	
	struct EventProperty
	{
		EventPropertyType eptType;
		
		union
		{
			long lValue;
			char * szValue;
			bool bValue;
		} uValue;
	};
	
	

	class Event
	{
	public:
		~Event();
				
		long getLong(const char * szPropertyPath);
		const char * getString(const char * szPropertyPath);
		bool getFlag(const char * szPropertyPath);
		
		void setLong(const char * szPropartyPath, long lValue);
		void setString(const char * szPropertyPath, const char * szValue);
		void setFlag(const char szPropertyPath, bool fValue);
		
		bool hasProperty(const char * szPropertyPath);
		EventPropertyType getPropertyType(const char * szPropertyPath);
		void removeProperty(const char * szPropertyPath);
		
		const char * renderString();
		
	protected:
		std::map<char *, EventStringComparator, EventProperty> m_mProperties;
	};

	class EventEndpoint
	{
	public:
		virtual void eventFired(const char * szSlot, Event * pEvent) = 0;
	};
	
	typedef std::list<EventEndpoint *> EndpointList;

	class EventDispatcher
	{
	public:
		bool subscribeEvent(const char * szSlot, EventEndpoint * pSubscriber, bool bExclusive = false);
		bool unsubscribeEvent(const char * szSlot, EventEndpoint * pSubscriber);
		void unsubscribeEndpoint(EventEndpoint * pEndpoint);
		
		bool postEvent(const char * szSlot, Event * pEvent);
		
	protected:
		std::map<char *, EventStringComparator, EndpointList> m_mSlots;
	};
}

#endif // __MWCCORE_EVENT_H
