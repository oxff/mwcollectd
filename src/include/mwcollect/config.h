/*
 * kythenconfig, public domain software
 * 03-2005 by Georg Wicherski (and slightly modified for mwc3 by me again :D)
 *
 * $Id: config.h 34 2005-06-11 23:06:36Z oxff $
 *
 */

#ifndef __KYTHEN_CONFIG_H
#define __KYTHEN_CONFIG_H

#include <string>
#include <list>

namespace mwccore
{
	typedef struct ConfigurationNode_s
	{
		std::string sName;

		struct // was union but not allowed because of constructor.. :/
		{
			std::string sValue;
			std::list<ConfigurationNode_s *> lpChildren;
		} uData;

		ConfigurationNode_s * pFather; // needed for parsing
		bool bIsLeaf; // has sValue or lpChildren?; an empty block is considered as not beeing leaf!
	} ConfigurationNode;
	
	class ConfigurationDirectiveManager
	{
	public:
		virtual bool loadModule(const char * szModulePath, const char * szConfiguration) = 0;
		
		// this can optionally be provided to enable the %loadModule("pathToModule", "moduleConfig")
		// statement which is used by mwcollect for example.
		// if you do not provide a ConfigurationDirectiveManager * to the Configuration Constructor, this feature
		// will be disabled.		
	};

	class Configuration
	{
	public:
		Configuration();
		Configuration(ConfigurationDirectiveManager * pDirectiveManager);
		virtual ~Configuration();

		bool parse(const char * szFile); // load configuration file and call ConfigurationDirectiveManager::loadModule if enabled
		void free(); // free all loaded information (also called by constructor, so only needed if reloading)

		virtual const char * getString(const char * szPath, const char * szDefault); // get the string specified by szPath or return szDefault if not found, resulting ptr is instable (result of std::string::c_str())
		virtual long getLong(const char * szPath, long lDefault); // get a long specified by szPath or return lDefault if not found, uses strtol (format)
		virtual std::list<const char *> * getChildren(const char * szPath); // return a list of children of block specified by szPath
		virtual bool leafExists(const char * szPath); // does that leaf (= value) exist? (if it exists as block, FALSE IS RETURNED
		virtual bool blockExists(const char * szPath); // does that block exist?
		virtual std::list<const char *> * getStringList(const char * szPath); // enumerates the _values_ of all children of a block specified by szPath; RESULT IS NOT THREAD SAFE because next call will modify the result list, next parsing will modify the pointers in the list

		void statistics(unsigned int& pBlocks, unsigned int& pValues, unsigned int& pCharacters); // load some fancy statistics about the currently last loaded configuration file

	private:
		void freenode(ConfigurationNode * pFree); // yeah I love you irc guys ;P

		ConfigurationNode * pathToNode(const char * szPath, ConfigurationNode * pStart = 0);

	protected:
		ConfigurationNode * m_pRoot;

		unsigned int m_nBlocks, m_nValues, m_nCharacters; // statisitics are always cool
		
		ConfigurationDirectiveManager * m_pDirectiveManager;
	};

}

#endif // __KYTHEN_CONFIG_H
