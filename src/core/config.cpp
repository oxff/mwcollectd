/*
 * kythenconfig, public domain software
 * 03-2005 by Georg Wicherski (and slightly modified for mwc3 by me again :D)
 *
 * $Id: config.cpp 131 2005-10-03 14:47:24Z ryan $
 *
 */

#include <sys/stat.h>
#include <mwcollect/config.h>
#include <stdio.h>
#include <ctype.h>

namespace mwccore
{
#if 1 // be verbose in complain messages?
#define COMPLAIN(a) printf("[config parse error] line %u, column %u, parsing '%c', [" __FILE__ ":%u]: %s\n", y, x, c, __LINE__, a)
#else
#define COMPLAIN(a) printf("[config parse error] %u:%u, parsing '%c': %s", y, x, c, a)
#endif

Configuration::Configuration()
{
	m_pRoot = 0;
	m_pDirectiveManager = 0;
}

Configuration::Configuration(ConfigurationDirectiveManager * pDirectiveManager)
{
	m_pRoot = 0;
	m_pDirectiveManager = pDirectiveManager;
}

Configuration::~Configuration()
{
	free();
}


void Configuration::free()
{
	freenode(m_pRoot);
}

void Configuration::freenode(ConfigurationNode * pFree)
{
	if(pFree->bIsLeaf)
	{
		for(std::list<ConfigurationNode *>::iterator i = pFree->uData.lpChildren.begin(); i != pFree->uData.lpChildren.end(); ++i)
			freenode(* i);
	}

	delete pFree;
}

typedef enum
{ // different states for our state parser ::parse
	CPS_IN_VOID,
	CPS_IN_CHILD,

	CPS_IN_NAME,
	CPS_IN_VALUE,
	CPS_IN_VALUE_ESCAPE,

	CPS_EXPECTING_VEND,
	CPS_EXPECTING_VALUE,
	
	CPS_IN_COMMENT,
	
	// all for the %loadModule stuff...
	CPS_SKIPPING_DIRECTIVE,
	CPS_EXPECTING_DIRECTIVE_PARAMETER,
	CPS_EXPECTING_DIRECTIVE_PARAMETER_SEPARATOR,
	CPS_EXPECTING_DIRECTIVE_PARAMETER_END,
	
	// for the string lists
	CPS_IN_STRINGLIST,
} ConfigParseState;

typedef enum
{
	VST_VALUE_STRING = 0,
	VST_DIRECTIVE_STRING_A,
	VST_DIRECTIVE_STRING_B,
	VST_STRINGLIST_ITEM,
} ValueStringType;

bool Configuration::parse(const char * szFile)
{ // bloody biaaatch ;)
	FILE * pFile;
	ConfigParseState cpsState, cpsRestore;
	ValueStringType vstType;
	unsigned int nDepth, nRead = 0;
	std::string sName, sValue, sDirectiveModule;
	int x = 0, y = 1;
	ConfigurationNode * pCurrent;
	char * szBuffer;
	bool bParseDirective = (m_pDirectiveManager != 0);
	
	const char szDirectiveString[] = "%loadModule";
	#define nDirectiveLength (sizeof(szDirectiveString) -1)
	unsigned int nDirectiveSkip;
	
	std::list<std::string> lsStringList;

	{
		struct stat fs;

		if(m_pRoot)
			return false;

		if(!(pFile = fopen(szFile, "rb")))
			return false;

		stat(szFile, &fs);

		if(!(szBuffer = (char *) malloc(fs.st_size)))
			return false;

		if(fread(szBuffer, 1, fs.st_size, pFile) < 1)
			return false;

		fclose(pFile);

		m_nCharacters = (unsigned int) fs.st_size;
	}

	{
		m_pRoot = new ConfigurationNode;

		m_pRoot->uData.lpChildren.clear();
		m_pRoot->bIsLeaf = false;
		m_pRoot->pFather = 0;
		m_pRoot->sName = std::string("root");
		pCurrent = m_pRoot;

		cpsState = CPS_IN_VOID;

		m_nBlocks = 0;
		m_nValues = 0;
	}

	{ // actual parsing
		char c;

		for(nRead = 0; nRead < m_nCharacters; ++nRead)
		{
			c = szBuffer[nRead];

			if(c == '\n')
			{
				++y; x = 0;
			}
			else if(c != '\r')
				++x;			

			// these are more or less general rules for comments and whitespace characters, they apply to most states

			if(cpsState == CPS_IN_COMMENT)
			{
				if(c == '\n')
					cpsState = cpsRestore;
					
				continue;
			}

			if(c == ';' && cpsState != CPS_IN_VALUE && cpsState != CPS_EXPECTING_VEND) // outside of values, slightly ignored if not required
				continue;

			if(cpsState != CPS_IN_VALUE && isspace(c))
				continue; // if we're not currently parsing some value, discard any whitespace characters

			if(cpsState != CPS_IN_VALUE && c == '#')
			{
				cpsRestore = cpsState;
				cpsState = CPS_IN_COMMENT;

				continue;
			}

			
			// these are state specific rules

			switch(cpsState)
			{
			case CPS_IN_VOID:				
				if(c == '{')
				{
					sName.clear();
					nDepth = 1;

					pCurrent = m_pRoot;
					cpsState = CPS_IN_CHILD;
				}
				else if(c == szDirectiveString[0] && bParseDirective)
				{
					nDirectiveSkip = 1;
					cpsState = CPS_SKIPPING_DIRECTIVE;
				}
				else
				{
					if(bParseDirective)
						COMPLAIN("Parsing in void, expecting open root bracket, loadModule directive or comment.");
					else
						COMPLAIN("Parsing in void, expecting open root bracket or comment.");
										
					return false;
				}

				break;

			case CPS_IN_CHILD:
				if(c == '}')
				{
					--nDepth;

					if(!nDepth)
						cpsState = CPS_IN_VOID;
					else
						pCurrent = pCurrent->pFather;

					continue;
				}
				else
				{
					sName.clear();
					cpsState = CPS_IN_NAME;
				}

			case CPS_IN_NAME:
				if(c == '=')
				{
					cpsState = CPS_EXPECTING_VALUE;
					vstType = VST_VALUE_STRING;
				}
				else if(c == '{')
				{ // create a new child
					ConfigurationNode * pNew = new ConfigurationNode;

					if(pCurrent->bIsLeaf)
					{
						COMPLAIN("Want to create a block child for a leaf!");
						return false;
					}

					pNew->pFather = pCurrent;
					pNew->sName = sName;
					pNew->uData.lpChildren.clear();
					pNew->bIsLeaf = false;

					pCurrent->uData.lpChildren.push_back(pNew);
					pCurrent = pNew;

					sName.clear();

					++nDepth;
					++m_nBlocks;
					cpsState = CPS_IN_CHILD;
				}
				else
					sName.push_back(c);

				break;

			case CPS_EXPECTING_VALUE:
				if(c == '\"')
				{
					sValue.clear();
					cpsState = CPS_IN_VALUE;
				}
				else if(c == '(')
				{
					lsStringList.clear();
					cpsState = CPS_IN_STRINGLIST;
				}
				else
				{
					COMPLAIN("Expecting Value, however found did not find \".");
					return false;
				}

				break;

			case CPS_IN_VALUE:
				if(c == '\"')
				{
					if(vstType == VST_VALUE_STRING)
					{
						ConfigurationNode * pNew = new ConfigurationNode;

						if(pCurrent->bIsLeaf)
						{
							COMPLAIN("Want to create a leaf child for a leaf!");
							return false;
						}

						pNew->sName = sName;
						pNew->uData.sValue = sValue;
						pNew->bIsLeaf = true;
						pNew->pFather = pCurrent;

						pCurrent->uData.lpChildren.push_back(pNew);
						// no pCurrent = pNew needed since we have a leaf and so we are continuing in the old one

						cpsState = CPS_EXPECTING_VEND;
						++m_nValues;
					}
					else if(vstType == VST_STRINGLIST_ITEM)
					{
						lsStringList.push_back(sValue);
						cpsState = CPS_IN_STRINGLIST;
						
						++m_nValues;
					}
					else
					{						
						if(vstType == VST_DIRECTIVE_STRING_A)
						{
							sDirectiveModule = sValue;
							
							cpsState = CPS_EXPECTING_DIRECTIVE_PARAMETER_SEPARATOR;
						}							
						else if(vstType == VST_DIRECTIVE_STRING_B)
						{
							cpsState = CPS_EXPECTING_DIRECTIVE_PARAMETER_END;
							
							m_pDirectiveManager->loadModule(sDirectiveModule.c_str(), sValue.c_str());
						}
						else
							COMPLAIN("This should never have happened!");
					}
					
					sValue.clear();
				}
				else if(c == '\\')
					cpsState = CPS_IN_VALUE_ESCAPE;
				else
					sValue.push_back(c);

				break;

			case CPS_IN_VALUE_ESCAPE: // yeah we are nearly like a C++ parser... nearly... at least a bit...
				if(c == '\"')
					sValue.push_back('\"');
				else if(c == 't')
					sValue.push_back('\t');
				else if(c == 'n')
					sValue.push_back('\n');
				else if(c == 'r')
					sValue.push_back('\r');
				else if(c == '\\')
					sValue.push_back('\\');
				else
				{
					COMPLAIN("Unknown escape character.");
					return false;
				}

				cpsState = CPS_IN_VALUE;
				break;

			case CPS_EXPECTING_VEND:
				if(c == ';')
					cpsState = CPS_IN_CHILD;
				else
				{
					COMPLAIN("Unterminated value.. missing ';'?");
					return false;
				}

				break;
				
			case CPS_SKIPPING_DIRECTIVE:
				if(c == szDirectiveString[nDirectiveSkip])
				{
					++nDirectiveSkip;
					
					if(nDirectiveSkip == nDirectiveLength)
						cpsState = CPS_EXPECTING_DIRECTIVE_PARAMETER;
				}
				else
				{
					COMPLAIN("Unknown directive (perhaps typo when writing loadModule?)!");
					return false;
				}
				
				break;
				
			case CPS_EXPECTING_DIRECTIVE_PARAMETER:
				if(c == '(')
				{
					cpsState = CPS_EXPECTING_VALUE;
					vstType = VST_DIRECTIVE_STRING_A;
				}
				else
				{
					COMPLAIN("Expecting %loadModule parameter.");
					return false;
				}
				
				break;
				
			case CPS_EXPECTING_DIRECTIVE_PARAMETER_SEPARATOR:
				if(c == ',' || c == '|')
				{
					cpsState = CPS_EXPECTING_VALUE;
					vstType = VST_DIRECTIVE_STRING_B;
					
					sValue.clear();
				}
				else
				{
					COMPLAIN("Expected Directive Parameter Separator (',' or '|'), however found something else!");
					return false;
				}
				
				break;
				
			case CPS_EXPECTING_DIRECTIVE_PARAMETER_END:
				if(c == ')')
					cpsState = CPS_IN_VOID;
				else
				{
					COMPLAIN("Expecting end of Directive Parameter ('('), however found something else!");
					return false;
				}
				
				break;
				
			case CPS_IN_STRINGLIST:
				if(c == '\"')
				{
					cpsState = CPS_IN_VALUE;
					vstType = VST_STRINGLIST_ITEM;
				}
				else if(c == ')')
				{
					ConfigurationNode * pChild, * pNew = new ConfigurationNode;

					if(pCurrent->bIsLeaf)
					{
						COMPLAIN("Want to create a block child for a leaf!");
						return false;
					}

					pNew->pFather = pCurrent;
					pNew->sName = sName;
					pNew->uData.lpChildren.clear();
					pNew->bIsLeaf = false;
													
					for(std::list<std::string>::iterator it = lsStringList.begin(); it != lsStringList.end(); ++it)
					{
						pChild = new ConfigurationNode;
						
						pChild->pFather = pNew;
						pChild->sName = "string-list-entry";
						pChild->uData.sValue = * it;
						pChild->bIsLeaf = true;
						
						pNew->uData.lpChildren.push_back(pChild);
					}
					
					pCurrent->uData.lpChildren.push_back(pNew);
					
					lsStringList.clear();						
					++m_nBlocks;											
					cpsState = CPS_EXPECTING_VEND;
				}
				else if(c != ',')
				{
					COMPLAIN("Unrecognized char within stringlist.");
					return false;
				}
					
				break;

			default:
				COMPLAIN("Unknown state in parser!");
				return false;
			}
		}
	}

	::free(szBuffer);
	return true;
}


ConfigurationNode * Configuration::pathToNode(const char * szPath, ConfigurationNode * pStart)
{ // ok we get something like :foo:bar:baz and turn this into the pointer to the struct representing the baz node, using recursion
	std::string sName;

	if(!pStart)
	{
		if(* szPath == ':')
			++szPath;

		pStart = m_pRoot;
	}

	if(pStart->bIsLeaf)
		return 0;

	while(* szPath && * szPath != ':')
		sName.push_back(* (szPath++));

	for(std::list<ConfigurationNode *>::iterator i = pStart->uData.lpChildren.begin(); i != pStart->uData.lpChildren.end(); ++i)
	{
		if((* i)->sName != sName)
			continue;
		else if(* szPath)
			return pathToNode(++szPath, (* i));
		else
			return (* i);
	}

	return 0; // no such foobarian
}

bool Configuration::blockExists(const char * szPath)
{ // test if the given path leads to a valid block
	ConfigurationNode * pNode = pathToNode(szPath);

	if(!pNode || pNode->bIsLeaf)
		return false;

	return true;
}

bool Configuration::leafExists(const char * szPath)
{ // test if the given path leads to a valid leaf
	ConfigurationNode * pNode = pathToNode(szPath);

	if(!pNode || !pNode->bIsLeaf)
		return false;

	return true;
}

std::list<const char *> * Configuration::getChildren(const char * szPath)
{ // enumerate all the children of a node represented by a given task, this isn't that complicated in general,
	// however needs some work to get it into some ['programmer friendly' | 'manipulation safe'] <const char *>list...
	// RESULT IS NOT THREAD SAFE because next call will modify the result list, next parsing will modify the pointers in the list

	static std::list<const char *> lszReturn;
	ConfigurationNode * pNode = pathToNode(szPath);

	if(!pNode || pNode->bIsLeaf)
		return 0;

	lszReturn = std::list<const char *>();

	for(std::list<ConfigurationNode *>::iterator i = (pNode->uData.lpChildren).begin(); i != (pNode->uData.lpChildren).end(); ++i)
		lszReturn.push_back((* i)->sName.c_str());

	return &lszReturn;
}

std::list<const char *> * Configuration::getStringList(const char * szPath)
{
	static std::list<const char *> lszReturn;
	
	ConfigurationNode * pNode = pathToNode(szPath);
	
	if(!pNode || pNode->bIsLeaf)
		return 0;
		
	lszReturn = std::list<const char *>();
	
	for(std::list<ConfigurationNode *>::iterator i = (pNode->uData.lpChildren).begin(); i != (pNode->uData.lpChildren).end(); ++i)
		lszReturn.push_back((* i)->uData.sValue.c_str());

	return &lszReturn;
}

const char * Configuration::getString(const char * szPath, const char * szDefault)
{ // fetch a string value by path
	// MORE OR LESS THREAD SAFE, next parsing will modify the result pointer

	ConfigurationNode * pNode = pathToNode(szPath);

	if(!pNode || !pNode->bIsLeaf)
		return szDefault;

	return pNode->uData.sValue.c_str();
}

long Configuration::getLong(const char * szPath, long lDefault)
{ // fetch a long by path
	// THREADSAFE since returned as copy
	// if leaf contains non-number string literal instead of some number, this will return 0 instead of lDefault so take care

	ConfigurationNode * pNode = pathToNode(szPath);

	if(!pNode || !pNode->bIsLeaf)
		return lDefault;

	return strtol(pNode->uData.sValue.c_str(), 0, 0);
}

void Configuration::statistics(unsigned int& pBlocks, unsigned int& pValues, unsigned int& pCharacters)
{
	pBlocks = m_nBlocks;
	pValues = m_nValues;
	pCharacters = m_nCharacters;
}


} // close the namespace
