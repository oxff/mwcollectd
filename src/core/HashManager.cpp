/*
 * HashManager.cpp - asynchronous hashing of arbitary data
 *
 * This code is distributed governed by the terms listed in the LICENSE file in
 * the top directory of this source package.
 *
 * (c) 2007 by Georg 'oxff' Wicherski, <georg-wicherski@pixel-house.net>
 *
 */

#include "Daemon.hpp"


namespace mwcollectd
{


HashManager::HashManager()
{
	// TODO: read from config
	m_blocksAtOnce = 4;
}


void HashManager::computeHash(HashReceiver * receiver, HashType type,
		uint8_t * data, unsigned int length)
{
	HashTask task;
	
	task.receiver = receiver;
	task.type = type;
	task.data = data;
	task.length = length;
	task.offset = 0;
	
	switch(type)
	{
		case HT_MD5:
			MD5_Init(&task.context.md5);
			break;
			
		case HT_SHA2_256:
			SHA256_Init(&task.context.sha2_256);
			break;
			
		case HT_SHA2_512:
			SHA512_Init(&task.context.sha2_512);
			break;
		
		default:
			LOG(L_CRIT, "Unknown hash type in <%s>!", __PRETTY_FUNCTION__);
	}
	
	m_tasks.push_back(task);
}

bool HashManager::computationPending()
{
	return !m_tasks.empty();
}


#define DIGEST_ROUND(digestsize, blocksize, contextname, updatefn, finalfn); \
{ \
	length = m_blocksAtOnce * blocksize; \
	\
	if(task->length - task->offset < length) \
		length = task->length - task->offset; \
	\
	updatefn(&task->context.contextname, (unsigned char *) (task->data + \
		task->offset), length); \
	task->offset += length; \
	\
	if(task->length == task->offset) \
	{ \
		unsigned char digest[digestsize]; \
		\
		finalfn(digest, &task->context.contextname); \
		\
		task->receiver->hashComputed(task->type, task->data, \
			task->length, (uint8_t *) digest, digestsize); \
		\
		m_tasks.pop_front(); \
	} \
}

void HashManager::loop()
{	
	if(m_tasks.empty())
		return;

	unsigned int length;		
	std::list<HashTask>::iterator task = m_tasks.begin();
	
	switch(task->type)
	{
		case HT_MD5:
			DIGEST_ROUND(MD5_DIGEST_LENGTH, MD5_CBLOCK, md5, MD5_Update,
				MD5_Final);
			break;
			
		case HT_SHA2_256:
			DIGEST_ROUND(SHA256_DIGEST_LENGTH, SHA256_CBLOCK, sha2_256,
				SHA256_Update, SHA256_Final);
			break;
			
		case HT_SHA2_512:
			DIGEST_ROUND(SHA512_DIGEST_LENGTH, SHA512_CBLOCK, sha2_512,
				SHA512_Update, SHA512_Final);			
			break;
	}
}

void HashManager::dropReceiver(HashReceiver * receiver)
{
	std::list<HashTask>::iterator i, next;
	
	for(i = m_tasks.begin(); i != m_tasks.end(); i = next)
	{
		next = i;
		++next;
		
		if(i->receiver == receiver)
			m_tasks.erase(i);
	}
}


}

