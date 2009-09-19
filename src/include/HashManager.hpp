/*
 * HashManager.hpp - asynchronous hashing of arbitary data
 *
 * This code is distributed governed by the terms listed in the LICENSE file in
 * the top directory of this source package.
 *
 * (c) 2007 by Georg 'oxff' Wicherski, <georg-wicherski@pixel-house.net>
 *
 */


#include <stdint.h>
#include <list>

#include <openssl/sha.h>
#include <openssl/md5.h>


#ifndef __INCLUDE_HashManager_cpp
#define __INCLUDE_HashManager_cpp


namespace mwcollectd
{


//! Different hash algorithms supported by the HashManager.
enum HashType
{
	//! Message Digest 5
	HT_MD5,
	//! SHA2, 256bit digest size
	HT_SHA2_256,
	//! SHA2, 512bit digest size
	HT_SHA2_512,
};

/**
 * A HashReceiver is notified by the HashManager upon completition of a  hash
 * calculation. Note that the data memory is the same as passed to the function
 * and must be kept valid until this function is called! So it is a good idea
 * to malloc before calling HashManager::computeHash and free in the callback.
 */
class HashReceiver
{
public:
	virtual ~HashReceiver() { }
	
	//! The hash on the provided data has been computed successfully.
	virtual void hashComputed(HashType type, uint8_t * data,
		unsigned int dataLength, uint8_t * hash, unsigned int hashLength) = 0;
};


struct HashTask
{
	HashType type;
	uint8_t * data;
	unsigned int length, offset;

	union
	{
		MD5_CTX md5;
		SHA256_CTX sha2_256;
		SHA512_CTX sha2_512;
	} context;
	
	HashReceiver * receiver;
};


/**
 * Facility for asynchronously computing hashs on arbitary data. Each round of
 * the main loop, one block is calculated. Hence, the main loop should not block
 * on absence of I/O events if computationPending returned true.
 */
class HashManager
{
public:
	HashManager();
	virtual ~HashManager() { }
	
	/**
	 * Compute the given hash type for the given data asynchronoysly.
	 * The data pointer has to remain valid until the receiver is notified about
	 * the completition of the computation!
	 * @param receiver	The HashReceiver who will get the final hash result.
	 * @param type		Algorithm to be used when computating the hash.
	 * @param data		Data to hash. Must remain valid during computation!
	 * @param length	The length of the data in bytes.
	 */
	virtual void computeHash(HashReceiver * receiver, HashType type,
		uint8_t * data, unsigned int length);
	
	/**
	 * Drop all computations associated with a specific receiver (in case of
	 * invalidation). If this function is not called before a receiver is
	 * deleted, an invalid memory deference will happen upon finialization of
	 * the has computation.
	 */
	virtual void dropReceiver(HashReceiver * receiver);
	
	/**
	 * Compute the next block, should be called every main loop iteration. Does
	 * nothing if there are no pending hashings.
	 */
	void loop();
	
	/**
	 * Determine whether loop needs to be called. If this returns true, the
	 * main loop should not block / sleep.
	 * @return True if a block computation is pending.
	 */
	bool computationPending();
		
private:
	std::list<HashTask> m_tasks;
	uint32_t m_blocksAtOnce;
};


}


#endif // __INCLUDE_HashManager_cpp
