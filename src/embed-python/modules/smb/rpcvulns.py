#
#				    _ _           _      _ 
#	 _ __ _____      _____ ___ | | | ___  ___| |_ __| |
#	| '_ ` _ \ \ /\ / / __/ _ \| | |/ _ \/ __| __/ _` |
#	| | | | | \ V  V / (_| (_) | | |  __/ (__| || (_| |
#	|_| |_| |_|\_/\_/ \___\___/|_|_|\___|\___|\__\__,_|
#
#
# 	Copyright 2009 Mark Schloesser <ms@mwcollect.org>
#
#
#	This file is part of mwcollectd.
#
#	mwcollectd is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	mwcollectd is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU Lesser General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with mwcollectd. If not, see <http://www.gnu.org/licenses/>.
#
#
#	This SMB emulation was originally written for dionaea and is also
#	redistributed with mwcollectd. Unlike the rest of mwcollectd, this
#	code is licensed under the GPL.

import dionaea_compat

rpclog = dionaea_compat.Logger('RPCVULN')

class RPCVULN:
	uuid = ''
	opnum = 0

	@classmethod
	def processrequest(cls, p):
		pass

class MS08_067(RPCVULN): # also ms06_040
	# SRVSVC
	uuid = 'c84f324b7016d30112785a47bf6ee188'
	# NetPathCanonicalize
	opnum = 0x1f

	@classmethod
	def processrequest(cls, p):
		rpclog.info('got the DCERPC request for NetPathCanonicalize. MS08-067 exploit?')
		rpclog.debug('DCERPC request: {0}'.format(p.summary()))

class MS04_011(RPCVULN):
	# DSSETUP
	uuid = '6a2819390cb1d0119ba800c04fd92ef5'
	# DsRolerUpgradeDownlevelServer
	opnum = 0x09

	@classmethod
	def processrequest(cls, p):
		rpclog.info('got the DCERPC request for DsRolerUpgradeDownlevelServer. MS04-011 exploit?')
		rpclog.debug('DCERPC request: {0}'.format(p.summary()))

class MS03_049(RPCVULN):
	# WKSSVC
	uuid = '98d0ff6b12a11036983346c3f87e345a'
	# NetAddAlternateComputerName
	opnum = 0x1b

	@classmethod
	def processrequest(cls, p):
		rpclog.info('got the DCERPC request for NetAddAlternateComputerName. MS03-049 exploit?')
		rpclog.debug('DCERPC request: {0}'.format(p.summary()))

class MS06_066(RPCVULN):
	# NWWKS
	uuid = '81b07ae6449821359d32834f038001c0'
	# NwOpenEnumNdsSubTrees
	opnum = 0x09

	@classmethod
	def processrequest(cls, p):
		rpclog.info('got the DCERPC request for NwOpenEnumNdsSubTrees. MS06-066 exploit?')
		rpclog.debug('DCERPC request: {0}'.format(p.summary()))

class MS06_066_2(RPCVULN):
	# NWWKS
	uuid = '81b07ae6449821359d32834f038001c0'
	# NwChangePassword
	opnum = 0x01

	@classmethod
	def processrequest(cls, p):
		rpclog.info('got the DCERPC request for NwChangePassword. MS06-066 exploit?')
		rpclog.debug('DCERPC request: {0}'.format(p.summary()))

class MS03_026(RPCVULN):
	# DCOM
	uuid = 'b84a9f4d1c7dcf11861e0020af6e7c57'
	# RemoteActivation
	opnum = 0x00

	@classmethod
	def processrequest(cls, p):
		rpclog.info('got the DCERPC request for RemoteActivation. MS03-026 exploit?')
		rpclog.debug('DCERPC request: {0}'.format(p.summary()))

class MS05_017(RPCVULN):
	# MSMQ
	uuid = '30a0b3fd5f06d111bb9b00a024ea5525'
	# QMDeleteObject
	opnum = 0x09

	@classmethod
	def processrequest(cls, p):
		rpclog.info('got the DCERPC request for QMDeleteObject. MS05-017 exploit?')
		rpclog.debug('DCERPC request: {0}'.format(p.summary()))

class MS07_065(RPCVULN):
	# MSMQ
	uuid = '30a0b3fd5f06d111bb9b00a024ea5525'
	# QMCreateObjectInternal
	opnum = 0x06

	@classmethod
	def processrequest(cls, p):
		rpclog.info('got the DCERPC request for QMCreateObjectInternal. MS07-065 exploit?')
		rpclog.debug('DCERPC request: {0}'.format(p.summary()))

class MS05_039(RPCVULN):
	# PNP
	uuid = '404e9f8d3da0ce118f6908003e30051b'
	# PNP_QueryResConfList
	opnum = 0x36

	@classmethod
	def processrequest(cls, p):
		rpclog.info('got the DCERPC request for PNP_QueryResConfList. MS05-039 exploit?')
		rpclog.debug('DCERPC request: {0}'.format(p.summary()))


