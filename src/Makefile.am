# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign


if LIBEMU_MODULE
shellcode_libemu_dir = shellcode-libemu
endif

if NFQ_MODULE
dynserv_nfqueue_dir = dynserv-nfqueue
endif

SUBDIRS = core \
	  log-irc \
	  $(dynserv_nfqueue_dir) \
	  dynserv-mirror \
	  filestore-streams \
	  $(shellcode_libemu_dir)

EXTRA_DIST = README
