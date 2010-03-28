# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated -Wno-strict-aliasing -I../include/
AM_LDFLAGS =

pkglib_LTLIBRARIES = dynserv-nfqueue.la

dynserv_nfqueue_la_SOURCES = dynserv-nfqueue.cpp
dynserv_nfqueue_la_LDFLAGS = -module -no-undefined -avoid-version -lnetfilter_queue
