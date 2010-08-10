# botsnoopd automake input
# $Id: Makefile.am 5 2007-11-02 16:15:24Z oxff $
# (c) 2007 by Georg 'oxff' Wicherski, <georg-wicherski@pixel-house.net>

AUTOMAKE_OPTIONS = foreign

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated -I../include/ $(POSTGRESQL_CXXFLAGS)
AM_LDFLAGS =

pkglib_LTLIBRARIES = postgres.la

postgres_la_SOURCES  = interface-psql.cpp
postgres_la_SOURCES += PostgresSocket.cpp
postgres_la_LDFLAGS  = -module -no-undefined -avoid-version $(POSTGRESQL_LDFLAGS)
