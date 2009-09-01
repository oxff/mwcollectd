# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>

AUTOMAKE_OPTIONS = foreign

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated -Wno-missing-braces -I../include/
AM_LDFLAGS =

pkglib_LTLIBRARIES = embed-python.la

embed_python_la_SOURCES  = embed-python.cpp
embed_python_la_SOURCES += PythonEndpoint.cpp
embed_python_la_SOURCES += binding.cpp
embed_python_la_CPPFLAGS = $(PYTHON_CPPFLAGS)
embed_python_la_LDFLAGS = -module -no-undefined -avoid-version $(PYTHON_LDFLAGS)
