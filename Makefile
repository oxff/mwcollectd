# mwcollect3 Makefile
# based upon a Makefile of Paul Baecher, Markus Koetter, Georg Wicherski
# $Id: Makefile 308 2006-02-07 16:41:33Z oxff $

MAKEFLAGS += -s

#
# compiler flags
#

CXX = g++
CXXFLAGS += -I./src/include
CXXFLAGS += -D _GNU_SOURCE -pthread -fPIC

ifdef DEBUG
CXXFLAGS += -g -D _DEBUG
else
CXXFLAGS += -D NDEBUG
endif

# detect linux, osx or *bsd
POSIX_FLAVOUR := $(shell if test `uname -s` = 'Linux'; then echo -n 'LINUX_FLAVOURED'; elif test `uname -s` = 'OpenBSD'; then echo -n 'OBSD_FLAVOURED'; elif test `uname -s` = 'FreeBSD'; then echo -n 'OBSD_FLAVOURED'; fi)

ifndef POSIX_FLAVOUR
error:
	echo 'Error: Could not determine your POSIX flavour (one of Linux, *BSD or OSX)!'
	/bin/false
endif

CXXFLAGS += -D$(POSIX_FLAVOUR) -DPOSIX_FLAVOUR=\"$(POSIX_FLAVOUR)\"

#
# linker flags
#

ifeq ($(POSIX_FLAVOUR), LINUX_FLAVOURED)
LDFLAGS += -ldl
ifdef NO_CAPS
CXXFLAGS += -D__NO_CAPABILITY
else
LDFLAGS += -lcap
endif
endif

ifeq ($(POSIX_FLAVOUR), OBSD_FLAVOURED)
LDFLAGS += -L/usr/local/lib/
endif

LDFLAGS += -rdynamic -lpcre -lcurl -lpthread
#
# what makes a complete mwcollectd build?
# this perfectly supports overriding which modules to build by commandline
# but giving a good set of default modules
#

ifndef NO_BUILTIN_MODULES
MODULES += log-file net-posix log-irc vuln-ms05-39 vuln-ms04-11 vuln-ms03-26 shell-basic shell-transfer download-tftp submit-localfile scparse-misc download-curl vuln-ms05-51 log-syslog submit-gotek
endif

#
# Version?
#

ifndef RELEASE
VERSION := $(shell if test -d .svn; then svnversion -nc ./src; fi)

ifndef VERSION
VERSION := unknown
endif
endif

ifdef RELEASE
VERSION := $(RELEASE)
endif

#
# different aliases
#

message:
	echo '[*] mwcollect Daemon Core'
	$(MAKE) all

all: core modules documentation
core: ./bin/mwcollectd
modules:
# call make for each module
	$(foreach mod, $(MODULES), echo '' && echo '[*] Module $(mod)' && export MODULE_NAME=$(mod) && VERSION="$(VERSION)" $(MAKE) -f ./Makefile.MODULE;)
	
#
# which obj files belong to the different parts?
#

CORE_SOURCE = $(shell find ./src/core -iname '*.cpp')
CORE_OBJ = $(CORE_SOURCE:.cpp=.o)

#
# how to build the obj files?
#

./src/core/%.o: ./src/core/%.cpp
	echo '[C] $<'
	$(CXX) $(CXXFLAGS) -c -D MWCD_VERSION=\"$(VERSION)\" -o $@ $<

#
# how to link the different parts?
#

./bin/mwcollectd: $(CORE_OBJ)
	echo '[L] $@'
	$(CXX) $(CXXFLAGS) -o $@ $(CORE_OBJ) $(LDFLAGS)

#
# cleaning up...
#

clean_core:
	echo '[*] Clean mwcollect Daemon Core'
	rm -f ./src/core/*.o
	rm -f ./bin/mwcollectd

clean_modules:
	$(foreach mod, $(MODULES), echo '[*] Clean Module $(mod)' && export MODULE_NAME=$(mod) && $(MAKE) -f ./Makefile.MODULE clean;)

clean: clean_core clean_modules clean_doc

documentation:
clean_doc:
