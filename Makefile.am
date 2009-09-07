# mwcollectd automake input
# (c) 2009 by Georg Wicherski, Kaspersky Labs GmbH <gw@mwcollect.org>
# Installing configuration and embed-python modules inspired by Markus Koetter.

AUTOMAKE_OPTIONS = foreign
SUBDIRS = src

EXTRA_DIST = README

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/mwcollectd

	for conf in `find ./conf/ -name '*.conf'`; do \
		target=$(DESTDIR)$(sysconfdir)/mwcollectd/`basename "$$conf"`; \
		if [ ! -e "$$target" ]; then \
			$(INSTALL_DATA) "$$conf" "$$target"; \
		fi; \
	done


