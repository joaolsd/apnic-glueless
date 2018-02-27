ACLOCAL_AMFLAGS = -I m4 --install

AM_LDFLAGS = -lrt

bin_PROGRAMS = \
	glueless-parent \
	glueless-child \
	glueless-sibling

EXTRAS = \
	src/base.cc src/base.h \
	src/process.c src/process.h \
	src/evutils.c src/evutils.h \
	src/utils.c src/utils.h \
	src/logging.c src/logging.h \
	src/atr_handler.c src/atr_handler.h

glueless_parent_SOURCES = \
	src/glueless-parent.cc \
	$(EXTRAS)

glueless_child_SOURCES = \
	src/glueless-child.cc \
	$(EXTRAS)

glueless_sibling_SOURCES = \
	src/glueless-sibling.cc \
	$(EXTRAS)
