SUBDIRS = 


# make clean
CLEANFILES = 

# make maintainer-clean
MAINTAINERCLEANFILES = \
	Makefile.in


bin_PROGRAMS =
noinst_PROGRAMS =


noinst_PROGRAMS += test
test_SOURCES = \
    test.c

test_LDADD = \
	$(top_builddir)/src/.libs/libtpcap.a
	
test_LDFLAGS =

test_CPPFLAGS = \
	-I../ \
	-g \
	-I$(top_builddir)/headers