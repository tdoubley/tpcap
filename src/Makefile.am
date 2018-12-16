lib_LTLIBRARIES=libtpcap.la
libtpcap_ladir = $(prefix)/include


MAINTAINERCLEANFILES = \
	Makefile.in \
	config.h.in \
	config.h.in~

pkginclude_HEADERS = \
	../headers/tpcap/tpcap.h


noinst_HEADERS = \
	utils/*.h \
	pcap/*.h \
	*.h


PCAP = \
    pcap/pcap_parser.c

UTILS = 

libtpcap_la_SOURCES = \
	tpcap.c \
	$(PCAP)
	${UTILS}


libtpcap_la_CFLAGS = 


libtpcap_la_CPPFLAGS = \
	-I.. \
	-g \
	-fPIC \
	-O3 \
	-I../headers


libtpcap_la_LDFLAGS =


libtpcap_la_LIBADD = 

