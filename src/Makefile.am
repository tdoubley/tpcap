lib_LTLIBRARIES = libtpcap.la
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
        protocol/*.h \
	*.h


PCAP = \
    pcap/pcap_parser.c \
    pcap/pcap.c
    
PROTOCOL = \
    protocol/protocol.c \
    protocol/http.c \
    protocol/app_proto.c

UTILS = 

libtpcap_la_SOURCES = \
	tpcap.c \
	$(PCAP) \
        $(PROTOCOL) \
	$(UTILS)


libtpcap_la_CFLAGS = 


libtpcap_la_CPPFLAGS = \
	-I.. \
	-g \
	-fPIC \
	-O3 \
	-I../others \
	-I../headers \
        $(TPCAP_NO_DEBUG)


libtpcap_la_LDFLAGS =
    


libtpcap_la_LIBADD = \
	../others/libhttpparser.la

