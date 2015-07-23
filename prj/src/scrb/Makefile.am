SUBDIRS = .

INCLUDES = \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)

AM_CPPFLAGS = \
  $(GNUNET_CPPFLAGS)

# Set this variable if you are using GNUNET libraries for all programs and
# libraries. You don't then need to target-specific _LDFLAGS with GNUNET_LDFLAGS
# AM_LDFLAGS = \
#   $(GNUNET_LDFLAGS) \
#   $(WINFLAGS) \
#   -export-dynamic

lib_LTLIBRARIES = \
	libgnunetscrb.la\
 	libgnunetscrbblock.la

pkgcfgdir= $(prefix)/share/gnunet/config.d/

libexecdir= $(prefix)/lib/gnunet/libexec/

libgnunetscrb_la_SOURCES = \
  scrb_api.c 
libgnunetscrb_la_LIBADD = \
  -lgnunetutil
libgnunetscrb_la_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0

libgnunetscrbblock_la_SOURCES = \
  scrb_block_lib.h
libgnunetscrbblock_la_LIBADD = \
  -lgnunetutil -lgnunetcore -lgnunetdht\
  $(INTLLIBS)
libgnunetscrbblock_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 1:0:0
 

bin_PROGRAMS = gnunet-scrb testbed_scrb

libexec_PROGRAMS = gnunet-service-scrb

check_PROGRAMS = \
 test_scrb_api 

TESTS = $(check_PROGRAMS)

gnunet_service_scrb_SOURCES = \
  gnunet-service-scrb.c
gnunet_service_scrb_LDADD = \
  -lgnunetutil -lgnunetcore -lgnunetdht -lgnunetstatistics\
  libgnunetscrbblock.la \
  $(INTLLIBS) 
gnunet_service_scrb_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic 

gnunet_scrb_SOURCES = \
  gnunet-scrb.c
gnunet_scrb_LDADD = \
  -lgnunetutil -lgnunetdht \ #-lgnunetstrings\ 
  $(INTLLIBS) \
  scrb_api.o 
gnunet_scrb_LDFLAGS = \
 $(GNUNET_LDFLAGS) $(WINFLAGS) -export-dynamic 
 
testbed_scrb_SOURCES = \
  testbed_scrb.c
testbed_scrb_LDADD = \
  -lgnunetutil \
  -lgnunettestbed \
  $(INTLLIBS) \
  scrb_api.o
testbed_scrb_LDFLAGS = \
 $(GNUNET_LDFLAGS) $(WINFLAGS) -export-dynamic 

test_scrb_api_SOURCES = \
 test_scrb_scrb.c
test_scrb_api_LDADD = \
  $(top_builddir)/src/scrb/libgnunetscrb.la \
  -lgnunetutil
test_scrb_api_LDFLAGS = \
 $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic
  
plugindir = $(libdir)/gnunet
plugin_LTLIBRARIES = \
	libgnunet_plugin_block_scrb.la
libgnunet_plugin_block_scrb_la_SOURCES = \
	plugin_block_scrb.c
libgnunet_plugin_block_scrb_la_LIBADD = \
	$(prefix)/lib/libgnunethello.la \
	$(prefix)/lib/libgnunetblock.la \
	$(prefix)/lib/libgnunetutil.la
libgnunet_plugin_block_scrb_la_LDFLAGS = \
	$(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_block_scrb_la_DEPENDENCIES = \
	$(prefix)/lib/libgnunetblock.la
 
 
 pkgcfg_DATA = scrb.conf 
 
