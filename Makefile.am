ACLOCAL_AMFLAGS=-I m4

EXTRA_DIST = autogen.sh ChangeLog README.md LICENSE

AM_CPPFLAGS = -Wall -Werror 
AM_CPPFLAGS += -fPIC -pipe  -O -Wall -Wextra -Wpointer-arith -Wno-unused-parameter -Wno-deprecated-declarations -Wno-unused-function -Wno-ignored-qualifiers
AM_CPPFLAGS += $(CODE_COVERAGE_CPPFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = --coverage

LDADD = $(CODE_COVERAGE_LIBS)

includesubdir = $(includedir)/oauth2

includesub_HEADERS = \
	src/liboauth2-sts/include/oauth2/sts.h

lib_LTLIBRARIES = @PACKAGE_NAME@.la

@PACKAGE_NAME@_la_CFLAGS = @OAUTH2_CFLAGS@ @OAUTH2_NGINX_CFLAGS@ @NGINX_CFLAGS@ @XML_CFLAGS@ -Isrc/liboauth2-sts/include
@PACKAGE_NAME@_la_LIBADD = @OAUTH2_LIBS@ @OAUTH2_NGINX_LIBS@ @NGINX_LIBS@ @XML_LIBS@ 
@PACKAGE_NAME@_la_SOURCES = \
	src/liboauth2-sts/src/sts_int.h \
	src/liboauth2-sts/src/sts.c \
	src/liboauth2-sts/src/wstrust.c \
	src/liboauth2-sts/src/ropc.c \
	src/liboauth2-sts/src/otx.c \
	src/@PACKAGE_NAME@.c \
	src/@PACKAGE_NAME@_modules.c
@PACKAGE_NAME@_la_LDFLAGS = -module

@CODE_COVERAGE_RULES@

clang-format:
	clang-format -style=file -i `find . -name *.[ch]`

install:
	sudo cp .libs/@PACKAGE_NAME@.so  /usr/local/nginx/modules/
