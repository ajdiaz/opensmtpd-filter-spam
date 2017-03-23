OPENSMTPD_SMTPD_USER = smtpd
OPENSMTPD_SMTPQ_USER = smtpq

# This is commit of the OpenSMTPD-extras repository according for current
# required API version. If you change it, probably filter-spam do not
# compile well, but it's up to you.
#OPENSMTPD_EXTRAS_REF = fa95f9ff8b88692d64a1037ad1bfb5b67337fabe
#OPENSMTPD_EXTRAS_REF = master
OPENSMTPD_EXTRAS_REF = 751c7b6b56a13a2381485daf0f97dd7fc0da289e

OPENSMTPD_EXTRAS_DIR = opensmtpd-extras
OPENSMTPD_EXTRAS_PATH = $(SRCDIR)/$(OPENSMTPD_EXTRAS_DIR)

OPENSMTPD_REQS = $(OPENSMTPD_EXTRAS_DIR)/api/util.o \
    $(OPENSMTPD_EXTRAS_DIR)/api/tree.o \
    $(OPENSMTPD_EXTRAS_DIR)/api/iobuf.o \
    $(OPENSMTPD_EXTRAS_DIR)/api/ioev.o \
    $(OPENSMTPD_EXTRAS_DIR)/api/mproc.o \
    $(OPENSMTPD_EXTRAS_DIR)/api/filter_api.o \
    $(OPENSMTPD_EXTRAS_DIR)/api/log.o \
    $(OPENSMTPD_EXTRAS_DIR)/api/dict.o \
    $(OPENSMTPD_EXTRAS_DIR)/api/rfc2822.o \
    $(OPENSMTPD_EXTRAS_DIR)/openbsd-compat/libopenbsd-compat.a

BINS = filter-spam
REQS = filter_spam.o dnsbl.o spf.o pause.o grey.o $(OPENSMTPD_REQS)

CFLAGS += \
		-I$(SRCDIR) \
		-I$(OPENSMTPD_EXTRAS_PATH)/api \
    -I$(OPENSMTPD_EXTRAS_PATH)/openbsd-compat/ \
    -I$(OPENSMTPD_EXTRAS_PATH)/ \
    -L$(OPENSMTPD_EXTRAS_PATH)/openbsd-compat/ \
    -DHAVE_CONFIG_H \
    -D_FORTIFY_SOURCE=2 \
    -O2 \
    -fstack-protector-strong \
    -Wformat \
    -Werror=format-security \
    -fPIC \
    -DPIC \
    -Wall \
    -Wpointer-arith \
    -Wuninitialized \
    -Wsign-compare \
    -Wformat-security \
    -Wsizeof-pointer-memaccess \
    -Wno-pointer-sign \
    -Wno-unused-result \
    -fno-strict-aliasing \
    -fno-builtin-memset \
    -DBUILD_FILTER

LDFLAGS += -L$(OPENSMTPD_EXTRAS_PATH)/openbsd-compat/ \
  	-lopenbsd-compat \
    -levent \
    -lspf2 \
    -lssl \
    -ldb \
    -lcrypto

filter-spam  := $(REQS)

bootstrap:
	@[[ -x $(OPENSMTPD_EXTRAS_PATH)/bootstrap ]] || ( \
			cd $(SRCDIR); ls; \
			./bootstrap "$(OPENSMTPD_EXTRAS_DIR)" \
									"$(OPENSMTPD_EXTRAS_REF)" \
									"$(OPENSMTPD_SMTPD_USER)" \
									"$(OPENSMTPD_SMTPQ_USER)"; )
	$(MAKE) all

mrproper: clean
	@rm -rf $(OPENSMTPD_EXTRAS_PATH)
