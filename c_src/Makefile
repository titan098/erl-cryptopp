DEPS=../deps

ifndef CRYPTOPP_VERSION 
CRYPTOPP_VERSION=562
endif

all: $(DEPS)/cryptopp/libcryptopp.a

clean:
	if test -e $(DEPS)/cryptopp/GNUMakefile; then \
		cd $(DEPS)/cryptopp; make clean; \
	else \
		true; \
	fi

distclean:
	@rm -rf $(DEPS)

$(DEPS):
	@mkdir -p $(DEPS) && cp cryptopp$(CRYPTOPP_VERSION).patch $(DEPS)

$(DEPS)/cryptopp$(CRYPTOPP_VERSION).zip: $(DEPS)
	@curl -z $(DEPS)/cryptopp$(CRYPTOPP_VERSION).zip http://www.cryptopp.com/cryptopp$(CRYPTOPP_VERSION).zip -o $(DEPS)/cryptopp$(CRYPTOPP_VERSION).zip

$(DEPS)/cryptopp: $(DEPS)/cryptopp$(CRYPTOPP_VERSION).zip
	@cd $(DEPS) && unzip -d cryptopp cryptopp$(CRYPTOPP_VERSION).zip

$(DEPS)/cryptopp/libcryptopp.a: $(DEPS)/cryptopp
	@cd $(DEPS)/cryptopp && make libcryptopp.a
