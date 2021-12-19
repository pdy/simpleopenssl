print-%  : ; @echo $* = $($*)

CXX := clang++
STRIP := strip

FLAGS := -std=c++17 -Wno-deprecated-register -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded

LD_FLAGS := -L../3rd/openssl/lib

OPENSSL_LIBS := -lssl -lcrypto

LD_LIBS := -pthread $(OPENSSL_LIBS)

INCLUDES := -isystemcmdline -isystem../include -isystem../3rd/openssl/include

BUILD = ./bin/release
CXXFLAGS = $(FLAGS) $(INCLUDES) -O3 -Wall
ifneq (,$(findstring debug,$(MAKECMDGOALS)))
	BUILD = ./bin/debug
	CXXFLAGS = $(FLAGS) $(INCLUDES) -g -Weverything
	STRIP = echo
endif

.PHONY: all clean debug release

all: post-build 
debug: all
release: all

pre-build:
	@mkdir -p $(BUILD) 

post-build: main-build
	@$(STRIP) $(BUILD)/*

main-build: pre-build
	@$(MAKE) --no-print-directory $(BUILD)/hashfile
	@$(MAKE) --no-print-directory $(BUILD)/rsakeygen
	@$(MAKE) --no-print-directory $(BUILD)/x509info
	@$(MAKE) --no-print-directory $(BUILD)/ecdsa_self_signed_gen

clean:
	@rm -r ./bin

$(BUILD)/%: ./%.cpp
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LD_FLAGS) $(LD_LIBS)
	@echo "$@"
