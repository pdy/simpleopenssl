print-%  : ; @echo $* = $($*)

CXX := clang++
STRIP := strip

FLAGS := -std=c++17 -Wno-deprecated-register -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded

LD_FLAGS := -L../3rd/openssl/lib

OPENSSL_LIBS := -lssl -lcrypto

LD_LIBS := -pthread $(OPENSSL_LIBS)

INCLUDES := -isystem../include -isystem../3rd/openssl/include

ifeq ($(MAKECMDGOALS),debug)
	BUILD = ./bin/debug
	CXXFLAGS = $(FLAGS) $(INCLUDES) -g -Weverything
	STRIP = echo
else
	BUILD = ./bin/release
	CXXFLAGS = $(FLAGS) $(INCLUDES) -O3 -Wall
endif

.PHONY: all clean

all: post-build 
debug: all

pre-build:
	@mkdir -p $(BUILD) 

post-build: main-build
	$(STRIP) $(BUILD)/*

main-build: pre-build
	@$(MAKE) --no-print-directory $(BUILD)/hashfile
	@$(MAKE) --no-print-directory $(BUILD)/rsakeygen
	@$(MAKE) --no-print-directory $(BUILD)/x509info
	@$(MAKE) --no-print-directory $(BUILD)/not_finished_ecdsa_self_signed

clean:
	@rm -r ./bin

# PROGRAMS: $(BUILD)/hashfile $(BUILD)/rsakeygen $(BUILD)/x509info $(BUILD)/ecdsa_self_signed

$(BUILD)/%: ./%.cpp
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LD_FLAGS) $(LD_LIBS)
	@echo "$<"
