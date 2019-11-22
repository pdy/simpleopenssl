print-%  : ; @echo $* = $($*)

CXX := clang++
STRIP := strip

FLAGS := -std=c++14 -Wno-deprecated-register -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded

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

all: dist PROGRAMS strip
debug: all

dist:
	@mkdir -p $(BUILD) 
	
clean:
	@rm -r ./bin

strip:
	$(STRIP) $(BUILD)/*

PROGRAMS: $(BUILD)/hashfile $(BUILD)/rsa

$(BUILD)/%: ./%.cpp
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LD_FLAGS) $(LD_LIBS)
	@echo "$<"
