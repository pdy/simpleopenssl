print-%  : ; @echo $* = $($*)

CXX := clang++
STRIP := strip

# -frtti is required by boost, which is linked staticly
MANUAL_FLAGS := -std=c++14 -frtti -fexceptions -Wno-deprecated-register
FLAGS := $(MANUAL_FLAGS)

LD_FLAGS := -L./3rd/gtest/lib -L./3rd/openssl/lib

GTEST := -lgtest -lgmock -lgmock_main
OPENSSL_LINKING := -lssl -lcrypto

LD_LIBS := -pthread $(OPENSSL_LINKING)

INCLUDES := -I./include/ -I./3rd/openssl/include -I./3rd/gtest/include
ROOT_BUILD := ./build

ifeq ($(MAKECMDGOALS),debug)
	BUILD = $(ROOT_BUILD)/debug
	CXXFLAGS = $(FLAGS) $(INCLUDES) -g -Wall 
	STRIP = echo
else
	BUILD = $(ROOT_BUILD)/release
	CXXFLAGS = $(FLAGS) $(INCLUDES) -O3 -Wall	
endif

OBJ := $(BUILD)/obj

.PHONY: all clean

DESTBIN := $(BUILD)/bin

all: dist $(DESTBIN)/UnitTests strip
debug: all

dist:
	@mkdir -p $(OBJ) $(DESTBIN)
	
clean:
	@rm -r $(BUILD) $(ROOT_BUILD)

strip:
	$(STRIP) $(DESTBIN)/*

OBJS_UT := $(OBJ)/EcdsaUT.o $(OBJ)/EvpUT.o $(OBJ)/EcdsaKeyUT.o $(OBJ)/EvpKeyUT.o $(OBJ)/HashUT.o

$(DESTBIN)/UnitTests: $(OBJS_UT)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LD_FLAGS) $(GTEST) $(LD_LIBS)

$(OBJ)/%.o: ./test/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $^

$(OBJ)/EcdsaUT.o: ./test/EcdsaUT.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $^

$(OBJ)/EcdsaKeyUT.o: ./test/EcdsaKeyUT.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $^

$(OBJ)/EvpUT.o: ./test/EvpUT.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $^

$(OBJ)/EvpKeyUT.o: ./test/EvpKeyUT.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $^

$(OBJ)/HashUT.o: ./test/HashUT.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $^
