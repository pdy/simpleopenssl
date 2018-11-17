print-%  : ; @echo $* = $($*)

CXX := clang++
STRIP := strip

# suppress GTEST warnings
TEST_FLAGS := -Wno-global-constructors -Wno-exit-time-destructors -Wno-missing-prototypes -Wno-weak-vtables \
	-Wno-missing-variable-declarations -Wno-gnu-zero-variadic-macro-arguments

FLAGS := -std=c++14 -Wno-deprecated-register -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded

LD_FLAGS := -L./3rd/gtest/lib -L./3rd/openssl/lib

GTEST_LIBS := -lgtest -lgmock -lgmock_main
OPENSSL_LIBS := -lssl -lcrypto

LD_LIBS := -pthread $(OPENSSL_LIBS)

INCLUDES := -I./include/ -isystem./3rd/openssl/include -isystem./3rd/gtest/include
ROOT_BUILD := ./build

ifeq ($(MAKECMDGOALS),debug)
	BUILD = $(ROOT_BUILD)/debug
	CXXFLAGS = $(FLAGS) $(INCLUDES) -g -Weverything
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

OBJS_UT := $(OBJ)/Asn1UT.o $(OBJ)/EcdsaSignVerifyUT.o $(OBJ)/EvpSignVerifyUT.o $(OBJ)/EcdsaKeyUT.o \
	$(OBJ)/EcdsaKeyUT.o $(OBJ)/EcdsaKeyGenUT.o $(OBJ)/EcdsaSignatureConvertersUT.o $(OBJ)/EvpKeyUT.o \
	$(OBJ)/HashUT.o $(OBJ)/X509UT.o $(OBJ)/X509PemUT.o $(OBJ)/X509CertExtensionsUT.o $(OBJ)/BignumUT.o \
	$(OBJ)/RsaKeyUT.o

$(DESTBIN)/UnitTests: $(OBJS_UT)
	$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -o $@ $^ $(LD_FLAGS) $(GTEST_LIBS) $(LD_LIBS)

$(OBJ)/%.o: ./test/%.cpp
	$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^

