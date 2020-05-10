print-%  : ; @echo $* = $($*)

CXX := clang++
STRIP := strip

# suppress GTEST warnings
TEST_FLAGS := -Wno-global-constructors -Wno-exit-time-destructors -Wno-missing-prototypes -Wno-weak-vtables \
	-Wno-missing-variable-declarations -Wno-gnu-zero-variadic-macro-arguments

FLAGS := -std=c++11 -Wno-deprecated-register -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded

LD_FLAGS := -L./3rd/gtest/lib -L./3rd/openssl/lib

GTEST_LIBS := -lgtest -lgmock -lgmock_main
OPENSSL_LIBS := -lssl -lcrypto

LD_LIBS := -pthread $(OPENSSL_LIBS)

INCLUDES := -I./include/ -isystem./3rd/openssl/include -isystem./3rd/gtest/include
ROOT_BUILD := ./build

ifeq ($(MAKECMDGOALS),release)
	BUILD = $(ROOT_BUILD)/release
	CXXFLAGS = $(FLAGS) $(INCLUDES) -O3 -Wall
else	
	BUILD = $(ROOT_BUILD)/debug
	CXXFLAGS = $(FLAGS) $(INCLUDES) -g -Weverything
	STRIP = echo
endif

SRC_TEST := $(wildcard ./test/*cpp)
SRC_X509_TEST := $(wildcard ./test/x509/*cpp)
SRC_ECDSA_TEST := $(wildcard ./test/ecdsa/*cpp)
SRC_RSA_TEST := $(wildcard ./test/rsa/*cpp)

OBJ_DIR := $(BUILD)/obj
OBJS_TEST := $(patsubst ./test/%.cpp,$(OBJ_DIR)/%.o, $(SRC_TEST))
OBJ_X509_DIR := $(OBJ_DIR)/x509
OBJS_X509_TEST := $(patsubst ./test/x509/%.cpp,$(OBJ_X509_DIR)/%.o, $(SRC_X509_TEST))
OBJ_ECDSA_DIR := $(OBJ_DIR)/ecdsa
OBJS_ECDSA_TEST := $(patsubst ./test/ecdsa/%.cpp,$(OBJ_ECDSA_DIR)/%.o, $(SRC_ECDSA_TEST))
OBJ_RSA_DIR := $(OBJ_DIR)/rsa
OBJS_RSA_TEST := $(patsubst ./test/rsa/%.cpp,$(OBJ_RSA_DIR)/%.o, $(SRC_RSA_TEST))

.PHONY: all clean runUT

DESTBIN := $(BUILD)/bin

all: dist $(DESTBIN)/UnitTests copydata strip
debug: all

dist:
	@mkdir -p $(OBJ_DIR) \
		$(OBJ_X509_DIR) \
		$(OBJ_RSA_DIR) \
		$(OBJ_ECDSA_DIR) \
		$(DESTBIN)
	
clean:
	@rm -r $(BUILD) $(ROOT_BUILD)

copydata:
	@cp -r ./test/data $(DESTBIN)/

strip:
	$(STRIP) $(DESTBIN)/UnitTests

runUT:
	@cd $(DESTBIN)/ && ./UnitTests && cd -


$(DESTBIN)/UnitTests: $(OBJS_TEST) $(OBJS_X509_TEST) $(OBJS_RSA_TEST) $(OBJS_ECDSA_TEST)
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -o $@ $^ $(LD_FLAGS) $(GTEST_LIBS) $(LD_LIBS)
	@echo "$<"

$(OBJ_DIR)/%.o: ./test/%.cpp
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^
	@echo "$<"

$(OBJ_X509_DIR)/%.o: ./test/x509/%.cpp
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^
	@echo "$<"

$(OBJ_RSA_DIR)/%.o: ./test/rsa/%.cpp
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^
	@echo "$<"

$(OBJ_ECDSA_DIR)/%.o: ./test/ecdsa/%.cpp
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^
	@echo "$<"

