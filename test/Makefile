print-%  : ; @echo $* = $($*)

CXX := clang++
STRIP := strip

PROJ_ROOT := ..
OPENSSL_PATH := $(PROJ_ROOT)/3rd/openssl_1.1.0f
GTEST_PATH := $(PROJ_ROOT)/3rd/gtest
TEST_PATH := $(PROJ_ROOT)/test

# suppress GTEST warnings
TEST_FLAGS := -Wno-global-constructors -Wno-exit-time-destructors -Wno-missing-prototypes -Wno-weak-vtables \
	-Wno-missing-variable-declarations -Wno-gnu-zero-variadic-macro-arguments

FLAGS := -std=c++11 -Wno-deprecated-register -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded

LD_FLAGS := -L$(GTEST_PATH)/lib -L$(OPENSSL_PATH)/lib

GTEST_LIBS := -lgtest -lgmock -lgmock_main
OPENSSL_LIBS := -lssl -lcrypto

LD_LIBS := -Wl,-Bstatic $(OPENSSL_LIBS) -Wl,-Bdynamic -pthread -ldl

INCLUDES := -I$(PROJ_ROOT)/include/ -isystem$(OPENSSL_PATH)/include -isystem$(GTEST_PATH)/include
ROOT_BUILD := $(PROJ_ROOT)/build

ifeq ($(MAKECMDGOALS),release)
	BUILD = $(ROOT_BUILD)/release
	CXXFLAGS = $(FLAGS) $(INCLUDES) -O3 -Wall
else	
	BUILD = $(ROOT_BUILD)/debug
	CXXFLAGS = $(FLAGS) $(INCLUDES) -g -Weverything
	STRIP = echo
endif

SRC_TEST := $(wildcard $(TEST_PATH)/*cpp)
SRC_X509_TEST := $(wildcard $(TEST_PATH)/x509/*cpp)
SRC_ECDSA_TEST := $(wildcard $(TEST_PATH)/ecdsa/*cpp)
SRC_RSA_TEST := $(wildcard $(TEST_PATH)/rsa/*cpp)
SRC_HASH_TEST := $(wildcard $(TEST_PATH)/hash/*cpp)
SRC_NID_TEST := $(wildcard $(TEST_PATH)/nid/*cpp)
SRC_EVP_TEST := $(wildcard $(TEST_PATH)/evp/*cpp)

OBJ_DIR := $(BUILD)/obj
OBJS_TEST := $(patsubst $(TEST_PATH)/%.cpp,$(OBJ_DIR)/%.o, $(SRC_TEST))

OBJ_X509_DIR := $(OBJ_DIR)/x509
OBJS_X509_TEST := $(patsubst $(TEST_PATH)/x509/%.cpp,$(OBJ_X509_DIR)/%.o, $(SRC_X509_TEST))

OBJ_ECDSA_DIR := $(OBJ_DIR)/ecdsa
OBJS_ECDSA_TEST := $(patsubst $(TEST_PATH)/ecdsa/%.cpp,$(OBJ_ECDSA_DIR)/%.o, $(SRC_ECDSA_TEST))

OBJ_RSA_DIR := $(OBJ_DIR)/rsa
OBJS_RSA_TEST := $(patsubst $(TEST_PATH)/rsa/%.cpp,$(OBJ_RSA_DIR)/%.o, $(SRC_RSA_TEST))

OBJ_HASH_DIR := $(OBJ_DIR)/hash
OBJS_HASH_TEST := $(patsubst $(TEST_PATH)/hash/%.cpp,$(OBJ_HASH_DIR)/%.o, $(SRC_HASH_TEST))

OBJ_NID_DIR := $(OBJ_DIR)/nid
OBJS_NID_TEST := $(patsubst $(TEST_PATH)/nid/%.cpp,$(OBJ_NID_DIR)/%.o, $(SRC_NID_TEST))

OBJ_EVP_DIR := $(OBJ_DIR)/evp
OBJS_EVP_TEST := $(patsubst $(TEST_PATH)/evp/%.cpp,$(OBJ_EVP_DIR)/%.o, $(SRC_EVP_TEST))

.PHONY: all clean

DESTBIN := $(BUILD)/bin

all: dist $(DESTBIN)/UnitTests copydata strip
debug: all
release: all

dist:
	@mkdir -p $(OBJ_DIR) \
		$(OBJ_X509_DIR) \
		$(OBJ_HASH_DIR) \
		$(OBJ_RSA_DIR) \
		$(OBJ_ECDSA_DIR) \
		$(OBJ_NID_DIR) \
		$(OBJ_EVP_DIR) \
		$(DESTBIN)
	
clean:
	@rm -r $(ROOT_BUILD)

copydata:
	@cp -r $(TEST_PATH)/data $(DESTBIN)/

strip:
	$(STRIP) $(DESTBIN)/UnitTests

$(DESTBIN)/UnitTests: $(OBJS_TEST) \
	$(OBJS_X509_TEST) $(OBJS_HASH_TEST) \
	$(OBJS_RSA_TEST) \
	$(OBJS_ECDSA_TEST) \
	$(OBJS_NID_TEST) \
	$(OBJS_EVP_TEST)
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -o $@ $^ $(LD_FLAGS) $(GTEST_LIBS) $(LD_LIBS)
	@echo "$<"

$(OBJ_DIR)/%.o: $(TEST_PATH)/%.cpp
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^
	@echo "$<"

$(OBJ_X509_DIR)/%.o: $(TEST_PATH)/x509/%.cpp
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^
	@echo "$<"

$(OBJ_HASH_DIR)/%.o: $(TEST_PATH)/hash/%.cpp
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^
	@echo "$<"

$(OBJ_NID_DIR)/%.o: $(TEST_PATH)/nid/%.cpp
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^
	@echo "$<"

$(OBJ_EVP_DIR)/%.o: $(TEST_PATH)/evp/%.cpp
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^
	@echo "$<"

(OBJ_RSA_DIR)/%.o: $(TEST_PATH)/rsa/%.cpp
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^
	@echo "$<"


$(OBJ_ECDSA_DIR)/%.o: $(TEST_PATH)/ecdsa/%.cpp
	@$(CXX) $(CXXFLAGS) $(TEST_FLAGS) -c -o $@ $^
	@echo "$<"

