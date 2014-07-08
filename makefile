CC := cc
CP := cp
RM := rm

SRCDIR := src
BUILDDIR := build
SRCEXT := c
BUILDEXT := o

SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/lib/%,$(SOURCES:.$(SRCEXT)=.$(BUILDEXT)))

CFLAGS := -DPIC -DSLAPD_OVER_LATCH=SLAPD_MOD_DYNAMIC -fPIC -g -O0
LIB := -lcurl -lcrypto -ldl -ljson -lpcre -lssl -pthread -shared
INC := -I${OPENLDAP_DIR}/include -I${OPENLDAP_DIR}/servers/slapd
TARGET := dist/lib/latch-overlay.so

all: ${TARGET}

$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@mkdir -p dist/lib
	@echo " $(CC) $^ -o $(TARGET) $(LIB)"; $(CC) $^ -o $(TARGET) $(LIB)

$(BUILDDIR)/lib/%.$(BUILDEXT): $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)/lib
	@echo " $(CC) $(CFLAGS) $(INC) -c -o $@ $<" ; $(CC) $(CFLAGS) $(INC) -c -o $@ $<
	
clean:
	@echo " Cleaning..."; 
	@echo " $(RM) -rf $(BUILDDIR) $(TARGET)"; $(RM) -rf $(BUILDDIR) $(TARGET)