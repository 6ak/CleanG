
ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

RTE_TARGET ?= $(RTE_TARGET)

# Default target, can be overriden by command line or environment
include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = clean_core_control

# all source are stored in SRCS-y
SRCS-y := clean_core_control.c

# OpenNetVM path
ONVM= $(SRCDIR)/../../onvm

CFLAGS += $(WERROR_FLAGS) -O3 -g

CFLAGS += -I$(ONVM)/onvm_nflib
CFLAGS += -I$(ONVM)/lib
LDFLAGS += $(ONVM)/onvm_nflib/$(RTE_TARGET)/libonvm.a
LDFLAGS += $(ONVM)/lib/$(RTE_TARGET)/lib/libonvmhelper.a -lm

include $(RTE_SDK)/mk/rte.extapp.mk
