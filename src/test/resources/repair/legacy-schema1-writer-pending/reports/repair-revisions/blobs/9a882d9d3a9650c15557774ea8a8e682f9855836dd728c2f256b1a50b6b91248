CC ?= gcc
CFLAGS ?= -std=c11 -g -Wall -Wextra -Iinclude
REPRODUCIBLE_CFLAGS := "-ffile-prefix-map=$$PWD=." "-fdebug-prefix-map=$$PWD=." "-fmacro-prefix-map=$$PWD=."
TARGET ?= build/reconstructed
SOURCES := src/main.c src/modules/alpha.c src/modules/beta.c src/modules/charlie.c src/modules/delta.c
ACTUAL_SOURCES := $(sort $(shell find src -type f -name '*.c'))
EXPECTED_SOURCES := $(sort $(SOURCES))
ifneq ($(ACTUAL_SOURCES),$(EXPECTED_SOURCES))
$(error source tree contains missing or unowned C files; expected '$(EXPECTED_SOURCES)', found '$(ACTUAL_SOURCES)')
endif
OBJECTS := $(SOURCES:src/%.c=build/%.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo "[link] $@"
	@$(CC) $(CFLAGS) $(REPRODUCIBLE_CFLAGS) $(OBJECTS) -o $@

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	@echo "[compile] $< -> $@"
	@$(CC) $(CFLAGS) $(REPRODUCIBLE_CFLAGS) -MMD -MP -c $< -o $@

clean:
	rm -rf build

-include $(OBJECTS:.o=.d)
.PHONY: all clean
