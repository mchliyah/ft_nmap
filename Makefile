# ===== Project Config =====
NAME        := ft_nmap
SRCS_DIR    := src
OBJ_DIR     := obj
INC_DIR     := include

# ===== Compiler & Flags =====
CC            := cc
CFLAGS        := -Wall -Wextra -Werror
DEBUG_FLAGS   := -g3 -O0 -fsanitize=address
RELEASE_FLAGS := -O2
LIBS          := -lpcap -lpthread

# ===== Automatic File Detection =====
SRCS        := $(wildcard $(SRCS_DIR)/*.c)
OBJS        := $(patsubst $(SRCS_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
DEPS        := $(OBJS:.o=.d)   # For dependency tracking

# ===== Build Mode (Debug/Release) =====
BUILD_MODE  ?= DEBUG  # Default to DEBUG for step-by-step debugging

ifeq ($(BUILD_MODE),DEBUG)
    CFLAGS += $(DEBUG_FLAGS)
    BUILD_MSG := DEBUG mode with -g3 -O0 -fsanitize=address
else
    CFLAGS += $(RELEASE_FLAGS)
    BUILD_MSG := RELEASE mode with -O2
endif

# ===== Rules =====
.PHONY: all clean fclean re debug release run gdb

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS)
	@echo "✅ Build completed: $(NAME) ($(BUILD_MSG))"

$(OBJ_DIR)/%.o: $(SRCS_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -MMD -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $@

# ===== Debug & Release Shortcuts =====
debug: 
	$(MAKE) BUILD_MODE=DEBUG all

release: 
	$(MAKE) BUILD_MODE=RELEASE all

# ===== Clean Build Shortcuts =====
debug-clean: clean
	$(MAKE) BUILD_MODE=DEBUG all

release-clean: clean
	$(MAKE) BUILD_MODE=RELEASE all

# ===== Run and Debug Shortcuts =====
run: $(NAME)
	./$(NAME)

run-debug: debug
	./$(NAME)

gdb: debug
	gdb ./$(NAME)

valgrind: debug
	valgrind --tool=memcheck --leak-check=full --track-origins=yes ./$(NAME)

# ===== Clean =====
clean:
	@rm -rf $(OBJ_DIR)
	@echo "🧹 Object files removed!"

fclean: clean
	@rm -f $(NAME)
	@echo "🔥 $(NAME) deleted!"

re: fclean all

# ===== Dependency Inclusion =====
# Auto-generated .d files for header changes
-include $(DEPS)
