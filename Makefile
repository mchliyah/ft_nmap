# ===== Project Config =====
NAME        := ft_nmap
SRCS_DIR    := src
OBJ_DIR     := obj
INC_DIR     := include

# ===== Compiler & Flags =====
CC            := cc
CFLAGS        := -Wall -Wextra -Werror
DEBUG_FLAGS   := -g3 -O0 -fsanitize=address
RELEASE_FLAGS := #-O2
LIBS          := -lpcap -lpthread

# ===== Automatic File Detection =====
SRCS        := $(wildcard $(SRCS_DIR)/*.c)
OBJS        := $(patsubst $(SRCS_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
DEPS        := $(OBJS:.o=.d)   # For dependency tracking

# ===== Build Mode (Debug/Release) =====
BUILD_MODE  ?= RELEASE  # Default to RELEASE, override with `make BUILD_MODE=DEBUG`

ifeq ($(BUILD_MODE),DEBUG)
    CFLAGS += $(DEBUG_FLAGS)
else
    CFLAGS += $(RELEASE_FLAGS)
endif

# ===== Rules =====
.PHONY: all clean fclean re debug release

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS)
	@echo "✅ Build completed: $(NAME) ($(BUILD_MODE) mode)"

$(OBJ_DIR)/%.o: $(SRCS_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -MMD -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $@

# ===== Debug & Release Shortcuts =====
debug: BUILD_MODE = DEBUG
debug: clean all

release: BUILD_MODE = RELEASE
release: clean all

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