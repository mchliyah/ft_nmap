NAME = ft_nmap

### PATH ###
SRCS_PATH = src/
OBJ_DIR = obj

### FILES ###
SRC = main.c
OBJ = $(SRC:.c=.o)

SRCS = $(addprefix $(SRCS_PATH), $(SRC))
OBJS = $(addprefix $(OBJ_DIR)/, $(OBJ))

### COMPILER FLAGS ###
CC = cc
CFLAGS = -Wall -Wextra -Werror
# LIBS = -lpcap -lpthread

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

$(OBJ_DIR)/%.o: $(SRCS_PATH)%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all
