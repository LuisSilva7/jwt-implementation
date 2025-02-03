APP_NAME = url-shortener
SRC = $(wildcard *.go config/*.go)  # Include all Go files in root and config directory

.PHONY: build run clean

# Compile the project
build:
	go build -o $(APP_NAME) $(SRC)

# Run the server
run: build
	@echo "\n"
	./$(APP_NAME)

# Remove compiled files
clean:
	rm -f $(APP_NAME)
