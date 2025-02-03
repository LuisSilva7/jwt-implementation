APP_NAME = jwt-implementation
SRC = $(wildcard cmd/*.go internal/**/*.go)  # Include all Go files in cmd and internal directories

.PHONY: build run clean

# Compile the project
build:
	go build -o $(APP_NAME) cmd/main/main.go

# Run the CLI application
run: build
	@echo "\n"
	./$(APP_NAME)

# Remove compiled binary
clean:
	rm -f $(APP_NAME)
