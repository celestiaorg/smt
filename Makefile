.SILENT:

help:
	printf "Available targets\n\n"
	awk '/^[a-zA-Z\-\_0-9]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")-1); \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			printf "%-30s %s\n", helpCommand, helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)

.PHONY: test_all
## Run all the unit tests
test_all:
	go test -v -count=1 ./...

.PHONY: test_smt
## Run all the ^TestSparseMerkleTree unit tests
test_smt:
	go test -v -count=1 -run TestSparseMerkleTree ./...

.PHONY: test_th
## Run all the ^TestTreeHasher unit tests
test_th:
	go test -v -count=1 -run TestTreeHasher ./...

.PHONY: test_ms
## Run all the ^TestMapStore unit tests
test_ms:
	go test -v -count=1 -run TestMapStore ./...