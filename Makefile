.PHONY: lint-projection
lint-projection:
	go run ./cmd/lint-projection ./pkg/rules
