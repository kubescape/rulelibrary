.PHONY: lint-projection generate-rules-crd

generate-rules-crd:
	bash ./gen.sh

lint-projection:
	go run ./cmd/lint-projection ./pkg/rules
