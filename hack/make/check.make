##@ Check
## Targets to be used to ensure code quality
.PHONY: verify-code
verify-code: vet ## Verify code formatting
	@diff -u <(echo -n) <(gofmt -s -d `find . -type f -name '*.go' -not -path "./vendor/*"`)

.PHONY: verify-manifests
verify-manifests: manifests ## Verify manifests update.
	git diff --exit-code ./config
	[ -z "$$(git ls-files --other --exclude-standard --directory --no-empty-directory ./config)" ]

.PHONY: verify-imports
verify-imports: ## Verify go imports are sorted and grouped correctly.
	hack/verify-imports.sh
