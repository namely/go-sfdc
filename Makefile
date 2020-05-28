.PHONY: test-local
test-local:
	go test `go list ./... | grep -v '/mocks' | grep -v '/gen'` -cover -count=1

.PHONY: docs
docs:
	godoc -http=:6060 &
