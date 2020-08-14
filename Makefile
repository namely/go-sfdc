.PHONY: test-local
test-local:
	go test `go list ./... | grep -v '/mocks' | grep -v '/gen'` -cover -count=1

.PHONY: test
test:
	go test `go list ./... | grep -v '/mocks' | grep -v '/gen'` -cover -count=1 -coverprofile=coverage.txt -covermode=count

.PHONY: docs
docs:
	godoc -http=:6060 &
