.phony: run-dev, test, clean

clean:
	rm -rf target

run-dev:
	clojure -X:dev:run

test:
	clojure -X:test
