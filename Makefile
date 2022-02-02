.phony: run-dev, test, clean, keycloak-demo

clean:
	rm -rf target

run-dev:
	clojure -X:dev:run

test:
	clojure -X:test

keycloak-demo:
	cd keycloak; docker compose up
