.phony: run-dev, test, clean, keycloak-demo

clean:
	rm -rf target

run-dev:
	clojure -X:dev:run

test:
	clojure -X:test

keycloak-demo:
	cd keycloak; docker compose up

.PHONY: pom.xml

pom.xml:
	clojure -X:deps mvn-pom :user nil
