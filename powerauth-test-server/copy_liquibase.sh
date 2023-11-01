#!/bin/bash

mkdir -p powerauth-test-server/deploy/liquibase/data/

cp -r docs/db/changelog/changesets/powerauth-test-server deploy/liquibase/data/