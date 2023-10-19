#!/bin/bash

mkdir -p deploy/liquibase/data/

cp -r ../docs/db/changelog/changesets/powerauth-test-server deploy/liquibase/data/