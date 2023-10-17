#!/bin/bash

mkdir -p deploy/liquibase/data/

cp -r powerauth-serverdocs/db/changesets/powerauth-test-server deploy/liquibase/data/powerauth-test-server