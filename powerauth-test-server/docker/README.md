# How to Build Docker


## Build War

```shell
mvn -pl powerauth-test-server clean package
```


## Build the docker image

```shell
docker build ./powerauth-test-server -t powerauth-test-server:1.5.0
```


## Prepare environment variables

* Copy `deploy/env.list.tmp` to `./env.list` and edit the values to use it via `docker run --env-file env.list IMAGE`
* Or set environment variables via `docker run -e POWERAUTH_TEST_SERVER_DATASOURCE_USERNAME='powerauth' IMAGE`


## Run the docker image

```shell
docker run -p 80:8080 powerauth-test-server:1.5.0
```
