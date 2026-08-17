# PowerAuth Tests

Multi-module Maven project (`com.wultra:powerauth-backend-tests-parent`) holding integration,
load, and FIDO2 tests plus a helper REST server for the PowerAuth stack. Built on Spring Boot
(parent `spring-boot-starter-parent`), Java 21 in CI, Lombok everywhere.

## Modules

- **powerauth-backend-tests** — JUnit 5 end-to-end tests of the PowerAuth protocol. The
  interesting code lives under `src/test` (the `src/main` part is just supporting config/util).
- **powerauth-test-server** — Spring Boot `war` exposing a REST API that wraps PowerAuth crypto
  actions via the embedded `powerauth-java-cmd-lib`. Has a Liquibase schema. AGPLv3 (not Apache).
- **powerauth-fido2-tests** — Spring Boot `war` web app for manually exercising WebAuthN/FIDO2
  ceremonies against a PowerAuth Server. Thymeleaf templates in `src/main/resources/templates`.
- **powerauth-load-tests** — Gatling load tests. Simulations are **Scala** under
  `src/test/scala`; supporting Java helpers under `src/test/java`.

## Build / test commands

```shell
# Build everything
mvn clean package

# Build a single module (e.g. the test server war)
mvn -pl powerauth-test-server clean package

# Run the backend integration tests (requires a running stack, see below)
mvn -pl powerauth-backend-tests test

# Run a single test class / method
mvn -pl powerauth-backend-tests test -Dtest=PowerAuthActivationTest
mvn -pl powerauth-backend-tests test -Dtest='PowerAuthActivationTest#testActivation'

# Run a Gatling load simulation
mvn -pl powerauth-load-tests gatling:test \
  -Dgatling.simulationClass=com.wultra.security.powerauth.test.PowerAuthLoadTest \
  -DconfigFile=path/to/config.json
```

There is no separate lint step; the build relies on standard Maven/compiler checks.

### Repositories profile

PowerAuth depends on `*-SNAPSHOT` artifacts. By default the **public** profile resolves them from
the Sonatype snapshots repo. Inside Wultra, pass `-DuseInternalRepo=true` to use the internal JFrog
Artifactory (requires `INTERNAL_USERNAME` / `INTERNAL_PASSWORD`). CI uses the internal repo.

## Running the backend tests is not self-contained

`powerauth-backend-tests` exercise a **live** PowerAuth stack — they do not start it. You must have
`powerauth-java-server` and `enrollment-server` (and for some tests `enrollment-server-onboarding`)
running and reachable. Service URLs and all `powerauth.test.*` switches are in
`powerauth-backend-tests/src/test/resources/application.properties` (default ports 58080/58081/58082).
Building dev `-SNAPSHOT` versions of those backends from source is described in
`powerauth-backend-tests/README.md`.

## Test conventions (powerauth-backend-tests)

- Tests are organized by **protocol version**: packages `v30`, `v31`, `v32`, `v33`, `v3x`, `v40`,
  `v4x`. Each version-specific test class is a thin wrapper that delegates the actual assertions to
  a version-shared logic class in `test/shared/v3` or `test/shared/v4` (e.g. `PowerAuthActivationTest`
  calls `PowerAuthActivationShared`). When adding a scenario, put reusable logic in the shared class
  and add per-version entry points, rather than duplicating logic across versions.
- Each test class declares its target version via a constant, e.g.
  `private static final PowerAuthVersion VERSION = PowerAuthVersion.V4_0;`.
- Most classes use `@SpringBootTest(classes = PowerAuthTestConfiguration.class)`; tests that need an
  HTTP callback endpoint use `webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT`.
- **Custom / customization-dependent tests** (onboarding, identity verification, some encryption and
  activation-code tests) are gated with
  `@EnabledIf(expression = "${powerauth.test.includeCustomTests}", loadContext = true)`. They run
  only when `powerauth.test.includeCustomTests=true`. The nightly integration workflow toggles this
  via the `POWERAUTH_TEST_INCLUDECUSTOMTESTS` env var.
- OIDC activation tests are skipped unless the `powerauth.test.activation.oidc.*` properties are set.

## Test server DB / migrations

`powerauth-test-server` schema is managed by Liquibase. The master changelog lives in
`docs/db/changelog/db.changelog-master.xml` with versioned changesets under
`docs/db/changelog/changesets/powerauth-test-server/`. Plain DDL for PostgreSQL is in `docs/sql/postgresql`.
Liquibase is opt-in: enable with the `liquibase` build profile / `LIQUIBASE_ENABLED` (Spring) or
`LQ_ENABLED` (Docker) env var. H2 is fine for local dev; PostgreSQL is recommended for automated runs.

## Conventions

- Lombok is enabled project-wide; the logger field is named `logger` (`lombok.log.fieldName=logger`),
  so use `logger.info(...)`, not `log.info(...)`.
- License headers: most modules are Apache 2.0, but **`powerauth-test-server` is GNU AGPLv3** — match
  the header of surrounding files in the module you edit.
- `.run/` holds IntelliJ run configurations for the test server and FIDO2 app.

## Changelog

`CHANGELOG.md` lives at the repository root. Update it before creating a pull request when a change
has a user-visible impact.

### Format

Strictly follow [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html):

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added a new test scenario [(#N)](https://github.com/wultra/powerauth-tests/issues/N)

## [1.2.3] - 2025-03-01

### Fixed

- Fixed a human-readable issue description [(#N)](https://github.com/wultra/powerauth-tests/issues/N)

[unreleased]: https://github.com/wultra/powerauth-tests/compare/1.2.3...HEAD
[1.2.3]: https://github.com/wultra/powerauth-tests/compare/1.2.2...1.2.3
```

Use only the change-type subsections that apply:

- `Added` — new features
- `Changed` — changes in existing functionality
- `Deprecated` — soon-to-be removed features
- `Removed` — removed features
- `Fixed` — bug fixes
- `Security` — security vulnerability fixes

Rules:

- Add new entries under `## [Unreleased]`.
- Start each entry with a verb and use a human-readable description rather than a raw commit message.
- Link each entry to the issue using
  `[(#N)](https://github.com/wultra/powerauth-tests/issues/N)`, not to the pull request.
- On release, rename `## [Unreleased]` to `## [x.y.z] - YYYY-MM-DD`, add a new empty
  `## [Unreleased]` above it, update the `[unreleased]` compare link, and add the released version's
  compare link.
- Add entries for new or changed user-facing documentation, such as API references, configuration,
  deployment, migration, or feature documentation.
- Skip entries for pure CI/tooling changes, internal documentation, code comments, Javadoc, minor
  wording fixes, typo fixes, broken-link fixes, and incomplete documentation. Add an entry when a
  documentation correction fixes a materially incorrect user instruction.

## CI

- `.github/workflows/maven-test.yml` — unit-level build on push/PR to `develop`/`master`/`releases/**`
  (Java 21, shared Wultra workflow).
- `.github/workflows/maven-integration-test.yml` — nightly + manual; runs
  `mvn -pl powerauth-backend-tests test -DuseInternalRepo=true` against the internal repo and publishes
  a JUnit report. Manual runs accept an `includeCustomTests` input.
- Separate `maven-deploy-*` and `publish-docker-image-*` workflows release the test server and FIDO2 app.
