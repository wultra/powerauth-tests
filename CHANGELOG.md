# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Set Hibernate DDL auto to `none` in `powerauth-test-server` ([#917](https://github.com/wultra/powerauth-tests/issues/917))

## [2.2.0] - 2026-07-23

### Added

- Added tests for secure configuration ([#916](https://github.com/wultra/powerauth-tests/issues/916))

### Changed

- Updated Spring Boot to version 4 ([#896](https://github.com/wultra/powerauth-tests/issues/896))
- Updated Spring Boot version ([#925](https://github.com/wultra/powerauth-tests/issues/925))
- Upgraded Docker base image to `ibm-semeru-runtimes:open-jdk-25.0.3.0-jre-noble` (OpenJDK 25) ([#913](https://github.com/wultra/powerauth-tests/issues/913))

### Fixed

- Fixed missing column `subject_id` in `audit_log` ([#906](https://github.com/wultra/powerauth-tests/issues/906))
- Fixed `consentRequired` flag for reactivation tests ([#888](https://github.com/wultra/powerauth-tests/issues/888))
- Fixed failing test for server status in protocol v4 ([#899](https://github.com/wultra/powerauth-tests/issues/899))
- Fixed `CryptoProviderException` handling in `ResultStatusService` ([#890](https://github.com/wultra/powerauth-tests/issues/890))
- Fixed formatting in JSON body for user creation request ([#931](https://github.com/wultra/powerauth-tests/pull/931))

[unreleased]: https://github.com/wultra/powerauth-tests/compare/2.2.0...HEAD
[2.2.0]: https://github.com/wultra/powerauth-tests/compare/2.1.0...2.2.0
