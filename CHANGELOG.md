# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-16

### Added

- Wake payloads: 96 bytes sealed to the device's push key and handle, with a replay guard.
- Wake handles and control secrets, with rotation and revocation, and wake cards for peers.
- A client for registering, rotating, unregistering, waking and following announcements.
- A self-hostable server delivering through APNs, FCM and relay announcements.
- The relay wake path's wire protocol (`/weirdnet/wake/1`): device subscriptions and sender deliveries.

[Unreleased]: https://github.com/WeirdBrains/weirdnet-push/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/WeirdBrains/weirdnet-push/compare/d0b62bdf920884a8a1801cbec0a38a58c4a79ded...v0.1.0
