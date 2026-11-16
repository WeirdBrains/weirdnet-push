# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Wake payloads: 96 bytes sealed to the device's push key and handle, with a replay guard.
- Wake handles and control secrets, with rotation and revocation, and wake cards for peers.
- A client for registering, rotating, unregistering, waking and following announcements.
- A self-hostable server delivering through APNs, FCM and relay announcements.

[Unreleased]: https://github.com/WeirdBrains/weirdnet-push/commits/main
