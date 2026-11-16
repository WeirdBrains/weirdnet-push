# weirdnet-push

Push wake-up for Weirdnet devices. A suspended phone can't keep a connection, so a peer or
the home relay that holds sealed messages for it asks a push service to wake it. This crate
is that service, its client, and the payload format.

- **Wake payloads** ([`wake`]): exactly 96 bytes, sealed to the device's push key (X25519,
  HKDF-SHA256, ChaCha20-Poly1305, a fresh key per payload) and bound to its handle. Inside
  is only a reason code (message waiting, connection requested), a random value and a time.
  [`ReplayGuard`] refuses repeats and stale wakes on the device.
- **Wake handles** ([`handle`]): 32 random bytes. The device shares its handle and push
  public key ([`WakeCard`]) only with its home relay and trusted peers, sealed. A control
  secret it keeps rotates the handle (the old one stops at once) or revokes it: the
  per-device off switch.
- **Client** ([`PushClient`], feature `client`, on by default): register, rotate,
  unregister, wake, and follow relay announcements.
- **Server** (feature `server`, the `weirdnet-push` binary): self-hostable; delivers through
  APNs (token auth, alert push with `mutable-content` for a Notification Service Extension;
  iOS background wake needs it), FCM HTTP v1 (high-priority data message, for Play builds),
  and the relay wake path (opt-in on the device: relays following the server pass the
  payload to devices connected to them, for F-Droid and builds without Google services).
  A token the provider rejects revokes its handle.

## What each party sees

| Party | Sees |
| --- | --- |
| Apple / Google | the device token, the time, and 96 bytes of ciphertext (the alert text is a fixed placeholder; the device writes the real one after decrypting) |
| The push service | the handle's hash and the device token (stored), the handle and time (per wake) |
| Relays carrying announcements | the handle, the time, the ciphertext |
| Senders | the handle and push public key they were given |

Nobody but the device sees the reason, and nobody sees message content, the sender,
peer ids, addresses or site names. The server stores only SHA-256 hashes of handles and
control secrets, and logs no handles or tokens.

## Running the server

```sh
cargo install weirdnet-push --features server
weirdnet-push relay-token                      # for each relay that follows
weirdnet-push check -c /etc/weirdnet-push/config.toml
weirdnet-push serve -c /etc/weirdnet-push/config.toml
```

See [`server::Config`] for the config file. Put TLS in front (a reverse proxy). Phase 1
abuse control is handle revocation and rotation; there are no rate limits yet.
UnifiedPush is phase 2.

BSD-3-Clause.
