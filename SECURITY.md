# Security

Report problems privately to m3talsmith@gmail.com.

## Goals

- A wake reveals nothing but timing: the payload is fixed-size ciphertext sealed to the
  device; push providers, the push service and relays can't read the reason, and nothing
  in it names the sender, peers, addresses or sites.
- A payload opens only with the device's push key and only for its handle; a fresh
  ephemeral key per payload means no key or nonce reuse. The device's [`ReplayGuard`]
  refuses repeats and wakes older or newer than its window.
- Only the device can rotate or revoke its handle (its control secret, compared in
  constant time against a stored hash). A rotated handle stops working at once.
- A leaked server store gives no handles or control secrets (only their SHA-256), though it
  does hold device tokens, which the providers need.
- Relays follow announcements only with a token whose SHA-256 is in the config.

## Limits

- Anyone holding a handle can wake the device; phase 1 has no rate limits. Rotate the
  handle (and tell trusted peers) if it is abused.
- The service learns when each device is woken and how often.
- Relay announcements go to every following relay; each sees the handle and timing.
