# Protocols, Config Formats, QR & Client Compatibility

Reference for every protocol the panel speaks, what config format it emits, whether that format is safely QR-encodable, which client apps consume it, and the known gaps we should close.

## 1. Supported protocols

Dispatched in `src/amnezia_panel/app.py` (`get_protocol_manager`) and enumerated for traffic sync in `_scrape_server_traffic`.

| Key | Real name | Manager | Container |
|---|---|---|---|
| `awg` | AmneziaWG (awg-go) | `AWGManager` | `amnezia-awg` |
| `awg2` | AmneziaWG 2.0 | `AWGManager` | `amnezia-awg2` |
| `awg_legacy` | Legacy AWG (wg/wg-quick) | `AWGManager` | `amnezia-awg-legacy` |
| `wireguard` | Classic WireGuard | `WireGuardManager` | `amnezia-wg` |
| `xray` | Xray VLESS-Reality | `XrayManager` | `amnezia-xray` |
| `telemt` | Telegram MTProxy | `TelemtManager` | `telemt` |
| `dns` | AmneziaDNS (Unbound + DoT) | `DNSManager` | `amnezia-dns` — infrastructure only, no clients |

**Not implemented** (even though AmneziaVPN supports them): OpenVPN, Shadowsocks, IKEv2, Cloak, OpenVPN-over-Cloak, Sftp-like tunnels.

## 2. Config formats produced

Built by each manager's `get_client_config(...)`.

### AmneziaWG (`awg` / `awg2` / `awg_legacy`) — `protocols/awg.py:985–1067`

WireGuard-style INI `.conf` with `[Interface]` + `[Peer]` plus AmneziaWG obfuscation keys:

```
Jc, Jmin, Jmax, S1, S2, S3, S4, H1, H2, H3, H4, I1, I2, I3, I4, I5, CPS
```

For `awg_legacy`, the code strips `S3, S4, I1..I5, CPS` (see `awg.py:1050`). DNS is hard-coded to `1.1.1.1, 1.0.0.1`, MTU comes from `AWG_DEFAULTS`, `AllowedIPs = 0.0.0.0/0, ::/0`.

### WireGuard (`wireguard`) — `protocols/wireguard.py:637–675`

Vanilla WireGuard `.conf`, no obfuscation fields.

### Xray VLESS-Reality (`xray`) — `protocols/xray.py:405–410`

A `vless://` URL (not a file):

```
vless://{uuid}@{host}:{port}?type=tcp&security=reality&pbk={pbk}&sni={sni}&fp=chrome&sid={sid}&spx=%2F&flow=xtls-rprx-vision#{name}
```

Params hard-coded: `type=tcp`, `fp=chrome`, `flow=xtls-rprx-vision`, `spx=%2F`. No WS/gRPC/QUIC, no alternative uTLS fingerprints.

### Telegram MTProxy (`telemt`) — `protocols/telemt.py:483–501`

Prefers TMProxy-API-provided link in order `tls` → `secure` → `classic` (the `tls` variant is `ee…`-prefixed FakeTLS padding). Fallback: `tg://proxy?server={host}&port={port}&secret={secret}`.

### Universal Amnezia deeplink (`vpn://…`) — `app.py:185`

```
vpn://<base64(config_text)>
```

Amnezia's universal wrapper — the client app base64-decodes and imports. Works for AWG/WG/Xray. The UI explicitly hides it for telemt (`assets/templates/my_connections.html:123`: "Telemt (MTProxy) doesn't have a 'VPN Link' (vpn://) format in Amnezia").

## 3. What is actually QR-codeable today

JS QR generator: `assets/static/js/qrcode.min.js`, hard-coded `correctLevel: L`. Invoked from three screens — `users.html:831`, `my_connections.html:152`, `user_share.html:198` — and **all three encode `result.config`, not the `vpn://` deeplink**.

| Protocol | QR payload today | Scannable by |
|---|---|---|
| `awg` / `awg2` / `awg_legacy` | Raw `.conf` INI text (~1–2 KB) | AmneziaVPN; WireGuard app will import but ignore `Jc/S1../I1..` |
| `wireguard` | Raw `.conf` | WireGuard native (all platforms), AmneziaVPN |
| `xray` | `vless://...` URL | v2rayN/NG, NekoBox, Hiddify, Streisand, Shadowrocket, V2Box, FoXray |
| `telemt` | `tg://proxy?...` URL | Telegram app built-in scanner |
| `dns` | n/a | — |

**Key gap:** the `vpn://<base64>` Amnezia-native deeplink is shown in a separate tab but **never QR-encoded**. To land inside the AmneziaVPN app via QR, the QR payload should be `vpn://…` (either replacing, or alongside, the raw config).

**Size risk:** a full AWG 2.0 config with every obfuscation key is ~1.2–1.8 KB. With `correctLevel L` it fits, but barely — any screen scaling/blur and phone cameras miss it. Bumping to `M` is the obvious hardening step.

## 4. Client-app compatibility per format

### AmneziaWG `.conf` (`awg` / `awg2` / `awg_legacy`)

- **AmneziaVPN** — Windows / macOS / Linux / iOS / Android — native, reads all J/S/H/I/CPS fields.
- **WireGuard official app** — imports but **silently drops unknown keys**; handshake fails against an AWG server because obfuscation isn't applied. Works only against a classic WG server.
- `awg2`-only keys (`I1..I5`, `CPS`) — rejected by older AmneziaVPN builds (pre-2024).
- `awg_legacy` — compatible with older Amnezia clients, but newer obfuscation fields are stripped; don't use on hard-blocking networks.

### WireGuard `.conf`

- WireGuard native on all platforms, `wg-quick`, TunnelKit, AmneziaVPN, TunSafe, WireSock.

### Xray VLESS-Reality URL

- **Mac**: V2Box, Streisand, FoXray, Hiddify.
- **Windows**: v2rayN, NekoRay, Hiddify, Clash.Meta.
- **iOS**: Shadowrocket (paid), Streisand, V2Box, FoXray.
- **Android**: v2rayNG, NekoBox / Box4Magisk, Hiddify.
- **AmneziaVPN**: only via the `vpn://` wrapper — and that wrapper isn't in the QR today.

### Telegram MTProxy (`tg://proxy`)

- Telegram app itself on every platform — scan QR → "Use this proxy". **Proxies Telegram traffic only**, not a system-wide VPN.

## 5. Known gaps / future work

1. **QR encodes raw config, not `vpn://`.** Switch AWG/WG/Xray QR target to the `vpn://` deeplink so Amnezia-native "Scan QR" flow works; or offer a toggle.
2. **Xray `vpn://` wraps a `vless://` URL redundantly** — 3rd-party Xray clients can't parse the wrapper. Keep raw `vless://` as the default share target for Xray.
3. **QR error correction hard-coded to `L`.** Default to `M`; fall back to `L` only when payload forces it. Long AWG configs are borderline unscannable.
4. **WireGuard-app users silently get AWG configs** with obfuscation keys and fail. Add a per-user/per-connection "flavor" export that strips AWG fields when the target is WG-native.
5. **Xray URL params frozen**: `type=tcp`, `fp=chrome`, `flow=xtls-rprx-vision`, `spx=%2F`. No WS/gRPC transports, no alternative TLS fingerprints, no uTLS profile switching.
6. **DNS / MTU / AllowedIPs hard-coded** in exported configs — no split-tunnel, no IPv6 interface address, no per-user DNS.
7. **Xray SNI** defaults to `yahoo.com`. No fallback if ISP SNI-filters it. Add multi-SNI rotation.
8. **Share link (`/share/<token>`)** exposes QR + raw config + `vpn://` with only a per-user password, optionally over HTTP. Treat the token as bearer-equivalent; consider rotating and signing it.
9. **No OpenVPN / Shadowsocks / Cloak / IKEv2.** The panel covers only part of AmneziaVPN's stack. If the target audience overlaps with AmneziaVPN desktop users, these are the next-most-requested.
10. **Telemt QR is `links.tls[0]`.** The `ee…`-prefixed FakeTLS secret is long — worth testing on iOS Telegram, whose camera scanner is more finicky than Android.

### Lowest-effort wins

- **#1** — switch QR payload for Amnezia protocols to `vpn://…`.
- **#3** — raise QR error-correction default to `M`.
- **#4** — add a WG-native export flavor.
