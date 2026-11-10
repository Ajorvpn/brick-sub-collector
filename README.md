# BrickVPN Subscription Collector & Tester

## Project Overview
BrickVPN automatically collects, tests, and maintains V2Ray/Xray subscription links.

## Features
- Multi-source fetching with asyncio + aiohttp
- Deep config parsing (VLESS / VMess / Trojan / SS)
- Batch GeoIP filtering (10 allowed countries)
- Dual-probe stability + real TLS/SNI handshake
- Jitter/latency quality scoring & ranking
- Clean node renaming
- Per-country quota enforcement

## Multi-Stage Pipeline
1. **Harvesting**: Fetch subscription URLs from `sources.txt`
2. **Deduplication**: Parse & dedup by `IP:Port`
3. **GeoIP Filtering**: Keep only allowed countries (exclude IR, CN, RU)
4. **Dual-Probe Stability**: 2 probes with 0% packet-loss tolerance
5. **Real Handshake**: TLS handshake or HTTP probe
6. **Quality Scoring**: `avg_latency + jitter * 1.5`, sorted ascending
7. **Renaming**: `{FLAG} {COUNTRY} {INDEX} | {PROTO} | ⚡ {MS}ms | BrickVPN`

## Direct Subscription Links
- Main VIP Subscription (Base64): `https://raw.githubusercontent.com/Ajorvpn/brick-sub-collector/sub/sub.txt`
- Main Readable Servers (Plain): `https://raw.githubusercontent.com/Ajorvpn/brick-sub-collector/sub/servers.txt`
- Live Health Status JSON: `https://raw.githubusercontent.com/Ajorvpn/brick-sub-collector/sub/status.json`

## Per-Country Subscription Table
| Country | Flag | Link to .txt | Link to Base64 |
|---------|------|-------------|---------------|
| Germany | 🇩🇪 | `countries/DE.txt` | `countries/DE_base64.txt` |
| Finland | 🇫🇮 | `countries/FI.txt` | `countries/FI_base64.txt` |
| Netherlands | 🇳🇱 | `countries/NL.txt` | `countries/NL_base64.txt` |
| United Kingdom | 🇬🇧 | `countries/GB.txt` | `countries/GB_base64.txt` |
| France | 🇫🇷 | `countries/FR.txt` | `countries/FR_base64.txt` |
| United States | 🇺🇸 | `countries/US.txt` | `countries/US_base64.txt` |
| Switzerland | 🇨🇭 | `countries/CH.txt` | `countries/CH_base64.txt` |
| Sweden | 🇸🇪 | `countries/SE.txt` | `countries/SE_base64.txt` |
| Austria | 🇦🇹 | `countries/AT.txt` | `countries/AT_base64.txt` |
| Canada | 🇨🇦 | `countries/CA.txt` | `countries/CA_base64.txt` |

## Per-Protocol Subscription Table
| Protocol | Link to .txt | Link to Base64 |
|----------|-------------|---------------|
| VLESS | `protocols/vless.txt` | `protocols/vless_base64.txt` |
| VMess | `protocols/vmess.txt` | `protocols/vmess_base64.txt` |
| Trojan | `protocols/trojan.txt` | `protocols/trojan_base64.txt` |
| SS | `protocols/ss.txt` | `protocols/ss_base64.txt` |

---

## فارسی

# BrickVPN Subscriber Collectors & Tester
این پروژه به صورت خودکار لینک‌های اشتراک V2Ray/Xray را گردآوری، تست می‌کند و نگهداری می‌کند.

## ویژگی‌ها
- دریافت همزمان با asyncio + aiohttp
- پارسی کردن عمیق config (VLESS / VMess / Trojan / SS)
- فیلترش geometriché (10 کشور مجاز)
- prouver chklik Stewartability + genuine TLS/SNI handshake
- امتیازدهی کیفیت جاچر و latency
- تغییر نام_nodes پاک
- کنترلeiro برای کشور

## pipelineMulti-Stage
1. **Harvesting**: urlها را از `sources.txt`fetch کنید
2. **Deduplication**: parse & dedup by `IP:Port`
3. **GeoIP Filtering**: only allowed countries keep (IR, CN, RU exclude)
4. **Dual-Probe Stability**: 2 probes with 0% packet-loss tolerance
5. **Real Handshake**: TLS handshake or HTTP probe
6. **Quality Scoring**: `avg_latency + jitter * 1.5`, sorted ascending
7. **Renaming**: `{FLAG} {COUNTRY} {INDEX} | {PROTO} | ⚡ {MS}ms | BrickVPN`