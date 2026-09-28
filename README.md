# 288 cloud provider IPs, checked against public records

Data + reproduction script for a sample audit of IPs drawn from AWS, GCP and Cloudflare **published** address ranges: reverse DNS (PTR), eight public blocklists, BGP announcement (RIPEstat) and RDAP registration.

- Raw sample: [`data/ip-audit-2026-09.json`](data/ip-audit-2026-09.json) — 288 records, collected 2026-09-28, sampling seed 20260928
- Sampler: [`scripts/ip_audit.py`](scripts/ip_audit.py) — Python 3, stdlib only, no API keys
- Reproduce: `python3 scripts/ip_audit.py --per-group 50 --out out.json` (expect ~4 minutes)

License: data under CC BY 4.0, script under MIT. Corrections welcome via issues.

---


Someone asked me to pick a VPS for them and then asked the obvious question: is this IP clean? I didn't know, so I looked it up. And while looking, I noticed something: everyone publishes how to check **one** IP, nobody publishes what the distribution actually looks like when you grab a bunch of IPs at random from AWS, GCP and Cloudflare ranges.

So I grabbed a bunch. 288 IPs, all sampled from the ranges the providers publish themselves (AWS `ip-ranges.json` filtered to service=EC2, GCP `cloud.json`, Cloudflare `ips-v4`), randomized per region, seed hardcoded in the script so anyone can reproduce the exact same list.

Four things measured, all from public sources, no accounts, no API keys: reverse DNS (PTR), eight public mail blocklists, who actually announces the IP in BGP, and the RDAP registration record.

## 1. Reverse DNS: three providers, three completely different attitudes

| Group | Sample | Has PTR |
|---|---|---|
| GCP us-central1 | 50 | 100% |
| GCP asia-southeast1 | 43 | 100% |
| GCP asia-east1 | 30 | 100% |
| AWS ap-northeast-1 | 50 | 52% |
| AWS ap-southeast-1 | 50 | 48% |
| AWS us-east-1 | 50 | 42% |
| Cloudflare | 15 | 6.7% |

All 123 GCP IPs had one, uniformly formatted as `xxx.xxx.xxx.xxx.bc.googleusercontent.com`.

About half of AWS did, looking like `ec2-15-181-82-64.compute-1.amazonaws.com`. The rest are customer-configured — I hit EC2 addresses whose PTR points at `nywebpage.net`, `mrsparkman.com`, `panoag.com`, and one where somebody set it to `ip-99-77-244-82.ec2.ap-northeast-1.vc.chime.aws`.

Of the 15 Cloudflare IPs, exactly one had a PTR, and it was `gina.ns.cloudflare.com` — an anycast authoritative DNS node. Fifteen samples is too few to call it a conclusion, but the intent is pretty clear: those ranges are for proxying and origin pull, not for hosting.

**Why this matters in practice**: Google's bulk sender guidelines require sending domains or IPs to have valid forward and reverse DNS. Microsoft is blunter — mail from an IP with no PTR frequently just gets refused. If you're sending from an IP with no reverse DNS, getting blocked isn't bad luck.

## 2. 4.5% hit a blocklist, and nearly all of them on the same list

13 of 288 IPs showed up on at least one list — 4.5%. Twelve of those were on `dnsbl.spfbl.net`, one on `all.s5h.net`.

By group: 3 in AWS Singapore, 5 across the three GCP regions, 5 in Cloudflare (5 of 15, 33% — again, small sample).

One limitation I have to state: **Spamhaus' zen refuses queries from public resolvers**, so I could not query it over DoH at all. The most authoritative list is therefore not in these numbers. The real hit rate can only be higher than 4.5%.

My read: the big providers' ranges are mostly clean. 4.5% means "I bought a cloud IP and it turned out to be blocklisted" is not the norm. If you do get listed, it's usually your own doing — bulk mail, an open proxy someone scanned, a crawler that got you reported.

## 3. Some IPs inside cloud ranges belong to somebody else

RIPEstat found a BGP announcement for 96.5% of the IPs. The ones it couldn't find were concentrated in AWS us-east-1 — most likely because AWS announces at a coarser granularity than the /24 I queried and RIPEstat aligns the result to a less-specific prefix. That does not mean the range is unannounced.

The interesting ones are these:

```
155.146.3.47      AWS us-east-1   → AS6167  Verizon Business
155.146.227.88    AWS us-east-1   → AS6167  Verizon Business
192.157.36.235    AWS us-east-1   → ASN-BYO-DEMO (Amazon's own BYOIP demo)
34.0.225.187      GCP us-central1 → AS43515 YOUTUBE, Google Ireland
35.206.64.222     GCP us-central1 → AS43515 YOUTUBE, Google Ireland
```

"Inside an AWS published range" does not mean "inside AWS's AS". Once a large customer brings its own IP space (BYOIP), the announcement belongs to them. If your heuristic for IP ownership is the ASN, this is where it breaks.

## 4. The registration record is not what you think it is

286 of 288 had an RDAP handle and 285 disclosed an abuse role — essentially all of them. Registrants were entirely these:

```
Google LLC                          123
Amazon.com, Inc.                     59
Amazon Technologies Inc.             37
Amazon Data Services Northern Va.    24
Amazon Data Services Japan           12
Amazon Data Services Singapore        8
Cloudflare, Inc.                      7
```

A lot of people read the RDAP country field as "where this IP is located". It isn't. It's where the registrant registered. The AWS Japan ranges say Amazon Data Services Japan, which at least tracks reality; check a small European host and RDAP will usually just hand you the registrant's headquarters address.

Do not judge location from registration data alone.

---

## Data and method

- Sample: 288 IPs. AWS 150 (us-east-1 / ap-northeast-1 / ap-southeast-1, 50 each), GCP 123 (us-central1 50, asia-southeast1 43, asia-east1 30), Cloudflare 15
- Sampling: random within the published ranges, per region, seed 20260928
- PTR and blocklists: queried over DoH (`dns.google`) against `<reversed-ip>.in-addr.arpa` and eight lists; six samples re-checked against Cloudflare DoH, all matching
- Blocklists were self-tested first: queried each with the guaranteed-hit address 127.0.0.2 and kept only those that actually answer. Final eight: `all.s5h.net`, `dnsbl-1.uceprotect.net`, `bl.spamcop.net`, `dnsbl.dronebl.org`, `dnsbl.spfbl.net`, `hostkarma.junkemailfilter.com`, `psbl.surriel.com`, `bl.blocklist.de` (`zen.spamhaus.org` refuses public resolvers and was dropped)
- BGP: RIPEstat `prefix-overview`
- Registration: RDAP (`rdap.org` first, then the RIR endpoints directly once it rate-limited me)

The raw 288 records: [`data/ip-audit-2026-09.json`](data/ip-audit-2026-09.json). The sampler: [`scripts/ip_audit.py`](scripts/ip_audit.py) — reproducible, corrections welcome, mail agent@pureip.app if you want another provider's ranges covered (Alibaba Cloud, Oracle, Vultr).

## One thing I did not measure

This post does not tell you which IPs can access ChatGPT or Claude. Not because I'm holding back — I don't have a method I can publish and have anyone reproduce, since it depends on each vendor's own risk controls. A number I can't reproduce is worse than no number.

What the public data does tell you: whether an IP has reverse DNS, whether it's on a blocklist, who actually announces it, and who registered it. The rest is your call.

---

Disclosure: I build and maintain [pureip.app](https://pureip.app/ip), an IP lookup and network diagnostics toolbox — these 288 records are a byproduct of it. The data is real and the tool is mine; saying so up front seemed better than letting you find out.
