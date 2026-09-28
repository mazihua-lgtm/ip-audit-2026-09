#!/usr/bin/env python3
"""云厂商 IP 公开体检采样器 — 数据全部来自公开可复现源，禁编造。

样本框（声明区域已知）：
  AWS  EC2  ip-ranges.amazonaws.com/ip-ranges.json   （ap-northeast-1 / ap-southeast-1 / us-east-1）
  GCP       gstatic.com/ipranges/cloud.json          （asia-east1 / asia-southeast1 / us-central1）
  CF        cloudflare.com/ips-v4                    （无"区域"概念，作为对照）
指标（每项都能从普通出网 IP 重复验证）：
  PTR      DoH 查 <rev>.in-addr.arpa
  DNSBL    先自检各黑名单是否应答，只保留会应答的
  RDAP     RIR 注册数据：netname / 注册国 / 是否公开 abuse 联系
  BGP      RIPEstat：被公告的 ASN + holder
用法：python3 ip_audit.py --per-group 50 --out /root/ip_audit_results.json
"""
import argparse, ipaddress, json, random, re, sys, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

UA = {"User-Agent": "pureip-audit/1.0 (+https://pureip.app)"}
DOH = "https://dns.google/resolve"
RICESTAT = "https://stat.ripe.net/data"
DEFAULT_BL = ["all.s5h.net", "dnsbl-1.uceprotect.net", "bl.spamcop.net",
              "spam.spamrbl.com", "dnsbl.dronebl.org", "dnsbl.spfbl.net",
              "ix.dnsbl.manitu.net", "hostkarma.junkemailfilter.com",
              "ubl.unsubscore.com", "psbl.surriel.com", "bl.blocklist.de"]
# 声明区域 → 预期国家（仅作对照，不做"正确性"判定）
REGION_CC = {"ap-northeast-1": "JP", "ap-southeast-1": "SG", "us-east-1": "US",
             "asia-east1": "TW", "asia-southeast1": "SG", "us-central1": "US"}


def get(url, timeout=25):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def doh(name, rtype="A"):
    try:
        d = json.loads(get(f"{DOH}?name={urllib.parse.quote(name)}&type={rtype}", timeout=12))
        if d.get("Status") != 0:
            return []
        return [a.get("data") for a in d.get("Answer", []) if a.get("type") == (12 if rtype == "PTR" else 1)]
    except Exception:
        return []


def probe_dnsbl(lists):
    """用必然命中的测试地址 127.0.0.2 自检，只留下真会应答的黑名单。"""
    ok = []
    for bl in lists:
        if doh(f"2.0.0.127.{bl}", "A"):
            ok.append(bl)
    return ok


# ---------- 样本框 ----------
def sample_aws(per_group, rng):
    d = json.loads(get("https://ip-ranges.amazonaws.com/ip-ranges.json"))
    out = {}
    for p in d.get("prefixes", []):
        reg = p.get("region")
        if p.get("service") != "EC2" or reg not in ("ap-northeast-1", "ap-southeast-1", "us-east-1"):
            continue
        out.setdefault(reg, []).append(p["ip_prefix"])
    return _sample_groups(out, per_group, rng, "aws")


def sample_gcp(per_group, rng):
    d = json.loads(get("https://www.gstatic.com/ipranges/cloud.json"))
    out = {}
    for p in d.get("prefixes", []):
        sc = p.get("scope")
        if "ipv4Prefix" in p and sc in ("asia-east1", "asia-southeast1", "us-central1"):
            out.setdefault(sc, []).append(p["ipv4Prefix"])
    return _sample_groups(out, per_group, rng, "gcp")


def sample_cf(per_group, rng):
    txt = get("https://www.cloudflare.com/ips-v4")
    return _sample_groups({"cloudflare": [l.strip() for l in txt.splitlines() if l.strip()]},
                          per_group, rng, "cf")


def _sample_groups(groups, per_group, rng, provider):
    res = []
    for region, cidrs in groups.items():
        pool = []
        nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        nets = [n for n in nets if n.num_addresses >= 4]
        # 每个 CIDR 里取 1 个随机地址，直到够数
        rng.shuffle(nets)
        for n in nets:
            if len(pool) >= per_group * 3:
                break
            pool.append(str(n.network_address + rng.randrange(1, min(n.num_addresses, 1024))))
        rng.shuffle(pool)
        for ip in pool[:per_group]:
            res.append({"ip": ip, "provider": provider, "region": region})
    return res


# ---------- 指标 ----------
def audit_one(item, dnsbls):
    ip = item["ip"]
    rev = ".".join(reversed(ip.split(".")))
    rec = dict(item)
    ptr = doh(f"{rev}.in-addr.arpa", "PTR")
    rec["ptr"] = ptr[0].rstrip(".") if ptr else None
    rec["ptr_kind"] = ("none" if not ptr else
                       "generic" if re.search(r"dynamic|dsl|dhcp|pool|broadband|cust", ptr[0], re.I) else "named")
    hits = {}
    for bl in dnsbls:
        a = doh(f"{rev}.{bl}", "A")
        if a:
            hits[bl] = a[0]
    rec["dnsbl"] = hits
    rec["dnsbl_count"] = len(hits)
    # RDAP：走 rdap.org 引导到对应 RIR
    try:
        j = json.loads(get(f"https://rdap.org/ip/{ip}", timeout=20))
        rec["rdap_netname"] = j.get("name")
        rec["rdap_country"] = j.get("country")
        rec["rdap_handle"] = j.get("handle")
        ents = j.get("entities", [])
        rec["rdap_abuse_roles"] = ("abuse" in json.dumps(ents))
        rec["rdap_handle_ok"] = bool(j.get("handle"))
        for e in ents:
            if "registrant" in (e.get("roles") or []):
                for vc in (e.get("vcardArray") or [None, []])[1]:
                    if vc and vc[0] == "fn":
                        rec["rdap_registrant_org"] = vc[3]
                        break
                break
    except Exception as e:
        rec["rdap_err"] = f"{type(e).__name__}"
    # RIPEstat：ASN + holder
    try:
        j = json.loads(get(f"{RICESTAT}/prefix-overview/data.json?resource={ip}", timeout=20))["data"]
        asns = j.get("asns") or []
        rec["asn"] = asns[0]["asn"] if asns else None
        rec["as_holder"] = (asns[0].get("holder") if asns else None)
        rec["announced"] = j.get("announced")
    except Exception as e:
        rec["bgp_err"] = f"{type(e).__name__}"
    try:
        j = json.loads(get(f"{RICESTAT}/rir/data.json?resource={ip}", timeout=20))["data"]
        rirs = j.get("rirs") or []
        rec["rir"] = rirs[0]["rir"] if rirs else None
    except Exception as e:
        rec["rir_err"] = f"{type(e).__name__}"
    rec["expect_cc"] = REGION_CC.get(item["region"])
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-group", type=int, default=50)
    ap.add_argument("--out", default="/root/ip_audit_results.json")
    ap.add_argument("--seed", type=int, default=20260928)
    a = ap.parse_args()
    rng = random.Random(a.seed)

    print("① 自检黑名单可用性 …", flush=True)
    live = probe_dnsbl(DEFAULT_BL)
    print("   应答的黑名单:", live, flush=True)
    if not live:
        print("   ⚠ 没有可用黑名单，DNSBL 指标将为空", flush=True)

    print("② 拉样本框 …", flush=True)
    items = sample_aws(a.per_group, rng) + sample_gcp(a.per_group, rng) + sample_cf(a.per_group, rng)
    print(f"   共 {len(items)} 个 IP；分布:",
          {f"{p['provider']}/{p['region']}": sum(1 for x in items if x['provider'] == p['provider'] and x['region'] == p['region'])
           for p in items}, flush=True)

    print("③ 逐 IP 体检（PTR / DNSBL / RDAP / BGP）…", flush=True)
    res, t0 = [], time.time()
    with ThreadPoolExecutor(max_workers=6) as ex:
        for i, rec in enumerate(ex.map(lambda it: audit_one(it, live), items), 1):
            res.append(rec)
            if i % 25 == 0:
                print(f"   {i}/{len(items)}  {time.time()-t0:.0f}s", flush=True)

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "seed": a.seed, "dnsbls_probed": DEFAULT_BL, "dnsbls_live": live,
           "sources": {"aws": "ip-ranges.amazonaws.com", "gcp": "gstatic.com/ipranges/cloud.json",
                       "cf": "cloudflare.com/ips-v4", "ptr_dnsbl": "dns.google DoH",
                       "rdap": "rdap.org", "bgp": "stat.ripe.net"},
           "sample": res}
    json.dump(out, open(a.out, "w"), ensure_ascii=False, indent=1)
    print(f"④ 已写 {a.out}（{len(res)} 条，{time.time()-t0:.0f}s）", flush=True)


if __name__ == "__main__":
    main()
