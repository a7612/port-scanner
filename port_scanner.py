#!/usr/bin/env python3
"""
async_port_scanner.py — compact & fast async port scanner
Tính năng:
 - target: IP | domain | CIDR
 - throttling (--rate) + jitter (-j)
 - concurrency (streaming producer/consumer)
 - optional host discovery (--discover)
 - lightweight banner probes, TLS-aware
 - outputs: --json và/hoặc --csv
 - service detection: banner heuristics + port fallbacks (DNS, SMB)
⚠️ Chỉ quét host mà bạn có quyền.
"""
import argparse, asyncio, socket, ssl, random, json, ipaddress, csv, sys, struct
from time import time
from typing import List, Optional

# ---------------------------
# helpers
# ---------------------------
def parse_ports(s: str) -> List[int]:
    """
    Parse string port input -> list[int].
    Hỗ trợ:
     - "A,B" => range A-B
     - "1-1000,80,443"
    """
    s = s.strip()
    # convenience: "A,B" (chỉ 1 dấu phẩy, không có "-") => coi như range A-B
    if ',' in s and '-' not in s and s.count(',') == 1:
        a,b = s.split(',',1)
        if a.isdigit() and b.isdigit():
            a,b = int(a), int(b)
            if 1<=a<=65535 and 1<=b<=65535 and a<b:
                return list(range(a,b+1))
    out=set()
    for part in s.split(','):
        part = part.strip()
        if not part: continue
        if '-' in part:
            a,b = map(int, part.split('-',1)); out.update(range(a,b+1))
        else:
            out.add(int(part))
    return sorted(x for x in out if 1<=x<=65535)

async def resolve_target(target: str, max_hosts: int=4096) -> List[str]:
    """
    Resolve target:
     - Nếu target là IP -> return [IP]
     - Nếu CIDR -> expand host list (giới hạn max_hosts)
     - Nếu domain -> DNS lookup ra nhiều IP
    """
    try: return [str(ipaddress.ip_address(target))]
    except: pass
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = list(net.hosts())
        if len(hosts) > max_hosts:
            print(f"[!] CIDR {target} có {len(hosts)} hosts — chỉ lấy {max_hosts}")
            hosts = hosts[:max_hosts]
        return [str(h) for h in hosts]
    except: pass
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
        return list({info[4][0] for info in infos})
    except: return []

# ---------------------------
# probes & connection
# ---------------------------
# Probe ngắn gọn để kích hoạt banner (ít intrusive nhất có thể)
KNOWN_PROBES = {
    21:   b"\r\n",                          # FTP
    22:   b"\r\n",                          # SSH
    23:   b"\r\n",                          # Telnet
    25:   b"\r\n",                          # SMTP
    80:   b"HEAD / HTTP/1.0\r\n\r\n",       # HTTP
    110:  b"\r\n",                          # POP3
    143:  b"\r\n",                          # IMAP
    443:  b"HEAD / HTTP/1.0\r\n\r\n",       # HTTPS
    3306: b"\r\n",                          # MySQL
    3389: b"\r\n",                          # RDP
    6379: b"PING\r\n",                      # Redis
    27017:b"\r\n",                          # MongoDB
    5900: b"\r\n",                          # VNC
}

async def probe_service(reader, writer, port, timeout=0.45) -> str:
    """
    Gửi probe tùy theo port để lấy banner/service:
     - Port 53: DNS over TCP query
     - Port trong KNOWN_PROBES -> gửi payload mẫu
     - Nếu response text -> trả về text
     - Nếu binary -> trả về hex tóm tắt
    """
    try:
        if port == 53:  # DNS probe đặc biệt
            try:
                qname = b''.join((len(label).to_bytes(1,'big') + label.encode() for label in "example.com".split('.'))) + b'\x00'
                header = b'\x12\x34' + b'\x01\x00' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00'
                question = qname + b'\x00\x01' + b'\x00\x01'
                payload = header + question
                tcp_payload = struct.pack("!H", len(payload)) + payload
                writer.write(tcp_payload)
                await writer.drain()
                length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
                resp_len = struct.unpack("!H", length_bytes)[0]
                resp = await asyncio.wait_for(reader.readexactly(min(resp_len, 1024)), timeout=timeout)
                if len(resp) >= 2:
                    txid = resp[0]*256 + resp[1]
                    return f"DNS_RESPONSE len={resp_len} id=0x{txid:04x}"
                return f"DNS_RESPONSE len={resp_len}"
            except Exception:
                pass

        if port in KNOWN_PROBES:
            writer.write(KNOWN_PROBES[port]); await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout)
        if not data: return ""
        try:
            txt = data.decode(errors="ignore").strip()
            if txt: return txt
        except: pass
        return data[:64].hex()
    except Exception:
        return ""

# ---------------------------
# Service detection heuristics
# ---------------------------
def detect_service(port:int, banner:Optional[str]) -> Optional[str]:
    """
    Xác định service:
     - Ưu tiên banner (chuỗi text chứa keyword)
     - Nếu không có banner -> fallback theo port number
    """
    b = (banner or "").lower()
    sigs = {
        "ssh": "ssh", "ftp": "ftp", "smtp": "smtp", "http": "http",
        "pop3": "pop3", "imap": "imap", "mysql": "mysql", "microsoft": "mssql",
        "rdp": "rdp", "redis": "redis", "mongodb": "mongodb",
        "rfb": "vnc", "dns_response": "dns"
    }
    for key, name in sigs.items():
        if key in b: return name

    port_map = {
        22:"ssh",21:"ftp",23:"telnet",25:"smtp",
        80:"http",8080:"http",443:"http",
        110:"pop3",143:"imap",
        3306:"mysql",1433:"mssql",3389:"rdp",
        6379:"redis",27017:"mongodb",
        5900:"vnc",5901:"vnc",
        53:"dns",139:"smb",445:"smb",135: "msrpc",
    }
    return port_map.get(port)

# ---------------------------
# Connect + detect
# ---------------------------
async def scan_connect(ip: str, port: int, timeout: float, use_ssl: bool) -> Optional[dict]:
    """
    Thử connect TCP (có/không TLS).
    Nếu connect thành công:
     - Probe service -> lấy banner
     - Detect service
     - Trả dict kết quả
    """
    ssl_ctx = None
    if use_ssl:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ssl_ctx), timeout)
    except Exception:
        return None

    banner = await probe_service(reader, writer, port)
    try:
        writer.close(); await writer.wait_closed()
    except: pass

    service = detect_service(port, banner)
    return {"ip": ip, "port": port, "banner": banner, "service": service}

# ---------------------------
# Host discovery (tùy chọn)
# ---------------------------
async def _tcp_ping(ip, port, timeout=0.25):
    """ Thử connect nhanh 1 port phổ biến -> host alive """
    try:
        r,w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        try: w.close(); await w.wait_closed()
        except: pass
        return True
    except: return False

async def host_discovery(ips: List[str], timeout=0.25, concurrency=200):
    """ Quét nhanh host bằng common ports -> lọc host alive """
    common=[80,443,22,53,135,139,445]
    sem=asyncio.Semaphore(concurrency); alive=set()
    async def p(ip):
        async with sem:
            for port in common:
                if await _tcp_ping(ip, port, timeout):
                    alive.add(ip); return
    await asyncio.gather(*(p(ip) for ip in ips))
    return sorted(alive)

# ---------------------------
# Scanner core
# ---------------------------
async def run_scan(target, ports, concurrency, rate, jitter, timeout, json_out, csv_out, no_tls, max_hosts, discover):
    """
    Core scan:
     - resolve target -> list IP
     - optional host discovery
     - dùng producer/consumer streaming để quét
     - ETA, progress, kết quả open
     - lưu JSON/CSV nếu có
    """
    ips = await resolve_target(target, max_hosts=max_hosts)
    if not ips:
        print(f"[!] Không resolve được {target}"); return
    print(f"[i] Resolve được {len(ips)} IP từ '{target}'")

    if discover:
        alive = await host_discovery(ips, timeout=min(0.25, timeout/2), concurrency=min(500, concurrency*2))
        print(f"[i] Discovery: {len(alive)}/{len(ips)} host alive")
        ips = alive or ips

    q = asyncio.Queue(maxsize=concurrency*2)
    total = len(ips)*len(ports)
    results = []
    start = time()
    done = 0
    done_lock = asyncio.Lock()

    # producer
    async def producer():
        for ip in ips:
            for p in ports:
                await q.put((ip,p))
        for _ in range(concurrency):
            await q.put((None,None))

    # consumer
    async def worker(worker_id:int):
        nonlocal done
        while True:
            ip,port = await q.get()
            if ip is None: q.task_done(); break
            await asyncio.sleep((1.0/max(rate,1e-6)) + random.uniform(0, jitter))
            res = await scan_connect(ip, port, timeout, (port==443 and not no_tls))
            async with done_lock:
                done += 1; cur_done = done
            if res:
                print(f"[+] {res['ip']}:{res['port']} OPEN ({res['service'] or 'unknown'})", flush=True)
                results.append(res)
            if cur_done % 100 == 0 or cur_done==total:
                elapsed = time()-start
                rate_now = cur_done/elapsed if elapsed>0 else 0
                eta = (total-cur_done)/rate_now if rate_now>0 else float('inf')
                pct = (cur_done/total)*100 if total else 0
                eta_s = f"{int(eta)}s" if eta!=float('inf') else "?"
                print(f"\r[=] {cur_done}/{total} ({pct:.1f}%) | Open:{len(results)} | elapsed:{int(elapsed)}s ETA:{eta_s}", end="", flush=True)
            q.task_done()

    producers = asyncio.create_task(producer())
    workers = [asyncio.create_task(worker(i)) for i in range(min(concurrency,1000))]
    await producers
    await q.join()

    # 🔥 Thay vì cancel -> cho worker tự nhận sentinel để thoát
    for _ in workers:
        await q.put((None, None))
    await asyncio.gather(*workers, return_exceptions=True)

    print()

    elapsed = time()-start
    print(f"[✓] Done. {len(ips)} IP × {len(ports)} port = {total}. Open: {len(results)}. Time: {elapsed:.1f}s")

    summary = {"target": target, "resolved_ips": ips, "ports_scanned_count": total, "elapsed_s": elapsed, "open_ports": results}
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f: json.dump(summary, f, indent=2, ensure_ascii=False)
        print(f"[i] JSON -> {json_out}")
    if csv_out:
        if not csv_out.lower().endswith(".csv"): csv_out += ".csv"
        with open(csv_out, "w", newline='', encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["target","resolved_ip","port","service","banner"])
            for r in results:
                banner = " ".join(str(r.get("banner","")).splitlines())
                w.writerow([target, r.get("ip",""), r.get("port",""), r.get("service","") or "", banner])
        print(f"[i] CSV -> {csv_out}")

# ---------------------------
# CLI
# ---------------------------
def build_parser():
    """
    Build argparse CLI:
     - target
     - options: ports, concurrency, rate, jitter, timeout, json, csv, no-tls, max-hosts, discover
    """
    p = argparse.ArgumentParser(prog="async-port-scanner",
        description="Async port scanner — IP/domain/CIDR. Use only on hosts you own/are permitted.")
    p.add_argument("target", help="IP | domain | CIDR (e.g. 192.168.2.0/24)")
    p.add_argument("-p","--ports", default="1-1024", help="ports (e.g. 22,80,443 or 1-65535). 'A,B' => A-B")
    p.add_argument("--concurrency", type=int, default=400, help="số worker")
    p.add_argument("--rate", type=float, default=500.0, help="connection starts/sec (throttle)")
    p.add_argument("-j","--jitter", type=float, default=0.01, help="jitter sec")
    p.add_argument("--timeout", type=float, default=0.7, help="connect/banner timeout (s)")
    p.add_argument("--json", help="write JSON summary")
    p.add_argument("--csv", help="write CSV")
    p.add_argument("--no-tls", action="store_true", help="disable TLS cho port 443")
    p.add_argument("--max-hosts", type=int, default=4096, help="limit số host từ CIDR")
    p.add_argument("--discover", action="store_true", help="host discovery nhanh")
    return p

def main():
    args = build_parser().parse_args()
    ports = parse_ports(args.ports)
    if not ports:
        print("[!] Không có port hợp lệ"); sys.exit(2)
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run_scan(args.target, ports, args.concurrency, args.rate, args.jitter,
                                        args.timeout, args.json, args.csv, args.no_tls, args.max_hosts, args.discover))
    finally:
        loop.close()

if __name__ == "__main__":
    main()
