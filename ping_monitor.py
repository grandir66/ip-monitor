#!/usr/bin/env python3
"""
GAMO VM Ping Monitor v4
────────────────────────
Due modalità:

  1) MONITOR — monitora IP da un CSV (come v3)
     python3 ping_monitor.py [--csv PATH] [--interval SEC] [--workers N]

  2) SCAN — scansiona reti CIDR, salva gli host vivi in un CSV compatibile
     python3 ping_monitor.py --scan 192.168.1.0/24 10.0.0.0/24
     python3 ping_monitor.py --scan-file reti.txt -o risultati.csv
     python3 ping_monitor.py --scan 10.0.0.0/24 --monitor   # scan + avvia monitor

Logica IP: preferisce indirizzi NON in 172.20.13.x / 172.20.15.x.
"""

import csv
import ipaddress
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import time
import argparse
import platform
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

if not (platform.system() == "Windows"):
    import tty
    import termios

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.rule import Rule
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ─── Configurazione ──────────────────────────────────────────────────────────
DEFAULT_CSV      = "hosts_all.csv"
DEFAULT_INTERVAL = 10
DEFAULT_WORKERS  = 30
DEFAULT_TIMEOUT  = 2
PING_COUNT       = 1
MAX_CHANGE_LOG   = 100   # eventi cambio tenuti in memoria
CHANGES_ROWS     = 10    # righe visibili nel pannello modifiche
# Altezza fissa del pannello modifiche (bordi + header + righe + subtitle)
CHANGES_PANEL_H  = CHANGES_ROWS + 5

EXCLUDED_NETS = [
    ipaddress.ip_network("172.20.13.0/24"),
    ipaddress.ip_network("172.20.15.0/24"),
]

IS_MAC = platform.system() == "Darwin"
IS_WIN = platform.system() == "Windows"

IPV4_RE    = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
LINK_LOCAL = re.compile(r'^(169\.254\.|fe80:|240\.)')


# ─── Selezione IP primario ────────────────────────────────────────────────────
def is_excluded(addr: str) -> bool:
    try:
        return any(ipaddress.ip_address(addr) in net for net in EXCLUDED_NETS)
    except ValueError:
        return False


def select_best_ipv4(ip_field: str) -> tuple:
    if not ip_field:
        return None, False
    candidates = []
    for part in ip_field.split(","):
        addr = part.strip().strip('"')
        if IPV4_RE.match(addr) and not LINK_LOCAL.match(addr):
            candidates.append(addr)
    if not candidates:
        return None, False
    preferred = [a for a in candidates if not is_excluded(a)]
    if preferred:
        return preferred[0], False
    return candidates[0], True   # fallback


# ─── Parsing CSV ──────────────────────────────────────────────────────────────
def load_vms(csv_path: str) -> list:
    vms = []
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("State", "").strip() != "Powered On":
                continue
            ip, fallback = select_best_ipv4(row.get("IP Address", ""))
            if not ip:
                continue
            vms.append({
                "name":     row.get("Name", "").strip(),
                "host":     row.get("Host", "").strip(),
                "ip":       ip,
                "fallback": fallback,
            })
    seen, unique = set(), []
    for vm in vms:
        if vm["ip"] not in seen:
            seen.add(vm["ip"])
            unique.append(vm)
    return unique


# ─── Ping ─────────────────────────────────────────────────────────────────────
def ping_host(ip: str, timeout: int, count: int) -> tuple:
    try:
        if IS_WIN:
            cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
        elif IS_MAC:
            cmd = ["ping", "-c", str(count), "-W", str(timeout * 1000),
                   "-t", str(timeout + 1), ip]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]
        t0 = time.monotonic()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        elapsed = (time.monotonic() - t0) * 1000
        if result.returncode == 0:
            m = re.search(r"time[=<]([\d.]+)\s*ms", result.stdout)
            return True, float(m.group(1)) if m else elapsed
        return False, -1.0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, -1.0


# ─── Risoluzione DNS ─────────────────────────────────────────────────────────
def reverse_dns(ip: str, dns_timeout: float = 2.0) -> str:
    """Tenta reverse DNS (PTR) su un IP. Ritorna hostname o stringa vuota."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(dns_timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


def resolve_dns_batch(hosts: list, workers: int):
    """Risolve reverse DNS in parallelo per una lista di host dict con chiave 'ip'."""
    total = len(hosts)
    if total == 0:
        return

    if HAS_RICH:
        from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
        console = Console()
        resolved = 0
        with Progress(
            TextColumn("[bold magenta]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("{task.completed}/{task.total}"),
            TextColumn("[magenta]{task.fields[resolved]} risolti[/]"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Reverse DNS", total=total, resolved=0)
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(reverse_dns, h["ip"]): h
                    for h in hosts
                }
                for future in as_completed(futures):
                    h = futures[future]
                    hostname = future.result()
                    h["hostname"] = hostname
                    if hostname:
                        resolved += 1
                    progress.update(task, advance=1, resolved=resolved)
    else:
        done = 0
        resolved = 0
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(reverse_dns, h["ip"]): h
                for h in hosts
            }
            for future in as_completed(futures):
                h = futures[future]
                hostname = future.result()
                h["hostname"] = hostname
                done += 1
                if hostname:
                    resolved += 1
                if done % 50 == 0 or done == total:
                    print(f"\r  DNS [{done}/{total}] {resolved} risolti",
                          end="", flush=True)
            print()

    print(f"[SCAN] Reverse DNS: {sum(1 for h in hosts if h.get('hostname'))}"
          f"/{total} hostname risolti")


# ─── Scan di rete ────────────────────────────────────────────────────────────
def parse_networks(args_scan, args_scan_file):
    """Raccoglie reti CIDR da argomenti CLI e/o file."""
    nets = []
    if args_scan:
        for cidr in args_scan:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                print(f"[ERRORE] Rete non valida: {cidr}")
                sys.exit(1)
    if args_scan_file:
        p = Path(args_scan_file)
        if not p.exists():
            print(f"[ERRORE] File reti non trovato: {args_scan_file}")
            sys.exit(1)
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # supporta anche CSV con colonne extra (prende primo campo)
            cidr = line.split(",")[0].strip().strip('"')
            if not cidr:
                continue
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                print(f"[AVVISO] Riga ignorata (non CIDR valido): {line}")
    return nets


def scan_networks(nets, workers, timeout, output_path):
    """Scansiona le reti, mostra progresso, salva CSV compatibile."""
    all_ips = []
    for net in nets:
        all_ips.extend(str(ip) for ip in net.hosts())

    total = len(all_ips)
    if total == 0:
        print("[ERRORE] Nessun host da scansionare.")
        sys.exit(1)

    net_labels = ", ".join(str(n) for n in nets)
    print(f"[SCAN] Reti: {net_labels}")
    print(f"[SCAN] Host da scansionare: {total}  |  workers={workers}  timeout={timeout}s")
    print()

    alive = []
    done = 0

    if HAS_RICH:
        from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
        console = Console()
        with Progress(
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("{task.completed}/{task.total}"),
            TextColumn("[green]{task.fields[alive_count]} vivi[/]"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scansione", total=total, alive_count=0)
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(ping_host, ip, timeout, PING_COUNT): ip
                    for ip in all_ips
                }
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        ok, lat = future.result()
                    except Exception:
                        ok, lat = False, -1.0
                    if ok:
                        # trova a quale rete appartiene
                        net_str = ""
                        ip_obj = ipaddress.ip_address(ip)
                        for net in nets:
                            if ip_obj in net:
                                net_str = str(net)
                                break
                        alive.append({
                            "ip": ip, "latency": lat, "network": net_str,
                        })
                    progress.update(task, advance=1, alive_count=len(alive))
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(ping_host, ip, timeout, PING_COUNT): ip
                for ip in all_ips
            }
            for future in as_completed(futures):
                ip = futures[future]
                done += 1
                try:
                    ok, lat = future.result()
                except Exception:
                    ok, lat = False, -1.0
                if ok:
                    ip_obj = ipaddress.ip_address(ip)
                    net_str = ""
                    for net in nets:
                        if ip_obj in net:
                            net_str = str(net)
                            break
                    alive.append({
                        "ip": ip, "latency": lat, "network": net_str,
                    })
                if done % 50 == 0 or done == total:
                    print(f"\r  [{done}/{total}] {len(alive)} host vivi", end="", flush=True)
            print()

    # ordina per IP
    alive.sort(key=lambda h: ipaddress.ip_address(h["ip"]))

    # fase 2: reverse DNS sugli host vivi
    if alive:
        print()
        resolve_dns_batch(alive, workers)

    # salva CSV compatibile con il monitor
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Name", "State", "Host", "Provisioned Space",
                         "IP Address", "Hostname", "Source"])
        for h in alive:
            hostname = h.get("hostname", "")
            name = hostname if hostname else h["ip"]
            writer.writerow([
                name,
                "Powered On",
                h["network"],
                "",
                h["ip"],
                hostname,
                "scan",
            ])

    print(f"\n[SCAN] Completato: {len(alive)}/{total} host vivi")
    print(f"[SCAN] Risultati salvati in: {output_path}")
    return alive


# ─── Evento cambio stato ──────────────────────────────────────────────────────
@dataclass
class ChangeEvent:
    ts:         datetime
    cycle:      int
    vm_name:    str
    ip:         str
    prev_state: object
    new_state:  bool


# ─── Stato host ───────────────────────────────────────────────────────────────
class HostState:
    def __init__(self, name: str, host: str, ip: str, fallback: bool = False):
        self.name      = name
        self.host      = host
        self.ip        = ip
        self.fallback  = fallback
        self.up        = None
        self.latency   = -1.0
        self.last_ok   = None
        self.last_fail = None
        self.streak    = 0
        self.changes   = 0

    def update(self, success: bool, latency: float,
               cycle: int, change_log: deque) -> bool:
        now  = datetime.now()
        prev = self.up
        self.up      = success
        self.latency = latency
        if success:
            self.last_ok = now
            self.streak  = max(1, self.streak + 1) if prev else 1
        else:
            self.last_fail = now
            self.streak    = min(-1, self.streak - 1) if prev is False else -1
        changed = (prev != success)
        if changed:
            self.changes += 1
            change_log.appendleft(ChangeEvent(
                ts=now, cycle=cycle,
                vm_name=self.name, ip=self.ip,
                prev_state=prev, new_state=success,
            ))
        return changed


# ─── Input tastiera (non bloccante) ──────────────────────────────────────────
class KeyReader:
    """Legge tasti freccia in un thread separato, aggiorna scroll_offset."""

    def __init__(self):
        self.scroll_offset = 0
        self.max_offset = 0
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if IS_WIN:
            return  # su Windows non supportato per ora
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def set_max(self, total_rows: int, visible_rows: int):
        self.max_offset = max(0, total_rows - visible_rows)
        if self.scroll_offset > self.max_offset:
            self.scroll_offset = self.max_offset

    def _read_loop(self):
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while not self._stop.is_set():
                if select.select([sys.stdin], [], [], 0.05)[0]:
                    ch = sys.stdin.read(1)
                    if ch == "\x1b":
                        seq = sys.stdin.read(1) if select.select([sys.stdin], [], [], 0.05)[0] else ""
                        if seq == "[":
                            code = sys.stdin.read(1) if select.select([sys.stdin], [], [], 0.05)[0] else ""
                            if code == "A":      # freccia su
                                self.scroll_offset = max(0, self.scroll_offset - 1)
                            elif code == "B":    # freccia giu
                                self.scroll_offset = min(self.max_offset, self.scroll_offset + 1)
                            elif code == "5":    # Page Up
                                sys.stdin.read(1) if select.select([sys.stdin], [], [], 0.05)[0] else ""
                                self.scroll_offset = max(0, self.scroll_offset - 10)
                            elif code == "6":    # Page Down
                                sys.stdin.read(1) if select.select([sys.stdin], [], [], 0.05)[0] else ""
                                self.scroll_offset = min(self.max_offset, self.scroll_offset + 10)
                            elif code == "H":    # Home
                                self.scroll_offset = 0
                            elif code == "F":    # End
                                self.scroll_offset = self.max_offset
                    elif ch == "q":
                        # 'q' per uscire
                        os.kill(os.getpid(), 2)  # SIGINT
                        break
        except Exception:
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


# ─── Componenti UI ────────────────────────────────────────────────────────────

def make_header(states: list, cycle: int, interval: int, next_in: int) -> Panel:
    up   = sum(1 for s in states if s.up is True)
    down = sum(1 for s in states if s.up is False)
    pend = sum(1 for s in states if s.up is None)
    total = len(states)

    bar_len = 40
    up_cells   = round(bar_len * up   / total) if total else 0
    down_cells = round(bar_len * down / total) if total else 0
    pend_cells = bar_len - up_cells - down_cells

    bar = Text()
    bar.append("█" * up_cells,   style="green")
    bar.append("█" * down_cells, style="red")
    bar.append("░" * pend_cells, style="dim")

    t = Text()
    t.append("  GAMO VM Ping Monitor  ", style="bold cyan")
    t.append(f"ciclo #{cycle}  ", style="yellow")
    t.append(f"▲ {up} UP  ",  style="bold green")
    t.append(f"▼ {down} DOWN  ", style="bold red")
    t.append(f"{pend} pend  │  ", style="dim")
    t.append(bar)
    t.append(f"  │  next {next_in}s  │  {datetime.now().strftime('%H:%M:%S')}  ",
             style="dim")
    t.append(f"interval={interval}s", style="dim")

    return Panel(t, box=box.HORIZONTALS, style="on grey7", padding=(0, 0))


def make_vm_table(states: list, term_height: int,
                  scroll_offset: int = 0, key_reader: "KeyReader | None" = None) -> Panel:
    """Tabella VM con scroll via tastiera. DOWN sempre in cima."""
    avail_rows = max(5, term_height - CHANGES_PANEL_H - 3 - 5)

    def sort_key(s):
        if s.up is False: return (0, s.name)
        if s.up is None:  return (1, s.name)
        return (2, s.name)

    sorted_states = sorted(states, key=sort_key)
    total = len(sorted_states)

    # aggiorna limiti scroll nel key_reader
    if key_reader:
        key_reader.set_max(total, avail_rows)
        scroll_offset = key_reader.scroll_offset

    end = min(scroll_offset + avail_rows, total)
    shown = sorted_states[scroll_offset:end]

    tbl = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold white on grey23",
        expand=True,
        padding=(0, 1),
        show_edge=False,
    )
    tbl.add_column("#",       style="dim",    no_wrap=True, min_width=4, justify="right")
    tbl.add_column("VM",      style="cyan",   no_wrap=True, min_width=22)
    tbl.add_column("IP",      style="yellow", no_wrap=True, min_width=16)
    tbl.add_column("Host",    style="dim",    no_wrap=True, min_width=13)
    tbl.add_column("Stato",   justify="center", min_width=9)
    tbl.add_column("Latenza", justify="right",  min_width=9)
    tbl.add_column("Streak",  justify="center", min_width=7)
    tbl.add_column("Ult. OK",                   min_width=10)
    tbl.add_column("Chg",     justify="right",  min_width=4)

    for idx, s in enumerate(shown, start=scroll_offset + 1):
        if s.fallback:
            ip_txt = Text(); ip_txt.append(s.ip, style="yellow"); ip_txt.append(" (fb)", style="dim")
        else:
            ip_txt = Text(s.ip, style="yellow")

        if s.up is True:
            stato = Text("● UP",   style="bold green")
            lat   = Text(f"{s.latency:.1f} ms" if s.latency >= 0 else "—", style="green")
            strk  = Text(f"↑{s.streak}", style="green")
            rst   = ""
        elif s.up is False:
            stato = Text("✖ DOWN", style="bold red")
            lat   = Text("timeout", style="dim red")
            strk  = Text(f"↓{abs(s.streak)}", style="red")
            rst   = "on grey7"
        else:
            stato = Text("…",  style="dim")
            lat   = Text("—",  style="dim")
            strk  = Text("—",  style="dim")
            rst   = ""

        last_ok = s.last_ok.strftime("%H:%M:%S") if s.last_ok else "—"
        chg     = (Text(str(s.changes), style="bold yellow")
                   if s.changes > 0 else Text("—", style="dim"))

        tbl.add_row(str(idx), s.name[:24], ip_txt, s.host[:13],
                    stato, lat, strk, last_ok, chg,
                    style=rst)

    # indicatore scroll
    if total <= avail_rows:
        pos_info = ""
    else:
        pos_info = (f"[dim]  righe {scroll_offset+1}-{end}/{total}"
                    f"  ↑↓ scroll · PgUp/PgDn · Home/End · q esci[/]")

    return Panel(tbl,
                 title=f"[dim]VM ({total} totali){pos_info}[/]",
                 subtitle="[dim]DOWN sempre in cima[/]" if total > avail_rows else "",
                 box=box.ROUNDED,
                 border_style="bright_black",
                 padding=(0, 0))


def make_changes_panel(change_log: deque) -> Panel:
    if not change_log:
        inner = Text(
            "  Nessuna modifica ancora — le variazioni UP ↔ DOWN appariranno qui in tempo reale.",
            style="dim italic",
        )
        return Panel(inner,
                     title="[bold yellow]📋  Modifiche[/]",
                     border_style="yellow dim",
                     padding=(0, 1),
                     height=CHANGES_PANEL_H)

    tbl = Table(box=None, show_header=True,
                header_style="bold white", expand=True,
                padding=(0, 1), show_edge=False)
    tbl.add_column("Orario", style="dim",    min_width=10, no_wrap=True)
    tbl.add_column("Ciclo",  style="dim",    min_width=5,  no_wrap=True, justify="right")
    tbl.add_column("VM",     style="cyan",   min_width=22, no_wrap=True)
    tbl.add_column("IP",     style="yellow", min_width=15, no_wrap=True)
    tbl.add_column("Evento",               min_width=15, no_wrap=True)
    tbl.add_column("Durata DOWN",          min_width=13, no_wrap=True)

    shown_events = list(change_log)[:CHANGES_ROWS]
    for ev in shown_events:
        if ev.prev_state is None:
            evento   = Text("INIT",   style="dim")
            duration = Text("—",      style="dim")
        elif ev.new_state:
            evento = Text("↑ RECOVERED", style="bold green")
            duration = Text("—", style="dim")
            for old in list(change_log):
                if old.ip == ev.ip and old is not ev and not old.new_state:
                    secs = int((ev.ts - old.ts).total_seconds())
                    h, r = divmod(secs, 3600)
                    m, s = divmod(r, 60)
                    dur_str = (f"{h}h{m:02d}m{s:02d}s" if h
                               else f"{m}m{s:02d}s" if m else f"{s}s")
                    duration = Text(dur_str, style="green")
                    break
        else:
            evento   = Text("↓ LOST",     style="bold red")
            duration = Text("in corso…",  style="red dim italic")

        tbl.add_row(
            ev.ts.strftime("%H:%M:%S"),
            f"#{ev.cycle}",
            ev.vm_name[:24],
            ev.ip,
            evento,
            duration,
        )

    total = len(change_log)
    subtitle = f"[dim]ultimi {len(shown_events)} / {total} eventi[/]"
    return Panel(tbl,
                 title="[bold yellow]📋  Modifiche rispetto alla scansione precedente[/]",
                 subtitle=subtitle,
                 border_style="yellow",
                 padding=(0, 0),
                 height=CHANGES_PANEL_H)


def build_layout(states: list, cycle: int, interval: int,
                 next_in: int, change_log: deque,
                 key_reader: "KeyReader | None" = None) -> Layout:
    """Layout fisso: header(3) + vm_table(variabile) + changes(fisso in basso)."""
    term_h = shutil.get_terminal_size((80, 40)).lines

    layout = Layout()
    layout.split_column(
        Layout(name="header",  size=3),
        Layout(name="main",    ratio=1),
        Layout(name="changes", size=CHANGES_PANEL_H),
    )
    layout["header"].update(make_header(states, cycle, interval, next_in))
    layout["main"].update(make_vm_table(states, term_h, key_reader=key_reader))
    layout["changes"].update(make_changes_panel(change_log))
    return layout


# ─── Loop principale ──────────────────────────────────────────────────────────
def run(csv_path: str, interval: int, workers: int, timeout: int):
    vms = load_vms(csv_path)
    if not vms:
        print(f"[ERRORE] Nessuna VM con IP trovata in {csv_path}")
        sys.exit(1)

    states: list = [HostState(v["name"], v["host"], v["ip"], v["fallback"]) for v in vms]
    change_log: deque = deque(maxlen=MAX_CHANGE_LOG)
    cycle = 0
    console = Console() if HAS_RICH else None

    def ping_cycle():
        nonlocal cycle
        cycle += 1
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(ping_host, s.ip, timeout, PING_COUNT): s
                for s in states
            }
            for future in as_completed(futures):
                s = futures[future]
                try:
                    ok, lat = future.result()
                except Exception:
                    ok, lat = False, -1.0
                s.update(ok, lat, cycle, change_log)

    if HAS_RICH:
        keys = KeyReader()
        keys.start()
        ping_cycle()
        try:
            with Live(
                build_layout(states, cycle, interval, interval, change_log, keys),
                console=console,
                screen=True,
                refresh_per_second=4,
            ) as live:
                while True:
                    deadline = time.monotonic() + interval
                    while True:
                        remaining = max(0, int(deadline - time.monotonic()))
                        live.update(
                            build_layout(states, cycle, interval, remaining,
                                         change_log, keys)
                        )
                        if time.monotonic() >= deadline:
                            break
                        time.sleep(0.15)
                    ping_cycle()
        finally:
            keys.stop()

    else:
        # Fallback testo senza rich
        while True:
            ping_cycle()
            os.system("cls" if IS_WIN else "clear")
            now  = datetime.now().strftime("%H:%M:%S")
            up   = sum(1 for s in states if s.up is True)
            down = sum(1 for s in states if s.up is False)
            print(f"{'='*80}\n  GAMO Monitor | Ciclo #{cycle} | {now} | UP={up} DOWN={down}\n{'='*80}")
            fmt = "{:<26} {:<16} {:<7} {:<10}"
            print(fmt.format("VM", "IP", "Stato", "Latenza"))
            print("-"*65)
            for s in sorted(states, key=lambda x: (x.up is not False, x.up is None)):
                stato = "UP" if s.up else ("DOWN" if s.up is False else "…")
                lat   = f"{s.latency:.1f}ms" if s.latency >= 0 and s.up else "—"
                print(fmt.format(s.name[:25], s.ip, stato, lat))
            if change_log:
                print(f"\n--- MODIFICHE ({len(change_log)}) ---")
                for ev in list(change_log)[:12]:
                    arrow = "RECOVERED" if ev.new_state else "LOST"
                    print(f"  {ev.ts.strftime('%H:%M:%S')}  #{ev.cycle:3d}  "
                          f"{ev.vm_name:<24}  {ev.ip:<15}  → {arrow}")
            time.sleep(interval)


# ─── Entry point ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="GAMO IP Monitor v4 — monitor + network scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""esempi:
  %(prog)s --csv hosts.csv                        # monitora da CSV
  %(prog)s --scan 192.168.1.0/24                  # scansiona una rete
  %(prog)s --scan 10.0.0.0/24 172.16.0.0/16       # scansiona più reti
  %(prog)s --scan-file reti.txt -o hosts.csv       # reti da file, salva CSV
  %(prog)s --scan 10.0.0.0/24 --monitor            # scan + avvia monitor
""")

    # --- Modalità monitor ---
    parser.add_argument("--csv",      default=DEFAULT_CSV,
                        help="CSV con gli host da monitorare (default: hosts_all.csv)")
    parser.add_argument("--interval", default=DEFAULT_INTERVAL, type=int,
                        help="Secondi tra cicli di ping (default 10)")
    parser.add_argument("--list",     action="store_true",
                        help="Stampa solo gli IP estratti dal CSV e termina")

    # --- Modalità scan ---
    parser.add_argument("--scan",     nargs="+", metavar="CIDR",
                        help="Reti CIDR da scansionare (es. 192.168.1.0/24)")
    parser.add_argument("--scan-file", metavar="FILE",
                        help="File con lista di reti CIDR (una per riga)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Path CSV di output per lo scan (default: scan_<timestamp>.csv)")
    parser.add_argument("--monitor",  action="store_true",
                        help="Dopo lo scan, avvia il monitor sui risultati")

    # --- Comuni ---
    parser.add_argument("--workers",  default=DEFAULT_WORKERS,  type=int,
                        help="Thread paralleli (default 30)")
    parser.add_argument("--timeout",  default=DEFAULT_TIMEOUT,  type=int,
                        help="Timeout ping in secondi (default 2)")

    args = parser.parse_args()

    # ─── Modalità SCAN ────────────────────────────────────────────────────
    if args.scan or args.scan_file:
        nets = parse_networks(args.scan, args.scan_file)
        if not nets:
            print("[ERRORE] Nessuna rete CIDR specificata.")
            sys.exit(1)

        if args.output:
            output_path = args.output
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"scan_{ts}.csv"

        try:
            alive = scan_networks(nets, args.workers, args.timeout, output_path)
        except KeyboardInterrupt:
            print("\n[INFO] Scan interrotto.")
            sys.exit(0)

        if args.monitor and alive:
            print(f"\n[INFO] Avvio monitor su {output_path}...")
            time.sleep(1)
            try:
                run(output_path, args.interval, args.workers, args.timeout)
            except KeyboardInterrupt:
                print("\n[INFO] Monitor terminato.")
        return

    # ─── Modalità MONITOR (default) ──────────────────────────────────────
    csv_path = args.csv
    if not Path(csv_path).exists():
        alt = Path(__file__).parent / Path(csv_path).name
        csv_path = str(alt) if alt.exists() else csv_path
    if not Path(csv_path).exists():
        print(f"[ERRORE] CSV non trovato: {csv_path}")
        sys.exit(1)

    if args.list:
        vms = load_vms(csv_path)
        fb  = [v for v in vms if v["fallback"]]
        print(f"{'VM':<28} {'IP':<18} {'Note':<12} {'Host'}")
        print("-" * 75)
        for vm in vms:
            note = "(fallback)" if vm["fallback"] else ""
            print(f"{vm['name']:<28} {vm['ip']:<18} {note:<12} {vm['host']}")
        print(f"\nTotale: {len(vms)} VM  "
              f"({len(fb)} con IP fallback da subnet 172.20.13/15)")
        return

    if not HAS_RICH:
        print("[AVVISO] 'rich' non trovato. Installa con: pip install rich\n")

    vms = load_vms(csv_path)
    fb  = sum(1 for v in vms if v["fallback"])
    print(f"[INFO] {len(vms)} VM  ({fb} fallback da subnet esclusa)")
    print(f"[INFO] interval={args.interval}s · workers={args.workers} · timeout={args.timeout}s")
    print("[INFO] CTRL+C per uscire\n")
    time.sleep(1)

    try:
        run(csv_path, args.interval, args.workers, args.timeout)
    except KeyboardInterrupt:
        print("\n[INFO] Monitor terminato.")


if __name__ == "__main__":
    main()
