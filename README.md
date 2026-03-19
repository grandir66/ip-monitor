# IP Monitor

Monitor ping in tempo reale e scanner di rete — un singolo file Python, zero dipendenze obbligatorie.

```
┌─ HEADER ──────────────────────────────────────────────────────┐
│ ▲ 45 UP  ▼ 3 DOWN  │ ████████████████████░░░ │ next 7s       │
├─ TABELLA (scroll ↑↓) ────────────────────────────────────────┤
│ #   VM              IP              Stato   Latenza  Streak  │
│ 1   SRV-DB01        10.0.1.5        ✖ DOWN  timeout  ↓3      │
│ 2   SRV-WEB01       10.0.1.10       ● UP    1.2 ms   ↑12     │
│ ...                                                           │
├─ MODIFICHE ───────────────────────────────────────────────────┤
│ 14:32:05  #8  SRV-DB01   10.0.1.5   ↓ LOST     in corso…     │
│ 14:30:12  #6  SRV-APP02  10.0.2.20  ↑ RECOVERED  2m03s       │
└───────────────────────────────────────────────────────────────┘
```

## Caratteristiche

- **Monitor** — cicli di ping paralleli con UI fullscreen (Rich) o fallback testo
- **Scanner** — scansiona reti CIDR, rileva host vivi, reverse DNS automatico
- **Navigazione** — scroll con frecce, PgUp/PgDn, Home/End, `q` per uscire
- **Un solo file** — `ping_monitor.py`, nessuna installazione, gira su qualsiasi macchina con Python 3.8+
- **Cross-platform** — Linux, macOS, Windows

## Requisiti

- **Python 3.8+**
- **`rich`** (opzionale, per UI fullscreen) — `pip install rich`

Senza `rich` funziona comunque con un'interfaccia testuale di base.

## Installazione

```bash
git clone https://github.com/domarc-srl/ip-monitor.git
cd ip-monitor
pip install rich   # opzionale ma consigliato
```

## Utilizzo

### Modalità Monitor

Monitora host da un file CSV:

```bash
# CSV di default (hosts_all.csv)
python3 ping_monitor.py

# CSV specifico
python3 ping_monitor.py --csv examples/hosts_example.csv

# Parametri personalizzati
python3 ping_monitor.py --csv hosts.csv --interval 5 --workers 50 --timeout 3

# Solo lista IP (senza monitor)
python3 ping_monitor.py --csv hosts.csv --list
```

### Modalità Scan

Scansiona reti per scoprire host attivi:

```bash
# Scansiona una rete
python3 ping_monitor.py --scan 192.168.1.0/24

# Scansiona più reti
python3 ping_monitor.py --scan 10.0.0.0/24 172.16.0.0/24

# Reti da file
python3 ping_monitor.py --scan-file examples/networks.txt

# Salva risultati in un CSV specifico
python3 ping_monitor.py --scan 192.168.1.0/24 -o lan_hosts.csv

# Scan + avvia subito il monitor sui risultati
python3 ping_monitor.py --scan 10.0.0.0/24 --monitor
```

### Navigazione nell'UI

| Tasto         | Azione                  |
|---------------|-------------------------|
| `↑` `↓`       | Scroll riga per riga    |
| `PgUp` `PgDn` | Scroll 10 righe         |
| `Home` `End`   | Inizio / fine lista     |
| `q`            | Esci                    |

## Formato CSV

Il CSV di input deve avere queste colonne:

| Colonna     | Obbligatoria | Descrizione                              |
|-------------|:------------:|------------------------------------------|
| `Name`      | si           | Nome dell'host / VM                      |
| `State`     | si           | Solo `Powered On` viene processato       |
| `Host`      | no           | Hypervisor / nodo di appartenenza        |
| `IP Address`| si           | Uno o più IPv4 separati da virgola       |

Esempio minimo:

```csv
Name,State,Host,IP Address
server-web,Powered On,node01,192.168.1.10
server-db,Powered On,node02,"10.0.0.5, 10.0.1.5"
```

Lo scanner genera CSV nello stesso formato, quindi i risultati di `--scan` sono direttamente usabili con `--csv`.

## Opzioni

```
--csv FILE          CSV con gli host da monitorare (default: hosts_all.csv)
--interval N        Secondi tra cicli di ping (default: 10)
--workers N         Thread paralleli per ping (default: 30)
--timeout N         Timeout ping in secondi (default: 2)
--list              Stampa IP estratti dal CSV e termina

--scan CIDR [...]   Reti CIDR da scansionare
--scan-file FILE    File con lista di reti (una per riga, # per commenti)
-o, --output FILE   CSV di output per lo scan (default: scan_<timestamp>.csv)
--monitor           Dopo lo scan, avvia il monitor sui risultati
```

## Logica di selezione IP

Quando un host ha più indirizzi IP:

1. Filtra solo IPv4 validi (esclude link-local, fe80, 169.254.x)
2. Preferisce IP **non** in subnet escluse (configurabili in `EXCLUDED_NETS`)
3. Se tutti gli IP sono in subnet escluse, usa il primo come fallback (segnato `fb`)

## Licenza

MIT — vedi [LICENSE](LICENSE)
