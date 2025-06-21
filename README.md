---

### ✅ `README.md`

```markdown
# FortiGate Configuration Parser & Database Loader

This project parses FortiGate `.conf` CLI configuration files and stores them in a normalized SQLite database. It allows for structured queries, version tracking, and configuration audits via a clean relational schema.

---

## 📦 Features

- Parse nested FortiGate configuration blocks (`system interface`, `firewall policy`, `vpn`, etc.)
- Save parsed data into corresponding normalized SQL tables
- Log source/local filenames and timestamps for traceability
- View configuration relationships via JOINs (e.g., firewall policy → interface → address)
- Track config changes for audit/versioning
- View or query config data in DB tools like DB Browser for SQLite

---

## 🧱 Project Structure

```

.
├── main.py                      # Entry point to parse and save .conf file
├── fortigate\_parser.py         # Parses FortiGate CLI config into structured dict
├── database\_handler.py         # Saves structured config into normalized SQLite schema
├── models.py                   # (Optional) SQLAlchemy models (if separated)
├── fortigate\_config.db         # Generated SQLite database
├── sample\_configs/             # Optional: store example FortiGate .conf files
└── README.md

````

---

## ▶️ Usage

### Run the Parser:
```bash
python main.py <path_to_local_conf> <source_file_name>
````

**Example:**

```bash
python main.py C:/Users/Lior.M/Downloads/fortigate1.conf config1
```

This will:

* Parse the config file
* Save entries into SQLite
* Log `source_file` and `local_file`
* Print loaded config and saved tables

---

## 🔍 Querying the Data

You can open `fortigate_config.db` using tools like:

* [DB Browser for SQLite](https://sqlitebrowser.org/)
* VSCode SQLite extensions

### Example Query: Join Firewall Policy With Interfaces and Addresses

```sql
SELECT
  p.id AS policy_id,
  p.name AS policy_name,
  p.srcintf,
  si_src.alias AS srcintf_alias,
  si_src.ip AS srcintf_ip,
  p.dstintf,
  si_dst.alias AS dstintf_alias,
  si_dst.ip AS dstintf_ip,
  p.srcaddr,
  fa_src.subnet AS src_subnet,
  p.dstaddr,
  fa_dst.subnet AS dst_subnet,
  p.service,
  p.action,
  p.schedule,
  p.logtraffic,
  p.source_file,
  p.created_at
FROM firewall_policies p
LEFT JOIN system_interface si_src ON si_src.name = p.srcintf
LEFT JOIN system_interface si_dst ON si_dst.name = p.dstintf
LEFT JOIN firewall_address fa_src ON fa_src.name = p.srcaddr
LEFT JOIN firewall_address fa_dst ON fa_dst.name = p.dstaddr;
```

---

## ⚙️ Development Tips

### Reset DB (if schema changes)

If you change the schema (e.g., add `source_file`), delete the old DB:

```bash
rm fortigate_config.db
```

Or in Python:

```python
self.metadata.drop_all(self.engine)  # Only for development
self.metadata.create_all(self.engine)
```

---

## ✅ Supported Config Blocks

* ✅ system interface
* ✅ firewall policy
* ✅ firewall address
* ✅ firewall addrgrp
* ✅ dhcp servers
* ✅ vpn ipsec (phase1-interface, phase2-interface)
* ✅ user local
* ✅ firewall service custom
* ✅ router static
* ✅ system admin
* ✅ firewall schedule recurring
* ✅ firewall vip
* ✅ system global
* ⬜️ unset / delete / rename (planned)
* ⬜️ plugin / complex DSL (planned)

---

## 🔐 TODO

* [ ] Support for `unset`, `delete`, `rename` commands
* [ ] Handle multi-line plugin structures
* [ ] Add Alembic for DB migrations
* [ ] Export to JSON / Excel
* [ ] Generate config comparison reports

---

## 🛠 Requirements

* Python 3.8+
* `sqlalchemy`
* `pandas`
* `sqlite3` (built-in)

Install:

```bash
pip install -r requirements.txt
```
