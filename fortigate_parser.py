import re
import json
from collections import defaultdict
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, Text, ForeignKey
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.sqlite import insert

class FortiGateConfigParser:
    def __init__(self):
        self.config = {}
        self.stack = []
        self.change_log = []
        self.current_file = ""

    def _get_nested_dict(self):
        d = self.config
        for key in self.stack:
            d = d.setdefault(key, {})
        return d

    def _normalize_value(self, key, value):
        list_keys = {
            "member", "service", "allowaccess", "dns-server",
            "ntp-server", "dnsfilter-profile", "ssh-filter-profile",
            "ipv6-address", "groups"
        }
        value = value.strip('"')
        if key in list_keys:
            return [v.strip('"') for v in value.split()]
        return value

    def _assign_value(self, key, value):
        current_dict = self._get_nested_dict()
        current_dict[key] = value

    def save_system_global(self, config_dict):
        session = self.Session()
        try:
            data = config_dict.get("system global", {})
            if not data:
                return
            session.execute(self.global_settings.insert().values(
                hostname=data.get("hostname"),
                timezone=data.get("timezone"),
                admintimeout=data.get("admintimeout"),
                alias=" | ".join(data.get("alias", [])) if isinstance(data.get("alias"), list) else data.get("alias")
            ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def parse_line(self, line):
        line = line.strip()
        if not line or line.startswith("#"):
            return

        if line.startswith("config "):
            block = line.split("config ", 1)[1].strip()
            self.stack.append(block)

        elif line.startswith("edit "):
            context = line.split("edit ", 1)[1].strip().strip('"')
            current_dict = self._get_nested_dict()
            self.stack.append(context)
            current_dict.setdefault(context, {})

        elif line.startswith("set "):
            parts = line.split(None, 2)
            if len(parts) == 2:
                key, value = parts[1], ""
            else:
                _, key, value = parts
            value = self._normalize_value(key, value)
            self._assign_value(key, value)

        elif line.startswith("unset "):
            key = line.split("unset ", 1)[1].strip()
            current_dict = self._get_nested_dict()
            current_dict.pop(key, None)

        elif line.startswith("delete "):
            entry = line.split("delete ", 1)[1].strip()
            current_dict = self._get_nested_dict()
            current_dict.pop(entry, None)

        elif line.startswith("rename "):
            parts = line.split()
            if len(parts) == 3:
                old, new = parts[1], parts[2]
                current_dict = self._get_nested_dict()
                if old in current_dict:
                    current_dict[new] = current_dict.pop(old)

        elif line == "next":
            if self.stack:
                self.stack.pop()

        elif line == "end":
            if self.stack:
                self.stack.pop()

        elif line.startswith("unset "):
            key = line.split("unset ", 1)[1].strip()
            current_dict = self._get_nested_dict()
            current_dict.pop(key, None)
            self.change_log.append({
                "action": "unset",
                "object_type": self.stack[-1] if self.stack else "global",
                "object_name": key,
                "new_name": None,
                "source_file": self.current_file,
                "timestamp": datetime.datetime.utcnow().isoformat()
            })

        elif line.startswith("delete "):
            entry = line.split("delete ", 1)[1].strip()
            current_dict = self._get_nested_dict()
            current_dict.pop(entry, None)
            self.change_log.append({
                "action": "delete",
                "object_type": self.stack[-1] if self.stack else "global",
                "object_name": entry,
                "new_name": None,
                "source_file": self.current_file,
                "timestamp": datetime.datetime.utcnow().isoformat()
            })

        elif line.startswith("rename "):
            parts = line.split()
            if len(parts) == 3:
                old, new = parts[1], parts[2]
                current_dict = self._get_nested_dict()
                if old in current_dict:
                    current_dict[new] = current_dict.pop(old)
                    self.change_log.append({
                        "action": "rename",
                        "object_type": self.stack[-1] if self.stack else "global",
                        "object_name": old,
                        "new_name": new,
                        "source_file": self.current_file,
                        "timestamp": datetime.datetime.utcnow().isoformat()
                    })

    def parse_config(self, lines):
        for line in lines:
            self.parse_line(line)
        return self.config

    def parse_from_file(self, filepath):
        self.current_file = filepath.split('/')[-1]
        with open(filepath, 'r') as f:
            lines = f.readlines()
        return self.parse_config(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python fortigate_config_parser.py <config_file_path>")
    else:
        parser = FortiGateConfigParser()
        config = parser.parse_from_file(sys.argv[1])
        print(json.dumps(config.get("system dhcp server", {}), indent=2))
