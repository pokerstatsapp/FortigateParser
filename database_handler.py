from sqlalchemy import (
    create_engine, MetaData, Table, Column, Integer, String, ForeignKey
)
from sqlalchemy.orm import sessionmaker
import datetime

class FortiGateDatabaseHandler:
    def __init__(self, db_url='sqlite:///fortigate_config.db'):
        self.engine = create_engine(db_url, echo=False)
        self.metadata = MetaData()

        self.system_interface = Table(
            'system_interface', self.metadata,
            Column('name', String, primary_key=True),
            Column('ip', String),
            Column('allowaccess', String),
            Column('alias', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.firewall_address = Table(
            'firewall_address', self.metadata,
            Column('name', String, primary_key=True),
            Column('subnet', String),
            Column('fqdn', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.firewall_addrgrp = Table(
            'firewall_addrgrp', self.metadata,
            Column('name', String, primary_key=True),
            Column('member', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.firewall_policies = Table(
            'firewall_policies', self.metadata,
            Column('id', Integer, primary_key=True),
            Column('name', String),
            Column('srcintf', String),
            Column('dstintf', String),
            Column('srcaddr', String),
            Column('dstaddr', String),
            Column('service', String),
            Column('action', String),
            Column('schedule', String),
            Column('logtraffic', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.vpn_phase1 = Table(
            'vpn_phase1', self.metadata,
            Column('name', String, primary_key=True),
            Column('interface', String),
            Column('peertype', String),
            Column('net_device', String),
            Column('proposal', String),
            Column('remote_gw', String),
            Column('psksecret', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.vpn_phase2 = Table(
            'vpn_phase2', self.metadata,
            Column('name', String, primary_key=True),
            Column('phase1name', String),
            Column('proposal', String),
            Column('pfs', String),
            Column('replay', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.phase2_selectors = Table(
            'phase2_selectors', self.metadata,
            Column('vpn_name', String, ForeignKey('vpn_phase2.name')),
            Column('selector_id', String),
            Column('src_subnet', String),
            Column('dst_subnet', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.dhcp_servers = Table(
            'dhcp_servers', self.metadata,
            Column('id', Integer, primary_key=True),
            Column('dns_service', String),
            Column('default_gateway', String),
            Column('netmask', String),
            Column('interface', String),
            Column('timezone_option', String),
            Column('tftp_server', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.ip_ranges = Table(
            'ip_ranges', self.metadata,
            Column('dhcp_id', Integer, ForeignKey('dhcp_servers.id')),
            Column('range_id', String),
            Column('start_ip', String),
            Column('end_ip', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.user_local = Table(
            'user_local', self.metadata,
            Column('username', String, primary_key=True),
            Column('password', String),
            Column('type', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.system_global = Table(
            'system_global', self.metadata,
            Column('setting', String, primary_key=True),
            Column('value', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.config_changes = Table(
            'config_changes', self.metadata,
            Column('id', Integer, primary_key=True, autoincrement=True),
            Column('action', String),
            Column('object_type', String),
            Column('object_name', String),
            Column('new_name', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('timestamp', String)
        )

        self.firewall_service_custom = Table(
            'firewall_service_custom', self.metadata,
            Column('name', String, primary_key=True),
            Column('protocol', String),
            Column('tcp_portrange', String),
            Column('udp_portrange', String),
            Column('icmp_type', String),
            Column('icmp_code', String),
            Column('comment', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.router_static = Table(
            'router_static', self.metadata,
            Column('id', Integer, primary_key=True),
            Column('dst', String),
            Column('gateway', String),
            Column('device', String),
            Column('priority', String),
            Column('distance', String),
            Column('comment', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.system_admin = Table(
            'system_admin', self.metadata,
            Column('username', String, primary_key=True),
            Column('password', String),
            Column('ssh_public_key1', String),
            Column('accprofile', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.firewall_schedule_recurring = Table(
            'firewall_schedule_recurring', self.metadata,
            Column('name', String, primary_key=True),
            Column('start', String),
            Column('end', String),
            Column('day', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.firewall_vip = Table(
            'firewall_vip', self.metadata,
            Column('name', String, primary_key=True),
            Column('extip', String),
            Column('mappedip', String),
            Column('portforward', String),
            Column('extport', String),
            Column('mappedport', String),
            Column('protocol', String),
            Column('comment', String),
            Column('source_file', String),
            Column('local_file', String),
            Column('created_at', String)
        )

        self.metadata.drop_all(self.engine) # FOR DEV STAGE
        self.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def save_config_changes(self, change_log):
        session = self.Session()
        try:
            for change in change_log:
                session.execute(self.config_changes.insert().values(
                    action=change.get("action"),
                    object_type=change.get("object_type"),
                    object_name=change.get("object_name"),
                    new_name=change.get("new_name"),
                    source_file=change.get("source_file"),
                    local_file=change.get("local_file"),
                    timestamp=change.get("timestamp")
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_system_global(self, config_dict):
        session = self.Session()
        try:
            session.execute(self.system_global.delete())
            data = config_dict.get("system global", {})
            for key, value in data.items():
                session.execute(self.system_global.insert().values(
                    setting=key,
                    value=str(value)
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_system_interface(self, config_dict):
        session = self.Session()
        try:
            session.execute(self.system_interface.delete())
            data = config_dict.get("system interface", {})
            for name, values in data.items():
                session.execute(self.system_interface.insert().values(
                    name=name,
                    ip=values.get("ip"),
                    allowaccess=" | ".join(values.get("allowaccess", [])),
                    alias=values.get("alias"),
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_firewall_address(self, config_dict):
        session = self.Session()
        try:
            session.execute(self.firewall_address.delete())
            data = config_dict.get("firewall address", {})
            for name, values in data.items():
                session.execute(self.firewall_address.insert().values(
                    name=name,
                    subnet=values.get("subnet"),
                    fqdn=values.get("fqdn"),
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_firewall_addrgrp(self, config_dict):
        session = self.Session()
        try:
            session.execute(self.firewall_addrgrp.delete())
            data = config_dict.get("firewall addrgrp", {})
            for name, values in data.items():
                session.execute(self.firewall_addrgrp.insert().values(
                    name=name,
                    member=" | ".join(values.get("member", [])),
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_user_local(self, config_dict):
        session = self.Session()
        try:
            session.execute(self.user_local.delete())
            data = config_dict.get("user local", {})
            for username, values in data.items():
                session.execute(self.user_local.insert().values(
                    username=username,
                    password=values.get("password"),
                    type=values.get("type"),
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_firewall_policies(self, config_dict):
        session = self.Session()
        try:
            session.execute(self.firewall_policies.delete())
            data = config_dict.get("firewall policy", {})
            for policy_id, values in data.items():
                session.execute(self.firewall_policies.insert().values(
                    id=int(policy_id),
                    name=values.get("name"),
                    srcintf=values.get("srcintf"),
                    dstintf=values.get("dstintf"),
                    srcaddr=values.get("srcaddr"),
                    dstaddr=values.get("dstaddr"),
                    service=" | ".join(values.get("service", [])),
                    action=values.get("action"),
                    schedule=values.get("schedule"),
                    logtraffic=values.get("logtraffic"),
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_vpn_phase1_interfaces(self, config_dict):
        session = self.Session()
        try:
            session.execute(self.vpn_phase1.delete())
            data = config_dict.get("vpn ipsec phase1-interface", {})
            for name, values in data.items():
                session.execute(self.vpn_phase1.insert().values(
                    name=name,
                    interface=values.get("interface"),
                    peertype=values.get("peertype"),
                    net_device=values.get("net-device"),
                    proposal=values.get("proposal"),
                    remote_gw=values.get("remote-gw"),
                    psksecret=values.get("psksecret"),
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_vpn_phase2_interfaces(self, config_dict):
        session = self.Session()
        try:
            session.execute(self.vpn_phase2.delete())
            session.execute(self.phase2_selectors.delete())

            data = config_dict.get("vpn ipsec phase2-interface", {})
            for name, values in data.items():
                session.execute(self.vpn_phase2.insert().values(
                    name=name,
                    phase1name=values.get("phase1name"),
                    proposal=values.get("proposal"),
                    pfs=values.get("pfs"),
                    replay=values.get("replay"),
                ))
                selectors = values.get("phase2selectors", {})
                for sel_id, sel_vals in selectors.items():
                    session.execute(self.phase2_selectors.insert().values(
                        vpn_name=name,
                        selector_id=sel_id,
                        src_subnet=sel_vals.get("src-subnet"),
                        dst_subnet=sel_vals.get("dst-subnet"),
                    ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_firewall_service_custom(self, config_dict, source_file, local_file):
        session = self.Session()
        try:
            session.execute(self.firewall_service_custom.delete())
            services = config_dict.get("firewall service custom", {})
            for name, values in services.items():
                session.execute(self.firewall_service_custom.insert().values(
                    name=name,
                    protocol=values.get("protocol"),
                    tcp_portrange=values.get("tcp-portrange"),
                    udp_portrange=values.get("udp-portrange"),
                    icmp_type=values.get("icmp-type"),
                    icmp_code=values.get("icmp-code"),
                    comment=values.get("comment"),
                    source_file=source_file,
                    local_file=local_file,
                    created_at=datetime.datetime.utcnow().isoformat()
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_router_static(self, config_dict, source_file, local_file):
        session = self.Session()
        try:
            session.execute(self.router_static.delete())
            routes = config_dict.get("router static", {})
            for route_id, values in routes.items():
                session.execute(self.router_static.insert().values(
                    id=int(route_id),
                    dst=values.get("dst"),
                    gateway=values.get("gateway"),
                    device=values.get("device"),
                    priority=values.get("priority"),
                    distance=values.get("distance"),
                    comment=values.get("comment"),
                    source_file=source_file,
                    local_file=local_file,
                    created_at=datetime.datetime.utcnow().isoformat()
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_system_admin(self, config_dict, source_file, local_file):
        session = self.Session()
        try:
            session.execute(self.system_admin.delete())
            admins = config_dict.get("system admin", {})
            for username, values in admins.items():
                session.execute(self.system_admin.insert().values(
                    username=username,
                    password=values.get("password"),
                    ssh_public_key1=values.get("ssh-public-key1"),
                    accprofile=values.get("accprofile"),
                    source_file=source_file,
                    local_file=local_file,
                    created_at=datetime.datetime.utcnow().isoformat()
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_firewall_schedule_recurring(self, config_dict, source_file, local_file):
        session = self.Session()
        try:
            session.execute(self.firewall_schedule_recurring.delete())
            schedules = config_dict.get("firewall schedule recurring", {})
            for name, values in schedules.items():
                session.execute(self.firewall_schedule_recurring.insert().values(
                    name=name,
                    start=values.get("start"),
                    end=values.get("end"),
                    day=" | ".join(values.get("day", [])),
                    source_file=source_file,
                    local_file=local_file,
                    created_at=datetime.datetime.utcnow().isoformat()
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_dhcp_servers(self, config_dict):
        dhcp_data = config_dict.get("dhcp server", {})
        session = self.Session()
        try:
            session.execute(self.dhcp_servers.delete())
            session.execute(self.ip_ranges.delete())
            for dhcp_id, dhcp_config in dhcp_data.items():
                session.execute(self.dhcp_servers.insert().values(
                    id=int(dhcp_id),
                    dns_service=dhcp_config.get("dns-service"),
                    default_gateway=dhcp_config.get("default-gateway"),
                    netmask=dhcp_config.get("netmask"),
                    interface=dhcp_config.get("interface"),
                    timezone_option=dhcp_config.get("timezone-option"),
                    tftp_server=dhcp_config.get("tftp-server")
                ))

                ip_ranges = dhcp_config.get("ip-range", {})
                for range_id, range_data in ip_ranges.items():
                    session.execute(self.ip_ranges.insert().values(
                        dhcp_id=int(dhcp_id),
                        range_id=range_id,
                        start_ip=range_data.get("start-ip"),
                        end_ip=range_data.get("end-ip")
                    ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_firewall_vip(self, config_dict, source_file, local_file):
        session = self.Session()
        try:
            session.execute(self.firewall_vip.delete())
            vips = config_dict.get("firewall vip", {})
            for name, values in vips.items():
                session.execute(self.firewall_vip.insert().values(
                    name=name,
                    extip=values.get("extip"),
                    extintf=values.get("extintf"),
                    mappedip=values.get("mappedip"),
                    portforward=values.get("portforward"),
                    protocol=values.get("protocol"),
                    extport=values.get("extport"),
                    mappedport=values.get("mappedport"),
                    source_file=source_file,
                    local_file=local_file,
                    created_at=datetime.datetime.utcnow().isoformat()
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def generate_change_report(self):
        from collections import defaultdict
        from sqlalchemy import text

        with self.engine.connect() as conn:
            result = conn.execute(text("SELECT source_file, action FROM config_changes"))
            summary = defaultdict(lambda: defaultdict(int))

            for row in result:
                summary[row.source_file][row.action] += 1

            print("\n[CHANGE REPORT SUMMARY]")
            for source_file, actions in summary.items():
                print(f"\nSource: {source_file}")
                for action, count in actions.items():
                    print(f"  {action}: {count}")

    def print_all_data(self):
        session = self.Session()
        try:
            for table in self.metadata.sorted_tables:
                print(f"\n--- {table.name} ---")
                results = session.execute(table.select()).mappings().all()
                for row in results:
                    print(dict(row))
        finally:
            session.close()
