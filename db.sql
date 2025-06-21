----------------- init schemas

CREATE TABLE IF NOT EXISTS system_interface (
    name TEXT PRIMARY KEY,
    ip TEXT,
    allowaccess TEXT,
    alias TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS firewall_address (
    name TEXT PRIMARY KEY,
    subnet TEXT,
    fqdn TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS firewall_addrgrp (
    name TEXT PRIMARY KEY,
    member TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS firewall_policies (
    id INTEGER PRIMARY KEY,
    name TEXT,
    srcintf TEXT,
    dstintf TEXT,
    srcaddr TEXT,
    dstaddr TEXT,
    service TEXT,
    action TEXT,
    schedule TEXT,
    logtraffic TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS vpn_phase1 (
    name TEXT PRIMARY KEY,
    interface TEXT,
    peertype TEXT,
    net_device TEXT,
    proposal TEXT,
    remote_gw TEXT,
    psksecret TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS vpn_phase2 (
    name TEXT PRIMARY KEY,
    phase1name TEXT,
    proposal TEXT,
    pfs TEXT,
    replay TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS phase2_selectors (
    vpn_name TEXT,
    selector_id TEXT,
    src_subnet TEXT,
    dst_subnet TEXT,
    source_file TEXT,
    created_at TEXT,
    FOREIGN KEY (vpn_name) REFERENCES vpn_phase2(name)
);

CREATE TABLE IF NOT EXISTS dhcp_servers (
    id INTEGER PRIMARY KEY,
    dns_service TEXT,
    default_gateway TEXT,
    netmask TEXT,
    interface TEXT,
    timezone_option TEXT,
    tftp_server TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS ip_ranges (
    dhcp_id INTEGER,
    range_id TEXT,
    start_ip TEXT,
    end_ip TEXT,
    source_file TEXT,
    created_at TEXT,
    FOREIGN KEY (dhcp_id) REFERENCES dhcp_servers(id)
);

CREATE TABLE IF NOT EXISTS user_local (
    username TEXT PRIMARY KEY,
    password TEXT,
    type TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS system_global (
    setting TEXT PRIMARY KEY,
    value TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS firewall_service_custom (
    name TEXT PRIMARY KEY,
    protocol TEXT,
    tcp_portrange TEXT,
    udp_portrange TEXT,
    icmp_type TEXT,
    icmp_code TEXT,
    comment TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS router_static (
    id INTEGER PRIMARY KEY,
    dst TEXT,
    gateway TEXT,
    device TEXT,
    priority TEXT,
    distance TEXT,
    comment TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS system_admin (
    username TEXT PRIMARY KEY,
    password TEXT,
    ssh_public_key1 TEXT,
    accprofile TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS firewall_schedule_recurring (
    name TEXT PRIMARY KEY,
    start TEXT,
    end TEXT,
    day TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS firewall_vip (
    name TEXT PRIMARY KEY,
    extip TEXT,
    extintf TEXT,
    mappedip TEXT,
    portforward TEXT,
    protocol TEXT,
    extport TEXT,
    mappedport TEXT,
    source_file TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS config_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    object_type TEXT,
    object_name TEXT,
    new_name TEXT,
    source_file TEXT,
    timestamp TEXT
);


------------------------------ query


SELECT 
  p.id,
  p.name,
  si.name AS src_interface,
  si.ip AS src_ip,
  si.alias AS src_alias,
  di.name AS dst_interface,
  di.ip AS dst_ip,
  fa_src.subnet AS src_subnet,
  fa_dst.subnet AS dst_subnet,
  p.service,
  p.action,
  p.schedule,
  p.logtraffic
FROM firewall_policies p
LEFT JOIN system_interface si ON p.srcintf = si.name
LEFT JOIN system_interface di ON p.dstintf = di.name
LEFT JOIN firewall_address fa_src ON p.srcaddr = fa_src.name
LEFT JOIN firewall_address fa_dst ON p.dstaddr = fa_dst.name
ORDER BY p.id;



----

SELECT
    p.id AS policy_id,
    p.name AS policy_name,
    p.srcintf,
    si1.ip AS srcintf_ip,
    p.dstintf,
    si2.ip AS dstintf_ip,
    p.srcaddr,
    a1.subnet AS src_subnet,
    p.dstaddr,
    a2.subnet AS dst_subnet,
    p.service,
    p.action,
    p.schedule,
    p.logtraffic
FROM firewall_policies p
LEFT JOIN system_interface si1 ON p.srcintf = si1.name
LEFT JOIN system_interface si2 ON p.dstintf = si2.name
LEFT JOIN firewall_address a1 ON p.srcaddr = a1.name
LEFT JOIN firewall_address a2 ON p.dstaddr = a2.name;



-----------------------------------------------------------


-------- VIP mappings

SELECT
    name,
    extip,
    extintf,
    mappedip,
    portforward,
    protocol,
    extport,
    mappedport
FROM firewall_vip;



------ DHCP server with its IP ranges

SELECT
    d.id,
    d.interface,
    d.default_gateway,
    r.range_id,
    r.start_ip,
    r.end_ip
FROM dhcp_servers d
LEFT JOIN ip_ranges r ON d.id = r.dhcp_id;


----- VPN Phase1 + Phase2 + Selectors

SELECT
    p2.name AS vpn_phase2,
    p2.phase1name,
    p1.remote_gw,
    s.selector_id,
    s.src_subnet,
    s.dst_subnet
FROM vpn_phase2 p2
LEFT JOIN vpn_phase1 p1 ON p2.phase1name = p1.name
LEFT JOIN phase2_selectors s ON p2.name = s.vpn_name;


----- Admin users & access profile

SELECT
    username,
    password,
    accprofile,
    ssh_public_key1
FROM system_admin;


----- All service custom entries with port/protocol


SELECT
    name,
    protocol,
    tcp_portrange,
    udp_portrange,
    icmp_type,
    icmp_code,
    comment
FROM firewall_service_custom;



----------------------------------------------------------------------------------

-- 1. system_interface
SELECT * FROM system_interface;

-- 2. firewall_address
SELECT * FROM firewall_address;

-- 3. firewall_policy
SELECT * FROM firewall_policies;

-- 4. user_local
SELECT * FROM user_local;

-- 5. dhcp_servers
SELECT * FROM dhcp_servers;

-- 6. vpn_phase1_interfaces
SELECT * FROM vpn_phase1_interfaces;

-- 7. vpn_phase2_interfaces
SELECT * FROM vpn_phase2_interfaces;

-- 8. firewall_service_custom
SELECT * FROM firewall_service_custom;

-- 9. router_static
SELECT * FROM router_static;

-- 10. system_admin
SELECT * FROM system_admin;

-- 11. firewall_schedule_recurring
SELECT * FROM firewall_schedule_recurring;

-- 12. firewall_vip
SELECT * FROM firewall_vip;

-- 13. config_changes
SELECT * FROM config_changes;
