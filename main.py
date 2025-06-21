import sys
import os
import json
from database_handler import FortiGateDatabaseHandler
from fortigate_parser import FortiGateConfigParser


def main(local_file_path, source_file_path):
    print(f"[INFO] Loading config from: {local_file_path}")

    # === Step 1: Parse configuration ===
    parser = FortiGateConfigParser()
    parsed_config = parser.parse_from_file(local_file_path)

    # Debug output
    print("[DEBUG] Parsed Configuration:")
    print(json.dumps(parsed_config, indent=2))

    # === Step 2: Prepare file metadata ===
    source_file = os.path.basename(source_file_path)
    local_file = local_file_path

    # === Step 3: Initialize DB handler ===
    db = FortiGateDatabaseHandler()

    # === Step 4: Save core configuration blocks ===
    db.save_system_global(parsed_config)
    db.save_system_interface(parsed_config)
    db.save_firewall_address(parsed_config)
    db.save_firewall_addrgrp(parsed_config)
    db.save_firewall_policies(parsed_config)
    db.save_user_local(parsed_config)
    db.save_dhcp_servers(parsed_config)
    db.save_vpn_phase1_interfaces(parsed_config)
    db.save_vpn_phase2_interfaces(parsed_config)

    # === Step 5: Save config blocks with file tracking ===
    db.save_firewall_service_custom(parsed_config, source_file, local_file)
    db.save_router_static(parsed_config, source_file, local_file)
    db.save_system_admin(parsed_config, source_file, local_file)
    db.save_firewall_schedule_recurring(parsed_config, source_file, local_file)
    db.save_firewall_vip(parsed_config, source_file, local_file)

    # === Step 6: Save change log with tracking ===
    for change in parser.change_log:
        change["source_file"] = source_file
        change["local_file"] = local_file
    db.save_config_changes(parser.change_log)

    # === Step 7: Output confirmation ===
    db.print_all_data()
    print("[INFO] Configuration saved to database.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python main.py <path_to_local_fortigate_config> <path_to_source_fortigate_config>")
        sys.exit(1)

    local_file_path = sys.argv[1]
    source_file_path = sys.argv[2]
    main(local_file_path, source_file_path)
