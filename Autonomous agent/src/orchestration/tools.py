import sys
from fastmcp import FastMCP
from src.utils.logging import get_logger

logger = get_logger("tools")

# Initialize FastMCP Server
mcp = FastMCP("CyberGuard-IR Tools")

@mcp.tool()
def collect_forensic_evidence(host_id: str) -> str:
    """
    Collects forensic evidence (running processes, active network connections) from a specific host.
    """
    logger.info("Executing forensic evidence collection", host_id=host_id, action="collect_forensic_evidence")
    
    # Return mock forensic data mimicking a live system
    evidence = {
        "host_id": host_id,
        "processes": [
            {"pid": 4, "name": "System", "path": "ntoskrnl.exe"},
            {"pid": 892, "name": "lsass.exe", "path": "C:\\Windows\\System32\\lsass.exe"},
            {"pid": 1044, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe"},
            {"pid": 4912, "name": "mimikatz.exe", "path": "C:\\temp\\mimikatz.exe", "cmdline": "mimikatz.exe sekurlsa::logonpasswords"},
            {"pid": 5832, "name": "vssadmin.exe", "path": "C:\\Windows\\System32\\vssadmin.exe", "cmdline": "vssadmin.exe delete shadows /all /quiet"}
        ],
        "network_connections": [
            {"protocol": "TCP", "local_ip": "10.0.0.15", "local_port": 22, "remote_ip": "192.168.99.180", "remote_port": 50412, "state": "ESTABLISHED"},
            {"protocol": "TCP", "local_ip": "10.0.0.15", "local_port": 49199, "remote_ip": "203.0.113.88", "remote_port": 443, "state": "ESTABLISHED"}
        ]
    }
    
    import json
    return json.dumps(evidence, indent=2)


@mcp.tool()
def quarantine_host(host_id: str) -> str:
    """
    Isolates a host from the network at the router/switch level, blocking all non-essential traffic.
    """
    logger.critical("ISOLATING HOST FROM NETWORK", host_id=host_id, action="quarantine_host")
    
    result = {
        "status": "Quarantined",
        "host_id": host_id,
        "isolation_rule_id": "FW-RULE-90412",
        "affected_subnets": ["10.0.0.0/24"],
        "timestamp": "2026-05-20T21:22:29+05:30",
        "message": f"Host '{host_id}' successfully quarantined in Security Zone. Active sessions terminated."
    }
    
    import json
    return json.dumps(result, indent=2)


@mcp.tool()
def disable_user_account(username: str) -> str:
    """
    Suspends a compromised user's active session and disables their Active Directory account.
    """
    logger.critical("SUSPENDING USER ACCOUNT", username=username, action="disable_user_account")
    
    result = {
        "status": "Disabled",
        "username": username,
        "directory_dn": f"CN={username},OU=Users,DC=bank,DC=local",
        "active_sessions_revoked": 3,
        "timestamp": "2026-05-20T21:22:29+05:30",
        "message": f"Active Directory account CN={username} disabled. Active Kerberos tickets invalidated."
    }
    
    import json
    return json.dumps(result, indent=2)
