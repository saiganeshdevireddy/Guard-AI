"""
Role-based permissions and high-impact action human approval gating.
"""
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel


class AgentRole(str, Enum):
    CONTROLLER = "CONTROLLER"
    FINDER = "FINDER"
    DEFENCE = "DEFENCE"
    OFFENCE = "OFFENCE"
    INFORMER = "INFORMER"
    USER = "USER"
    ADMIN = "ADMIN"


class Permission(str, Enum):
    # Read / Telemetry
    VIEW_TELEMETRY = "VIEW_TELEMETRY"
    SCAN_URL = "SCAN_URL"
    SCAN_FILE = "SCAN_FILE"
    SCAN_NETWORK = "SCAN_NETWORK"
    
    # Vault & Cryptography
    ENCRYPT_DATA = "ENCRYPT_DATA"
    DECRYPT_DATA = "DECRYPT_DATA"
    MANAGE_KEYS = "MANAGE_KEYS"
    
    # Informer / Voice
    ANNOUNCE_ALERT = "ANNOUNCE_ALERT"
    
    # Defensive Emergency / Lockdown (High Impact)
    ACTIVATE_EMERGENCY = "ACTIVATE_EMERGENCY"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    ISOLATE_NETWORK = "ISOLATE_NETWORK"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    RESET_EMERGENCY = "RESET_EMERGENCY"


# Matrix mapping roles to permitted actions
ROLE_PERMISSIONS: Dict[AgentRole, Set[Permission]] = {
    AgentRole.FINDER: {
        Permission.VIEW_TELEMETRY,
        Permission.SCAN_URL,
        Permission.SCAN_FILE,
        Permission.SCAN_NETWORK,
    },
    AgentRole.DEFENCE: {
        Permission.VIEW_TELEMETRY,
        Permission.ENCRYPT_DATA,
        Permission.DECRYPT_DATA,
        Permission.MANAGE_KEYS,
        Permission.QUARANTINE_FILE,
    },
    AgentRole.OFFENCE: {
        Permission.VIEW_TELEMETRY,
        Permission.ACTIVATE_EMERGENCY,
        Permission.QUARANTINE_FILE,
        Permission.ISOLATE_NETWORK,
        Permission.TERMINATE_PROCESS,
        Permission.RESET_EMERGENCY,
    },
    AgentRole.INFORMER: {
        Permission.VIEW_TELEMETRY,
        Permission.ANNOUNCE_ALERT,
    },
    AgentRole.CONTROLLER: {
        # Central coordinator can initiate all standard operations
        Permission.VIEW_TELEMETRY,
        Permission.SCAN_URL,
        Permission.SCAN_FILE,
        Permission.SCAN_NETWORK,
        Permission.ENCRYPT_DATA,
        Permission.DECRYPT_DATA,
        Permission.ANNOUNCE_ALERT,
        Permission.ACTIVATE_EMERGENCY,
        Permission.QUARANTINE_FILE,
    },
    AgentRole.USER: {
        # End user / Administrator
        *list(Permission),
    },
}

# Actions that MANDATE explicit human operator confirmation
HIGH_IMPACT_PERMISSIONS: Set[Permission] = {
    Permission.ISOLATE_NETWORK,
    Permission.TERMINATE_PROCESS,
    Permission.ACTIVATE_EMERGENCY,
    Permission.RESET_EMERGENCY,
    Permission.MANAGE_KEYS,
}


def check_permission(role: AgentRole, permission: Permission, human_confirmed: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether an actor role has the requested permission
    and verifies if high-impact human confirmation is met.
    """
    allowed_perms = ROLE_PERMISSIONS.get(role, set())
    if permission not in allowed_perms:
        return False, f"Role '{role.value}' does not possess permission '{permission.value}'."

    if permission in HIGH_IMPACT_PERMISSIONS and not human_confirmed:
        return False, f"Permission '{permission.value}' is a high-impact operation requiring explicit human confirmation."

    return True, None
