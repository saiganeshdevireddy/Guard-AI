"""
Android Mobile Companion Synchronization & Telemetry API Router.

Enforces cross-platform boundaries without pretending that browser-based software
can silently monitor native Android subsystem internals.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/android", tags=["Android Companion"])

# In-memory mock/companion device state
_DEVICE_STATE = {
    "device_name": "Pixel 8 Pro (Guard Companion)",
    "device_id": "AND-G8-9042",
    "os_version": "Android 14 (API Level 34)",
    "security_patch_level": "2026-10-05",
    "connection_status": "ONLINE",
    "last_sync": datetime.now(timezone.utc).isoformat(),
    "battery_percent": 88,
    "wifi_ssid": "CyberLab_Secure_5G",
    "permission_audit": {
        "apps_with_accessibility": 1,
        "apps_with_sms_read": 3,
        "apps_with_location": 7,
        "untrusted_sideloads_found": 0,
    },
    "remote_lock_engaged": False,
}


class TelemetrySyncRequest(BaseModel):
    battery_percent: Optional[int] = None
    wifi_ssid: Optional[str] = None
    untrusted_sideloads_found: Optional[int] = None


class RemoteLockRequest(BaseModel):
    device_id: str
    reason: str = "Defensive remote lockdown command"


@router.get("/status")
def get_android_status():
    """Returns paired Android companion status, patch level, and permission audit summary."""
    return _DEVICE_STATE


@router.post("/sync-telemetry")
def sync_android_telemetry(req: TelemetrySyncRequest):
    """Syncs live telemetry from Android companion client to Guard AI backend."""
    if req.battery_percent is not None:
        _DEVICE_STATE["battery_percent"] = req.battery_percent
    if req.wifi_ssid is not None:
        _DEVICE_STATE["wifi_ssid"] = req.wifi_ssid
    if req.untrusted_sideloads_found is not None:
        _DEVICE_STATE["permission_audit"]["untrusted_sideloads_found"] = req.untrusted_sideloads_found
    _DEVICE_STATE["last_sync"] = datetime.now(timezone.utc).isoformat()
    return {
        "status": "SYNCED",
        "device_state": _DEVICE_STATE
    }


@router.post("/remote-lock")
def trigger_android_remote_lock(req: RemoteLockRequest):
    """Sends a defensive remote lock command to the companion device."""
    if req.device_id != _DEVICE_STATE["device_id"]:
        raise HTTPException(status_code=404, detail="Unknown device ID")
    _DEVICE_STATE["remote_lock_engaged"] = True
    return {
        "status": "COMMAND_DISPATCHED",
        "command": "DEVICE_LOCK",
        "device_id": req.device_id,
        "reason": req.reason,
        "dispatched_at": datetime.now(timezone.utc).isoformat()
    }
