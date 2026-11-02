"""
Android Mobile Companion Synchronization & Telemetry API Router.

Enforces cross-platform boundaries without pretending that browser-based software
can silently monitor native Android subsystem internals.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.security.auth import require_permission

router = APIRouter(prefix="/android", tags=["Android Companion"])

# Explicitly fictional in-memory data keeps the companion workflow testable
# without implying that a native Android app or device is connected.
_DEMO_DEVICE = {
    "device_name": "Example Android device (demo)",
    "device_id": "DEMO-ANDROID-01",
    "connection_status": "DEMONSTRATION",
    "last_sync": None,
    "battery_percent": 88,
    "wifi_ssid": "Example network",
    "untrusted_sideloads_found": 0,
    "remote_lock_engaged": False,
}

class TelemetrySyncRequest(BaseModel):
    battery_percent: int | None = Field(default=None, ge=0, le=100)
    wifi_ssid: str | None = Field(default=None, max_length=128)
    untrusted_sideloads_found: int | None = Field(default=None, ge=0, le=10000)


class RemoteLockRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(default="Defensive remote lockdown command", max_length=500)


@router.get("/status")
def get_android_status(_user=Depends(require_permission("android:read"))):
    """Returns clearly marked demo telemetry; no real Android device is paired."""
    return {
        **_DEMO_DEVICE,
        "paired": False,
        "demo_mode": True,
        "remote_lock_supported": False,
        "message": "Demonstration data only. No native Android app or authenticated pairing service is included.",
    }


@router.post("/sync-telemetry")
def sync_android_telemetry(req: TelemetrySyncRequest, _user=Depends(require_permission("android:write"))):
    """Updates in-memory demo telemetry only; this does not contact a device."""
    if req.battery_percent is not None:
        _DEMO_DEVICE["battery_percent"] = req.battery_percent
    if req.wifi_ssid is not None:
        _DEMO_DEVICE["wifi_ssid"] = req.wifi_ssid
    if req.untrusted_sideloads_found is not None:
        _DEMO_DEVICE["untrusted_sideloads_found"] = req.untrusted_sideloads_found
    _DEMO_DEVICE["last_sync"] = datetime.now(timezone.utc).isoformat()
    return {"status": "SIMULATED_ONLY", "demo_mode": True, "device_state": get_android_status()}


@router.post("/remote-lock")
def trigger_android_remote_lock(req: RemoteLockRequest, _user=Depends(require_permission("android:write"))):
    """Changes only the in-memory demo flag; no lock command is sent to a device."""
    if req.device_id != _DEMO_DEVICE["device_id"]:
        raise HTTPException(status_code=404, detail="Unknown demonstration device ID")
    _DEMO_DEVICE["remote_lock_engaged"] = True
    return {
        "status": "SIMULATED_ONLY",
        "demo_mode": True,
        "command": "DEMO_DEVICE_LOCK",
        "device_id": req.device_id,
        "reason": req.reason,
        "dispatched_at": datetime.now(timezone.utc).isoformat(),
        "message": "Updated local demo state only; no Android device was contacted or locked.",
    }
