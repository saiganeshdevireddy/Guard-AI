"""Read-only Linux/KVM/Firecracker readiness checks.

These checks never create a VM and do not claim isolation. Runtime attestation and
trusted key distribution still belong to an independently operated Linux worker.
"""
import hashlib
import os
import platform
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass(frozen=True)
class RuntimeLimits:
    vcpu: int
    memory_mib: int
    disk_gib: int
    bandwidth_mbps: int


@dataclass(frozen=True)
class HostCapabilities:
    operating_system: str
    kvm_device_accessible: bool
    firecracker_path: str | None


@dataclass(frozen=True)
class ReadinessResult:
    ready: bool
    checks: tuple[str, ...]


class WorkerImageVerifier(Protocol):
    def verify(self, image_path: Path, signature_path: Path, key_id: str) -> bool:
        """Verify an image digest using a trusted, operator-provided public key."""


class Ed25519WorkerImageVerifier:
    """Ed25519 image-digest verifier; public keys must come from trusted configuration."""

    def __init__(self, trusted_public_keys: dict[str, Ed25519PublicKey]):
        self._keys = dict(trusted_public_keys)

    def verify(self, image_path: Path, signature_path: Path, key_id: str) -> bool:
        key = self._keys.get(key_id)
        if key is None or not image_path.is_file() or not signature_path.is_file():
            return False
        try:
            digest = hashlib.sha256()
            with image_path.open("rb") as image:
                for chunk in iter(lambda: image.read(1024 * 1024), b""):
                    digest.update(chunk)
            signature = signature_path.read_bytes()
            key.verify(signature, digest.digest())
            return True
        except (OSError, InvalidSignature, ValueError):
            return False


def discover_host_capabilities() -> HostCapabilities:
    """Inspect local host capabilities without changing system configuration."""
    os_name = platform.system()
    kvm_accessible = os_name == "Linux" and os.access("/dev/kvm", os.R_OK | os.W_OK)
    return HostCapabilities(
        operating_system=os_name,
        kvm_device_accessible=kvm_accessible,
        firecracker_path=shutil.which("firecracker") if os_name == "Linux" else None,
    )


def validate_runtime_readiness(
    capabilities: HostCapabilities,
    *,
    runtime_version_compatible: bool,
    image_verified: bool,
    limits: RuntimeLimits,
) -> ReadinessResult:
    """Return fail-closed readiness; injected facts are for a trusted worker probe."""
    failures: list[str] = []
    if capabilities.operating_system != "Linux":
        failures.append("linux_host_required")
    if capabilities.kvm_device_accessible is not True:
        failures.append("kvm_access_unavailable")
    if not capabilities.firecracker_path:
        failures.append("firecracker_runtime_unavailable")
    if runtime_version_compatible is not True:
        failures.append("runtime_version_unverified")
    if image_verified is not True:
        failures.append("worker_image_signature_unverified")
    if not (1 <= limits.vcpu <= 32):
        failures.append("vcpu_limit_invalid")
    if not (256 <= limits.memory_mib <= 65536):
        failures.append("memory_limit_invalid")
    if not (1 <= limits.disk_gib <= 512):
        failures.append("disk_limit_invalid")
    if not (1 <= limits.bandwidth_mbps <= 10000):
        failures.append("bandwidth_limit_invalid")
    return ReadinessResult(ready=not failures, checks=tuple(failures))
