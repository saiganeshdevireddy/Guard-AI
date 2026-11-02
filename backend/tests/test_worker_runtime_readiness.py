import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.services.worker_runtime_readiness import (
    Ed25519WorkerImageVerifier,
    HostCapabilities,
    RuntimeLimits,
    discover_host_capabilities,
    validate_runtime_readiness,
)


def _limits(**overrides):
    values = {"vcpu": 2, "memory_mib": 1024, "disk_gib": 10, "bandwidth_mbps": 100}
    values.update(overrides)
    return RuntimeLimits(**values)


def test_current_host_discovery_is_read_only_and_windows_cannot_claim_kvm():
    host = discover_host_capabilities()
    if host.operating_system != "Linux":
        assert host.kvm_device_accessible is False
        assert host.firecracker_path is None


def test_readiness_fails_closed_when_any_infrastructure_evidence_is_missing():
    result = validate_runtime_readiness(
        HostCapabilities("Linux", True, "/opt/firecracker"),
        runtime_version_compatible=False,
        image_verified=False,
        limits=_limits(),
    )
    assert result.ready is False
    assert "runtime_version_unverified" in result.checks
    assert "worker_image_signature_unverified" in result.checks


def test_invalid_resource_quotas_fail_closed_even_when_runtime_is_ready():
    result = validate_runtime_readiness(
        HostCapabilities("Linux", True, "/opt/firecracker"),
        runtime_version_compatible=True,
        image_verified=True,
        limits=_limits(vcpu=0, memory_mib=100, disk_gib=0, bandwidth_mbps=0),
    )
    assert result.ready is False
    assert set(result.checks) == {
        "vcpu_limit_invalid", "memory_limit_invalid", "disk_limit_invalid", "bandwidth_limit_invalid"
    }


def test_readiness_can_pass_only_when_all_supplied_prerequisites_are_valid():
    result = validate_runtime_readiness(
        HostCapabilities("Linux", True, "/opt/firecracker"),
        runtime_version_compatible=True,
        image_verified=True,
        limits=_limits(),
    )
    assert result.ready is True
    assert result.checks == ()


def test_ed25519_image_verifier_checks_digest_and_rejects_tampering(tmp_path):
    image = tmp_path / "worker.img"
    signature_file = tmp_path / "worker.img.sig"
    image.write_bytes(b"trusted test image")
    key = Ed25519PrivateKey.generate()
    digest = hashlib.sha256(image.read_bytes()).digest()
    signature_file.write_bytes(key.sign(digest))
    verifier = Ed25519WorkerImageVerifier({"test-key": key.public_key()})

    assert verifier.verify(image, signature_file, "test-key") is True
    image.write_bytes(b"modified test image")
    assert verifier.verify(image, signature_file, "test-key") is False
    assert verifier.verify(image, signature_file, "unknown-key") is False
