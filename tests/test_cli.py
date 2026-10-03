"""Tests for Canary Fabric CLI commands."""

import json
from unittest.mock import patch

from click.testing import CliRunner

from canary_fabric.cli.main import main as canary_main
from canary_fabric.cli.proxy_cli import main as proxy_main
from canary_fabric.core.crypto import derive_canary_token
from canary_fabric.core.watermark import WatermarkEncoder
from canary_fabric.forensics.certificate import LeakCertificate


def test_cli_main_help():
    runner = CliRunner()
    result = runner.invoke(canary_main, ["--help"])
    assert result.exit_code == 0
    assert "Canary Fabric: Zero-Trust Cryptographic Tripwires" in result.output


def test_cli_watermark_command():
    runner = CliRunner()
    result = runner.invoke(
        canary_main,
        ["watermark", "-t", "Project Pegasus confidential budget is $50M.", "--tenant-id", "corp_a", "--doc-id", "doc_99"],
    )
    assert result.exit_code == 0
    assert "Canary Token Generated & Injected Successfully" in result.output
    assert "Canary Signature:" in result.output
    assert "corp_a" in result.output


def test_cli_inspect_clean_and_watermarked():
    runner = CliRunner()

    # Clean text
    clean_res = runner.invoke(canary_main, ["inspect", "-t", "This is normal public text."])
    assert clean_res.exit_code == 0
    assert "Clean: No canary tokens detected" in clean_res.output

    # Watermarked text
    token = derive_canary_token("secret", "tenant_a", "doc_1", "chunk_0")
    wm_text = WatermarkEncoder.inject_watermark("Confidential acquisition document.", token)
    wm_res = runner.invoke(canary_main, ["inspect", "-t", wm_text])
    assert wm_res.exit_code == 0
    assert "WARNING: Active Canary Token(s) Detected!" in wm_res.output
    assert token in wm_res.output


def test_cli_honeytoken_types():
    runner = CliRunner()
    for ht_type in ["api_key", "database_uri", "aws_secret", "jwt", "email"]:
        res = runner.invoke(canary_main, ["honeytoken", "-k", ht_type, "--tenant-id", "corp_x", "--doc-id", "target_doc"])
        assert res.exit_code == 0
        assert "Synthetic Honeytoken Generated" in res.output
        assert "corp_x" in res.output


def test_cli_verify_certificate(tmp_path):
    runner = CliRunner()
    secret_key = "test_verification_secret"

    cert = LeakCertificate(
        certificate_id="cert_test_123",
        tenant_id="tenant_alpha",
        source_doc_id="doc_mna",
        source_chunk_id="chunk_0",
        canary_token="9A8B7C6D5E4F3A2B",
        leak_channel="chat_stream",
        action_taken="BLOCK_AND_SEVER",
    )
    cert.sign(secret_key)

    cert_file = tmp_path / "valid_cert.json"
    cert_file.write_text(cert.to_canonical_json(), encoding="utf-8")

    # Verify valid
    res_valid = runner.invoke(canary_main, ["verify", "-f", str(cert_file), "--secret-key", secret_key])
    assert res_valid.exit_code == 0
    assert "AUTHENTIC FORENSIC PROOF: Signature Validated" in res_valid.output

    # Verify tampered
    tampered_data = json.loads(cert.to_canonical_json())
    tampered_data["source_doc_id"] = "tampered_doc_id"
    tampered_file = tmp_path / "tampered_cert.json"
    tampered_file.write_text(json.dumps(tampered_data), encoding="utf-8")

    res_invalid = runner.invoke(canary_main, ["verify", "-f", str(tampered_file), "--secret-key", secret_key])
    assert res_invalid.exit_code == 0
    assert "INVALID CERTIFICATE: Cryptographic Signature Mismatch!" in res_invalid.output


def test_cli_benchmark():
    runner = CliRunner()
    result = runner.invoke(canary_main, ["benchmark", "-n", "10"])
    assert result.exit_code == 0
    assert "Average Scan Latency" in result.output
    assert "Throughput" in result.output


def test_cli_eval():
    runner = CliRunner()
    result = runner.invoke(canary_main, ["eval", "-t", "Project Apollo financial records."])
    assert result.exit_code == 0
    assert "Synthetic Red-Team Adversarial Evaluation Report" in result.output
    assert "Summary Scorecard" in result.output


def test_proxy_cli():
    runner = CliRunner()
    help_res = runner.invoke(proxy_main, ["--help"])
    assert help_res.exit_code == 0
    assert "Start the CanaryFabric streaming tripwire reverse proxy" in help_res.output

    with patch("uvicorn.run") as mock_run:
        run_res = runner.invoke(proxy_main, ["--port", "9090", "--host", "127.0.0.1", "--action", "redact_and_continue"])
        assert run_res.exit_code == 0
        assert mock_run.called
        assert "Starting CanaryFabric Reverse Proxy on 127.0.0.1:9090" in run_res.output
