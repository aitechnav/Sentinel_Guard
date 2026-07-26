"""Tests for SentinelGuard CLI bootstrap behavior."""

from pathlib import Path

import yaml

from sentinelguard import __version__
from sentinelguard.cli import main
from sentinelguard.gateway.config import GatewayConfig


def test_init_gateway_creates_runnable_starter_files(tmp_path, capsys):
    exit_code = main(["init", "--output-dir", str(tmp_path)])

    assert exit_code == 0
    expected_files = {
        "sentinelguard.yaml",
        "sentinelguard-gateway.yaml",
        ".env.example",
        "Dockerfile.sentinelguard",
        "docker-compose.sentinelguard.yml",
        "README.sentinelguard.md",
    }
    assert expected_files == {path.name for path in tmp_path.iterdir()}

    scanner_config = yaml.safe_load((tmp_path / "sentinelguard.yaml").read_text())
    assert scanner_config["prompt_scanners"]["prompt_injection"]["enabled"] is True
    assert scanner_config["prompt_scanners"]["pii"]["enabled"] is True
    assert scanner_config["output_scanners"]["data_leakage"]["enabled"] is True

    gateway_config = GatewayConfig.from_yaml(tmp_path / "sentinelguard-gateway.yaml")
    assert gateway_config.client_api_key_env == "SENTINELGUARD_GATEWAY_API_KEY"
    assert gateway_config.state_backend == "sqlite"
    assert gateway_config.state_path == "./.sentinelguard/gateway.sqlite3"
    assert gateway_config.streaming_mode == "buffered"
    assert [provider.model_name for provider in gateway_config.providers] == [
        "fast-chat",
        "smart-chat",
        "private-chat",
    ]
    assert gateway_config.virtual_keys[0].allowed_models == [
        "fast-chat",
        "smart-chat",
        "private-chat",
    ]
    compose_config = yaml.safe_load((tmp_path / "docker-compose.sentinelguard.yml").read_text())
    service = compose_config["services"]["sentinelguard-gateway"]
    assert service["build"]["dockerfile"] == "Dockerfile.sentinelguard"
    assert service["build"]["args"]["SENTINELGUARD_VERSION"] == (
        f"${{SENTINELGUARD_VERSION:-{__version__}}}"
    )
    assert service["image"] == "${SENTINELGUARD_IMAGE:-sentinelguard-gateway:local}"
    assert service["ports"] == ["${SENTINELGUARD_GATEWAY_PORT:-8080}:8080"]
    assert "--gateway-config" in service["command"]

    dockerfile = (tmp_path / "Dockerfile.sentinelguard").read_text()
    assert "sentinelguard[${SENTINELGUARD_EXTRAS}]==${SENTINELGUARD_VERSION}" in dockerfile

    output = capsys.readouterr().out
    assert "sentinelguard gateway --config sentinelguard.yaml" in output
    assert "http://localhost:8080/v1" in output


def test_init_library_profile_skips_gateway_files(tmp_path):
    exit_code = main(
        [
            "init",
            "--profile",
            "library",
            "--preset",
            "minimal",
            "--output-dir",
            str(tmp_path),
        ]
    )

    assert exit_code == 0
    assert {path.name for path in tmp_path.iterdir()} == {
        "sentinelguard.yaml",
        "README.sentinelguard.md",
    }
    scanner_config = yaml.safe_load((tmp_path / "sentinelguard.yaml").read_text())
    assert "prompt_injection" in scanner_config["prompt_scanners"]
    assert "unbounded_consumption" not in scanner_config["prompt_scanners"]


def test_init_does_not_overwrite_existing_files_without_force(tmp_path):
    config_path = tmp_path / "sentinelguard.yaml"
    config_path.write_text("mode: permissive\n", encoding="utf-8")

    exit_code = main(["init", "--output-dir", str(tmp_path)])

    assert exit_code == 0
    assert config_path.read_text(encoding="utf-8") == "mode: permissive\n"


def test_init_force_overwrites_existing_files(tmp_path):
    config_path = tmp_path / "sentinelguard.yaml"
    config_path.write_text("mode: permissive\n", encoding="utf-8")

    exit_code = main(["init", "--output-dir", str(tmp_path), "--force"])

    assert exit_code == 0
    assert yaml.safe_load(config_path.read_text(encoding="utf-8"))["mode"] == "standard"


def test_init_without_docker_omits_compose_file(tmp_path):
    exit_code = main(["init", "--output-dir", str(tmp_path), "--without-docker"])

    assert exit_code == 0
    assert not Path(tmp_path / "docker-compose.sentinelguard.yml").exists()


def test_config_set_get_and_toggle_updates_scanner_config(tmp_path, capsys):
    config_path = tmp_path / "sentinelguard.yaml"
    assert main(["config", "init", "--output", str(config_path)]) == 0

    assert main(["config", "set", "mode", "strict", "--file", str(config_path)]) == 0
    assert (
        main(
            [
                "config",
                "set",
                "prompt_scanners.prompt_injection.threshold",
                "0.72",
                "--file",
                str(config_path),
            ]
        )
        == 0
    )
    assert (
        main(["config", "disable", "pii", "--type", "prompt", "--file", str(config_path)])
        == 0
    )

    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert config["mode"] == "strict"
    assert config["prompt_scanners"]["prompt_injection"]["threshold"] == 0.72
    assert config["prompt_scanners"]["pii"]["enabled"] is False

    assert (
        main(
            [
                "config",
                "get",
                "prompt_scanners.prompt_injection.threshold",
                "--file",
                str(config_path),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.rstrip().endswith("0.72")


def test_gateway_config_set_get_updates_generated_gateway_config(tmp_path, capsys):
    assert main(["init", "--output-dir", str(tmp_path)]) == 0
    gateway_path = tmp_path / "sentinelguard-gateway.yaml"

    assert (
        main(
            [
                "gateway-config",
                "set",
                "gateway.cache_enabled",
                "true",
                "--file",
                str(gateway_path),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "gateway-config",
                "set",
                "gateway.providers.0.priority",
                "7",
                "--file",
                str(gateway_path),
            ]
        )
        == 0
    )

    config = yaml.safe_load(gateway_path.read_text(encoding="utf-8"))
    assert config["gateway"]["cache_enabled"] is True
    assert config["gateway"]["providers"][0]["priority"] == 7

    assert (
        main(
            [
                "gateway-config",
                "get",
                "gateway.routing_strategy",
                "--file",
                str(gateway_path),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.rstrip().endswith("priority")
