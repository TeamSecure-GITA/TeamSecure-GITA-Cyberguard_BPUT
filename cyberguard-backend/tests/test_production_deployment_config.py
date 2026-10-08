from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_production_compose_uses_persistent_postgres_backups_and_dependencies():
    compose = yaml.safe_load((ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8"))
    worker = compose["services"]["worker"]
    postgres = compose["services"]["postgres"]
    backend = compose["services"]["backend"]

    assert worker["environment"]["CYBERGUARD_BACKUP_PATH"] == "/data/cyberguard-postgres.backup"
    assert "cyberguard-data:/data" in worker["volumes"]
    assert "cyberguard-postgres:/var/lib/postgresql/data" in postgres["volumes"]
    assert worker["depends_on"]["backend"]["condition"] == "service_healthy"
    assert backend["depends_on"]["postgres"]["condition"] == "service_healthy"


def test_backend_image_copies_both_dependency_inputs_and_postgres_16_client():
    dockerfile = (ROOT / "cyberguard-backend" / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY requirements-models.lock ./" in dockerfile
    assert "--require-hashes -r requirements-models.lock" in dockerfile
    assert "postgresql-client-16" in dockerfile


def test_frontend_docker_build_has_an_npm_lockfile_for_clean_install():
    frontend = ROOT / "cyberguard-frontend"
    assert (frontend / "package-lock.json").is_file()
    dockerfile = (frontend / "Dockerfile").read_text(encoding="utf-8")
    assert "RUN npm ci" in dockerfile


def test_render_and_ci_install_hash_locked_python_dependencies():
    render = yaml.safe_load((ROOT / "render.yaml").read_text(encoding="utf-8"))
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    web_service = next(service for service in render["services"] if service["type"] == "web")
    assert "--require-hashes -r requirements.lock" in web_service["buildCommand"]
    assert "--require-hashes -r requirements-dev.lock" in workflow
