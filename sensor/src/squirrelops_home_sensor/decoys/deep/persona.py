"""One coherent synthetic world shared by every deep-decoy surface."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from importlib import resources
from typing import Any

from squirrelops_home_sensor.decoys import corpora
from squirrelops_home_sensor.decoys.profile import derive_key


@dataclass(frozen=True)
class PersonaProject:
    """A synthetic project referenced by guest and agent surfaces."""

    name: str
    slug: str
    path: str
    repository: str
    scheme: str
    product: str = "FieldKit"
    description: str = "Internal iOS field-service client"


@dataclass(frozen=True)
class PersonaModel:
    """One local model the Studio claims to serve, with consistent details."""

    name: str
    family: str
    parameter_size: str
    size: int
    digest: str


@dataclass(frozen=True)
class StudioMiniPersona:
    """Immutable identity and content for the flagship 2.1 deep decoy."""

    persona_id: str
    hostname: str
    display_name: str
    username: str
    organization: str
    git_hostname: str
    deployment_name: str
    build_number: int
    created_at: datetime
    primary_project: PersonaProject
    smb_shares: tuple[str, ...]
    models: tuple[PersonaModel, ...]
    login_password: str
    openai_api_key: str
    source_token: str
    mcp_server_name: str = "studio-build-tools"
    mcp_server_version: str = "0.9.7"
    ollama_version: str = "0.9.7"
    # (role, presented name): roles are what the protocol handlers dispatch
    # on; names are what an agent sees.
    mcp_tools: tuple[tuple[str, str], ...] = (
        ("list_projects", "list_projects"),
        ("read_runbook", "read_runbook"),
        ("get_deployment", "get_deployment"),
        ("search_secrets", "search_secrets"),
    )
    ticket_id: str = "ENG-284"
    release_branch: str = "release/2.8"

    @property
    def model_names(self) -> tuple[str, ...]:
        return tuple(model.name for model in self.models)

    def tool_name(self, role: str) -> str:
        """The presented name of a tool role."""
        for known_role, name in self.mcp_tools:
            if known_role == role:
                return name
        raise KeyError(role)

    def tool_role(self, name: str) -> str | None:
        """The role behind a presented tool name, if it is one of ours."""
        for role, known_name in self.mcp_tools:
            if known_name == name:
                return role
        return None

    @property
    def short_hostname(self) -> str:
        return self.hostname.removesuffix(".local")

    @property
    def model_created(self) -> int:
        return int(self.created_at.timestamp())

    def guest_files(self) -> dict[str, str]:
        """Return the canonical files materialized in the memory-only guest."""
        project = self.primary_project
        build_time = self.created_at - timedelta(minutes=17)
        signing_time = self.created_at - timedelta(days=2, hours=3)
        build_stamp = build_time.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S +0000")
        signing_stamp = signing_time.astimezone(UTC).strftime("%Y-%m-%d")

        git_config = (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            "\tbare = false\n"
            "[remote \"origin\"]\n"
            f"\turl = {project.repository}\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            f"[branch \"{self.release_branch}\"]\n"
            "\tremote = origin\n"
            f"\tmerge = refs/heads/{self.release_branch}\n"
        )
        shell_history = "\n".join(
            (
                f"cd {project.path}",
                "git pull --ff-only",
                f"bundle exec fastlane ios staging build:{self.build_number}",
                "tail -80 ~/Library/Logs/fastlane/latest.log",
                "open ~/Documents/Build\\ Recovery.md",
                "ollama list",
                "cursor .",
            )
        ) + "\n"
        environment = (
            f"OPENAI_BASE_URL=http://{self.short_hostname}:1234/v1\n"
            f"OPENAI_API_KEY={self.openai_api_key}\n"
            f"SOURCE_MIRROR_TOKEN={self.source_token}\n"
            f"DEPLOYMENT={self.deployment_name}\n"
            "MATCH_READONLY=true\n"
        )
        cursor_config = json.dumps(
            {
                "mcpServers": {
                    self.mcp_server_name: {
                        "url": f"http://{self.short_hostname}:8765/mcp",
                        "tools": [name for _role, name in self.mcp_tools],
                    }
                }
            },
            indent=2,
        ) + "\n"
        claude_settings = json.dumps(
            {
                "env": {
                    "OPENAI_BASE_URL": f"http://{self.short_hostname}:1234/v1",
                    "BUILD_PROJECT": project.path,
                },
                "permissions": {
                    "allow": [
                        f"mcp__{self.mcp_server_name}__{self.tool_name('list_projects')}",
                        f"mcp__{self.mcp_server_name}__{self.tool_name('read_runbook')}",
                    ]
                },
            },
            indent=2,
        ) + "\n"
        codex_config = (
            'model_provider = "studio"\n'
            f'model = "{self.model_names[0]}"\n\n'
            "[model_providers.studio]\n"
            'name = "Studio Mini Local"\n'
            f'base_url = "http://{self.short_hostname}:1234/v1"\n'
            'env_key = "OPENAI_API_KEY"\n'
        )
        recovery_note = (
            f"# {self.organization} build recovery\n\n"
            f"Last rehearsal: {signing_stamp}\n\n"
            f"The {project.name} staging lane is `{self.deployment_name}`. "
            f"Start in `{project.path}` and use `{self.git_hostname}` if the "
            "working copy needs to be rebuilt.\n\n"
            "The Finder target is `Builds`. Older signed artifacts are in "
            "`Time Machine Backups`; do not prune that share until the signing "
            "rotation is closed.\n"
        )
        fastlane_log = (
            f"[{build_stamp}]: Running lane ios staging\n"
            f"[{build_stamp}]: Project {project.slug}, scheme {project.scheme}\n"
            f"[{build_stamp}]: Build {self.build_number} uploaded to "
            f"{self.deployment_name}\n"
            f"[{build_stamp}]: WARN signing rotation ticket {self.ticket_id} remains open\n"
        )

        shell_profile = (
            'export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"\n'
            'export SHELL="/bin/zsh"\n'
            'export LANG="en_US.UTF-8"\n'
            f'export PROJECT_HOME="{project.path}"\n'
        )
        shell_config = (
            'PROMPT="%F{green}buildbot@studio-mini%f %F{blue}%~%f %# "\n'
            'setopt HIST_IGNORE_DUPS SHARE_HISTORY\n'
            'alias ll="ls -lah"\n'
        )
        project_file = (
            "// !$*UTF8*$!\n"
            "{\n"
            "\tarchiveVersion = 1;\n"
            "\tobjectVersion = 77;\n"
            "\tobjects = {\n"
            f"\t\tF1E1D001 /* {project.scheme} */ = {{isa = PBXNativeTarget; "
            f"name = {project.scheme}; productName = {project.product}; }};\n"
            "\t};\n"
            "\trootObject = F1E1D000;\n"
            "}\n"
        )
        app_source = (
            "import SwiftUI\n\n"
            "@main\n"
            f"struct {project.product}App: App {{\n"
            "    var body: some Scene { WindowGroup { RouteListView() } }\n"
            "}\n"
        )
        fastfile = (
            "default_platform(:ios)\n\n"
            "platform :ios do\n"
            "  lane :staging do |options|\n"
            f"    build_app(scheme: \"{project.scheme}\")\n"
            "    upload_to_testflight(skip_waiting_for_build_processing: true)\n"
            "  end\n"
            "end\n"
        )
        build_manifest = json.dumps(
            {
                "project": project.slug,
                "scheme": project.scheme,
                "build": self.build_number,
                "configuration": "Staging",
                "artifact": f"{project.product}-{self.build_number}.ipa",
                "status": "uploaded",
            },
            indent=2,
        ) + "\n"

        return {
            "/etc/hostname": f"{self.short_hostname}\n",
            f"/Users/{self.username}/.zprofile": shell_profile,
            f"/Users/{self.username}/.zshrc": shell_config,
            f"/Users/{self.username}/.zsh_history": shell_history,
            f"/Users/{self.username}/Projects/{project.slug}/.env.local": environment,
            f"/Users/{self.username}/Projects/{project.slug}/.gitignore": (
                ".env.local\nDerivedData/\n.build/\nfastlane/report.xml\n"
            ),
            f"/Users/{self.username}/Projects/{project.slug}/.git/config": git_config,
            f"/Users/{self.username}/Projects/{project.slug}/README.md": (
                f"# {project.name}\n\n{project.description} for "
                f"{self.organization}.\n"
            ),
            f"/Users/{self.username}/Projects/{project.slug}/{project.product}.xcodeproj/project.pbxproj": project_file,
            f"/Users/{self.username}/Projects/{project.slug}/Sources/App/{project.product}App.swift": app_source,
            f"/Users/{self.username}/Projects/{project.slug}/fastlane/Fastfile": fastfile,
            f"/Users/{self.username}/.cursor/mcp.json": cursor_config,
            f"/Users/{self.username}/.claude/settings.json": claude_settings,
            f"/Users/{self.username}/.codex/config.toml": codex_config,
            f"/Users/{self.username}/Documents/Build Recovery.md": recovery_note,
            f"/Users/{self.username}/Library/Logs/fastlane/latest.log": fastlane_log,
            f"/Users/{self.username}/Builds/{project.product}-{self.build_number}/manifest.json": build_manifest,
            f"/Users/{self.username}/Builds/{project.product}-{self.build_number}/ExportOptions.plist": (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<plist version="1.0"><dict><key>method</key>'
                '<string>app-store-connect</string></dict></plist>\n'
            ),
            f"/Users/{self.username}/Library/Time Machine Backups/README.txt": (
                "Studio Mini migration snapshots. Do not prune during signing rotation.\n"
            ),
        }


def _derive(secret: bytes, label: str, length: int) -> str:
    digest = hmac.new(secret, label.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:length]


@lru_cache(maxsize=1)
def _corpus() -> dict[str, Any]:
    return json.loads(resources.files(corpora).joinpath("persona.json").read_text("utf-8"))


def _pick(secret: bytes, label: str, options: list[Any]) -> Any:
    """One corpus entry per label, from its own HKDF key."""
    key = derive_key(secret, "studio_persona", label)
    return options[int.from_bytes(key[:8], "big") % len(options)]


def _model(secret: bytes, label: str, spec: dict[str, Any], *, product: str) -> PersonaModel:
    return PersonaModel(
        name=str(spec["name"]).format(product=product.lower()),
        family=str(spec["family"]),
        parameter_size=str(spec["parameter_size"]),
        size=int(spec["size"]),
        digest=derive_key(secret, "studio_persona", "model_digest", label).hex(),
    )


def build_studio_mini_persona(
    deployment_secret: bytes,
    created_at: datetime,
) -> StudioMiniPersona:
    """Build a stable persona with install-unique, synthetic credentials."""
    if len(deployment_secret) < 32:
        raise ValueError("Deployment secret must contain at least 32 bytes")
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("Persona creation time must be timezone-aware")

    normalized_time = created_at.astimezone(UTC)
    corpus = _corpus()
    # Hostname, username, organization, and shares are baked into the guest
    # image; everything an attacker reads out of the persona's files and the
    # agent endpoints is a draw.
    chosen = _pick(deployment_secret, "project", corpus["projects"])
    project = PersonaProject(
        name=str(chosen["name"]),
        slug=str(chosen["slug"]),
        path=f"/Users/buildbot/Projects/{chosen['slug']}",
        repository=f"ssh://git@git.hawthorn.internal/mobile/{chosen['slug']}.git",
        scheme=f"{chosen['product']}-Staging",
        product=str(chosen["product"]),
        description=str(chosen["description"]),
    )
    tool_set = _pick(deployment_secret, "tool_names", corpus["tool_name_sets"])
    release_minor = int.from_bytes(
        derive_key(deployment_secret, "studio_persona", "release_branch")[:2], "big"
    )
    ticket_number = 120 + int.from_bytes(
        derive_key(deployment_secret, "studio_persona", "ticket")[:2], "big"
    ) % 800
    build_number = 1800 + int(_derive(deployment_secret, "build-number", 4), 16) % 100
    password_suffix = int(_derive(deployment_secret, "login-password", 8), 16) % 1_000_000
    password_word = _pick(deployment_secret, "password_word", corpus["password_words"])
    return StudioMiniPersona(
        persona_id="studio-mini-v1",
        hostname="studio-mini.local",
        display_name="Studio Build Mac",
        username="buildbot",
        organization="Hawthorn Devices",
        git_hostname="git.hawthorn.internal",
        deployment_name=f"{project.slug}-staging",
        build_number=build_number,
        created_at=normalized_time,
        primary_project=project,
        smb_shares=("Builds", "Engineering", "Time Machine Backups"),
        models=(
            _model(
                deployment_secret, "coder",
                _pick(deployment_secret, "coder_model", corpus["coder_models"]),
                product=project.product,
            ),
            _model(
                deployment_secret, "helper",
                _pick(deployment_secret, "helper_model", corpus["helper_models"]),
                product=project.product,
            ),
        ),
        login_password=f"{password_word}!{password_suffix:06d}",
        openai_api_key=f"sk-proj-{_derive(deployment_secret, 'openai-api-key', 40)}",
        source_token=f"ghp_{_derive(deployment_secret, 'source-token', 36)}",
        mcp_server_name=str(_pick(deployment_secret, "mcp_server", corpus["mcp_servers"])),
        mcp_server_version=str(_pick(deployment_secret, "mcp_version", corpus["mcp_server_versions"])),
        ollama_version=str(_pick(deployment_secret, "ollama_version", corpus["ollama_versions"])),
        mcp_tools=tuple((role, str(tool_set[role])) for role in (
            "list_projects", "read_runbook", "get_deployment", "search_secrets"
        )),
        ticket_id=f"{_pick(deployment_secret, 'ticket_prefix', corpus['ticket_prefixes'])}-{ticket_number}",
        release_branch=f"release/{2 + release_minor % 3}.{release_minor % 12}",
    )
