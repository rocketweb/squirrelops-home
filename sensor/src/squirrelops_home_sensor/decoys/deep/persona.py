"""One coherent synthetic world shared by every deep-decoy surface."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True)
class PersonaProject:
    """A synthetic project referenced by guest and agent surfaces."""

    name: str
    slug: str
    path: str
    repository: str
    scheme: str


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
    model_names: tuple[str, ...]
    login_password: str
    openai_api_key: str
    source_token: str

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
            "[branch \"release/2.8\"]\n"
            "\tremote = origin\n"
            "\tmerge = refs/heads/release/2.8\n"
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
                    "studio-build-tools": {
                        "url": f"http://{self.short_hostname}:8765/mcp",
                        "tools": [
                            "list_projects",
                            "read_runbook",
                            "get_deployment",
                            "search_secrets",
                        ],
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
                        "mcp__studio-build-tools__list_projects",
                        "mcp__studio-build-tools__read_runbook",
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
            f"[{build_stamp}]: WARN signing rotation ticket ENG-284 remains open\n"
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
            "\t\tF1E1D001 /* FieldKit-Staging */ = {isa = PBXNativeTarget; "
            f"name = {project.scheme}; productName = FieldKit; }};\n"
            "\t};\n"
            "\trootObject = F1E1D000;\n"
            "}\n"
        )
        app_source = (
            "import SwiftUI\n\n"
            "@main\n"
            "struct FieldKitApp: App {\n"
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
                "artifact": f"FieldKit-{self.build_number}.ipa",
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
                f"# {project.name}\n\nInternal iOS field-service client for "
                f"{self.organization}.\n"
            ),
            f"/Users/{self.username}/Projects/{project.slug}/FieldKit.xcodeproj/project.pbxproj": project_file,
            f"/Users/{self.username}/Projects/{project.slug}/Sources/App/FieldKitApp.swift": app_source,
            f"/Users/{self.username}/Projects/{project.slug}/fastlane/Fastfile": fastfile,
            f"/Users/{self.username}/.cursor/mcp.json": cursor_config,
            f"/Users/{self.username}/.claude/settings.json": claude_settings,
            f"/Users/{self.username}/.codex/config.toml": codex_config,
            f"/Users/{self.username}/Documents/Build Recovery.md": recovery_note,
            f"/Users/{self.username}/Library/Logs/fastlane/latest.log": fastlane_log,
            f"/Users/{self.username}/Builds/FieldKit-{self.build_number}/manifest.json": build_manifest,
            f"/Users/{self.username}/Builds/FieldKit-{self.build_number}/ExportOptions.plist": (
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
    project = PersonaProject(
        name="FieldKit iOS",
        slug="fieldkit-ios",
        path="/Users/buildbot/Projects/fieldkit-ios",
        repository="ssh://git@git.hawthorn.internal/mobile/fieldkit-ios.git",
        scheme="FieldKit-Staging",
    )
    build_number = 1800 + int(_derive(deployment_secret, "build-number", 4), 16) % 100
    password_suffix = int(_derive(deployment_secret, "login-password", 8), 16) % 1_000_000
    return StudioMiniPersona(
        persona_id="studio-mini-v1",
        hostname="studio-mini.local",
        display_name="Studio Build Mac",
        username="buildbot",
        organization="Hawthorn Devices",
        git_hostname="git.hawthorn.internal",
        deployment_name="fieldkit-ios-staging",
        build_number=build_number,
        created_at=normalized_time,
        primary_project=project,
        smb_shares=("Builds", "Engineering", "Time Machine Backups"),
        model_names=("fieldkit-coder:14b", "release-notes:latest"),
        login_password=f"Juniper!{password_suffix:06d}",
        openai_api_key=f"sk-proj-{_derive(deployment_secret, 'openai-api-key', 40)}",
        source_token=f"ghp_{_derive(deployment_secret, 'source-token', 36)}",
    )
