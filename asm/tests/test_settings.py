"""Тесты чистой схемы Settings; сами не читают сеть и не меняют ASM_DB."""
from __future__ import annotations

import ast
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError, asdict
from types import MappingProxyType
from unittest import mock

from asm.settings import (
    ScanSettings, Settings, SettingsError, project_explicit_environment,
)


class TestSettings(unittest.TestCase):
    def test_defaults_match_legacy_scan_defaults_in_clean_process(self):
        """Первый typed snapshot в точности повторяет текущий scan.DEFAULTS."""
        project_root = pathlib.Path(__file__).resolve().parents[1]
        code = r'''
import json
from dataclasses import asdict
from asm import scan
from asm.settings import ScanSettings
print(json.dumps({"legacy": scan.DEFAULTS, "typed": asdict(ScanSettings())}, sort_keys=True))
'''
        with tempfile.TemporaryDirectory(prefix="asm-settings-defaults-") as tmp:
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("ASM_")}
            env["ASM_DB"] = os.path.join(tmp, "isolated.sqlite")
            prior_path = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (str(project_root) +
                                 (os.pathsep + prior_path if prior_path else ""))
            proc = subprocess.run(
                [sys.executable, "-c", code], cwd=project_root, env=env,
                text=True, capture_output=True, check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(result["typed"], result["legacy"])

    def test_layers_have_documented_precedence_and_objects_are_independent(self):
        first = Settings.from_sources(
            mode_values={"ASM_WORKERS": "3", "ASM_ACTIVE_SCAN": "0",
                         "ASM_FFUF": "1"},
            environment={"ASM_WORKERS": "5", "ASM_ACTIVE_SCAN": "yes",
                         "ASM_FFUF": "0"},
            cli_overrides={"workers": 7, "deep_paths": True},
        )
        second = Settings.from_sources(environment={"ASM_WORKERS": "2"})

        self.assertEqual(first.scan.workers, 7)
        self.assertTrue(first.scan.active_scan)
        self.assertTrue(first.scan.deep_paths)
        self.assertEqual(second.scan.workers, 2)
        self.assertNotEqual(first.scan.workers, second.scan.workers)
        self.assertEqual(Settings().scan.workers, 8)

    def test_mappings_and_process_environment_are_not_mutated(self):
        mode = MappingProxyType({"workers": 3})
        environment = {"ASM_MAX_IPS": "0", "ASM_ESTATE": "false"}
        cli = {"max_probes": 0}
        before = dict(os.environ)
        mode_before, env_before, cli_before = dict(mode), dict(environment), dict(cli)

        settings = Settings.from_sources(
            mode_values=mode, environment=environment, cli_overrides=cli,
        )

        self.assertEqual(settings.scan.workers, 3)
        self.assertEqual(settings.scan.max_ips, 0)
        self.assertFalse(settings.scan.estate)
        self.assertEqual(settings.scan.max_probes, 0)
        self.assertEqual(dict(mode), mode_before)
        self.assertEqual(environment, env_before)
        self.assertEqual(cli, cli_before)
        self.assertEqual(dict(os.environ), before)

    def test_full_environment_snapshot_projects_only_known_scan_fields(self):
        environment = {"ASM_WORKERS": "4", "OTHER_DOMAIN_SETTING": "ignored"}
        before = dict(environment)
        settings = Settings.from_environment_snapshot(environment)
        self.assertEqual(settings.scan.workers, 4)
        self.assertEqual(environment, before)

    def test_explicit_environment_projection_is_allowlisted_and_non_mutating(self):
        source = {
            "ASM_WORKERS": "2",
            "ASM_PROFILE": "operator-profile",
            "ASM_LLM_KEY": "synthetic-secret-sentinel",
            "UNRELATED": "ignored",
        }
        before = dict(source)
        projected = project_explicit_environment(
            source, additional_keys=("ASM_PROFILE",),
        )

        self.assertEqual(projected, {
            "ASM_WORKERS": "2", "ASM_PROFILE": "operator-profile",
        })
        self.assertNotIn("ASM_LLM_KEY", projected)
        self.assertNotIn("UNRELATED", projected)
        self.assertEqual(source, before)
        with self.assertRaisesRegex(SettingsError, "разрешённым ASM_"):
            project_explicit_environment(source, additional_keys=("LLM_KEY",))

    def test_environment_snapshot_uses_mode_then_explicit_environment(self):
        """Полный mode preset фильтруется до scan; env остаётся сильнее mode."""
        mode_values = {
            "ASM_PROFILE": "pentest",
            "ASM_WORKERS": "6",
            "ASM_ACTIVE_SCAN": "1",
            "ASM_FFUF": "0",
            "ASM_QUEUE_IMPACT": "1",
        }
        environment = {
            "ASM_WORKERS": "4",
            "ASM_ACTIVE_SCAN": "off",
            "ASM_LLM_KEY": "must-not-be-read-or-reported",
        }

        settings = Settings.from_environment_snapshot(
            environment, mode_values=mode_values,
        )
        mode_only = Settings.from_environment_snapshot(
            {}, mode_values=mode_values,
        )

        self.assertEqual(settings.scan.workers, 4)
        self.assertFalse(settings.scan.active_scan)
        self.assertFalse(settings.scan.deep_paths)
        self.assertEqual(mode_only.scan.workers, 6)
        self.assertTrue(mode_only.scan.active_scan)
        self.assertFalse(mode_only.scan.deep_paths)
        self.assertEqual(environment["ASM_LLM_KEY"], "must-not-be-read-or-reported")

    def test_typed_domain_groups_keep_precedence_and_parse_values(self):
        settings = Settings.from_sources(
            mode_values={
                "ASM_PROFILE": "pentest", "ASM_STEALTH": "warn",
                "ASM_QUEUE_IMPACT": "1", "ASM_NUCLEI_RATE": "80",
                "ASM_INWARD_PULL": "yes",
            },
            environment={
                "ASM_PROFILE": "safe", "ASM_QUEUE_IMPACT": "off",
                "ASM_RATE_SPREAD": "0",
            },
        )
        self.assertEqual(settings.engines.profile, "safe")
        self.assertEqual(settings.engines.nuclei_rate, 80)
        self.assertEqual(settings.engines.rate_spread, 0.0)
        self.assertEqual(settings.stealth.mode, "warn")
        self.assertFalse(settings.planner.queue_impact)
        self.assertTrue(settings.transport.inward_pull)
        defaults = Settings()
        self.assertIsNone(defaults.active.nuclei_templates)
        self.assertIsNone(defaults.model.llm_model)
        with self.assertRaises(AttributeError):
            _ = defaults.model.not_a_setting
        with self.assertRaises(TypeError):
            settings.engines.values["ASM_PROFILE"] = "changed"

    def test_to_legacy_dict_returns_an_independent_copy(self):
        settings = ScanSettings(workers=3)
        legacy = settings.to_legacy_dict()
        legacy["workers"] = 20
        self.assertEqual(settings.workers, 3)
        self.assertEqual(ScanSettings().to_legacy_dict()["workers"], 8)

    def test_boolean_tokens_are_explicit_and_case_insensitive(self):
        true_values = ("1", "true", "YES", " on ")
        false_values = ("0", "false", "NO", " off ")
        for value in true_values:
            with self.subTest(value=value):
                self.assertTrue(ScanSettings.from_mapping(
                    {"ASM_ACTIVE_SCAN": value}).active_scan)
        for value in false_values:
            with self.subTest(value=value):
                self.assertFalse(ScanSettings.from_mapping(
                    {"ASM_ACTIVE_SCAN": value}).active_scan)

    def test_zero_count_limits_are_valid_but_workers_must_be_positive(self):
        settings = ScanSettings.from_mapping({
            "max_subdomains": "0", "ASM_MAX_IPS": 0, "max_probes": 0,
            "max_cpes": 0, "max_active_targets": 0, "estate_words": 0,
            "estate_max_hosts": 0, "estate_max_prefixes": 0,
            "estate_prefix_ips": 0, "estate_max_extra_ips": 0,
        })
        self.assertEqual(settings.max_subdomains, 0)
        self.assertEqual(settings.estate_max_extra_ips, 0)
        with self.assertRaisesRegex(SettingsError, "ASM_WORKERS.*не меньше 1"):
            ScanSettings.from_mapping({"ASM_WORKERS": "0"})
        with self.assertRaisesRegex(SettingsError, "ASM_MAX_IPS.*не меньше 0"):
            ScanSettings.from_mapping({"ASM_MAX_IPS": "-1"})

    def test_invalid_values_and_unknown_fields_are_rejected(self):
        invalid = (
            ({"ASM_ACTIVE_SCAN": "maybe"}, "ASM_ACTIVE_SCAN"),
            ({"ASM_ACTIVE_SCAN": ""}, "ASM_ACTIVE_SCAN"),
            ({"ASM_WORKERS": "2.5"}, "ASM_WORKERS"),
            ({"ASM_WORKERS": ""}, "ASM_WORKERS"),
            ({"ASM_MAX_IPS": True}, "ASM_MAX_IPS"),
            ({"unexpected_scan_option": "1"}, "unexpected_scan_option"),
        )
        for values, expected_name in invalid:
            with self.subTest(values=values):
                with self.assertRaises(SettingsError) as caught:
                    ScanSettings.from_mapping(values, source="unit test")
                self.assertIn(expected_name, str(caught.exception))
                self.assertIn("unit test", str(caught.exception))

    def test_alias_collision_in_one_source_is_rejected(self):
        with self.assertRaisesRegex(SettingsError, "задана дважды"):
            ScanSettings.from_mapping({"workers": 2, "ASM_WORKERS": 3})

    def test_settings_are_immutable_and_reject_wrong_direct_types(self):
        settings = Settings()
        with self.assertRaises(FrozenInstanceError):
            settings.scan.workers = 12  # type: ignore[misc]
        with self.assertRaises(SettingsError):
            ScanSettings(workers=True)
        with self.assertRaises(SettingsError):
            Settings(scan={})  # type: ignore[arg-type]

    def test_scan_run_preserves_explicit_false_and_zero_per_scan_overrides(self):
        from asm import scan

        settings = Settings.from_sources(environment={
            "ASM_WORKERS": "2", "ASM_MAX_IPS": "11", "ASM_ACTIVE_SCAN": "1",
        })
        limits = {
            "workers": 3, "max_ips": 0, "active_scan": False,
            "code_path": "fixture", "passive": False,
        }
        with mock.patch.object(scan.store, "scan_mark_pid"), \
                mock.patch.object(scan.store, "scan_clear_pid"), \
                mock.patch.object(scan.store, "scan_log"), \
                mock.patch.object(scan.store, "scan_finish"), \
                mock.patch.object(scan, "_run") as run_scan:
            scan.run(901, limits, settings=settings)

        run_scan.assert_called_once()
        effective = run_scan.call_args.args[1]
        self.assertEqual(effective["workers"], 3)
        self.assertEqual(effective["max_ips"], 0)
        self.assertFalse(effective["active_scan"])
        self.assertEqual(effective["code_path"], "fixture")
        self.assertIs(effective["passive"], False)

    def test_cli_and_web_scan_workers_receive_explicit_settings(self):
        project_root = pathlib.Path(__file__).resolve().parents[1]

        def scanmod_run_callable(node):
            return (isinstance(node, ast.Attribute)
                    and node.attr == "run"
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "scanmod")

        app_tree = ast.parse((project_root / "app.py").read_text(encoding="utf-8"))
        web_tree = ast.parse((project_root / "asm" / "web.py").read_text(encoding="utf-8"))

        for tree, expected_calls in ((app_tree, 1), (web_tree, 2)):
            snapshot_calls = [
                node for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_scan_settings_snapshot"
            ]
            self.assertEqual(len(snapshot_calls), expected_calls)

        for tree in (app_tree, web_tree):
            builder = next(
                node for node in tree.body
                if isinstance(node, ast.FunctionDef)
                and node.name == "_scan_settings_snapshot"
            )
            builder_calls = [node for node in ast.walk(builder)
                             if isinstance(node, ast.Call)]
            self.assertTrue(any(
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "stored_preset"
                for call in builder_calls
            ))
            snapshot_calls = [
                call for call in builder_calls
                if isinstance(call.func, ast.Attribute)
                and call.func.attr == "from_environment_snapshot"
            ]
            self.assertEqual(len(snapshot_calls), 1)
            self.assertIn("mode_values", {kw.arg for kw in snapshot_calls[0].keywords})

        app_calls = [
            node for node in ast.walk(app_tree)
            if isinstance(node, ast.Call) and scanmod_run_callable(node.func)
        ]
        self.assertEqual(len(app_calls), 1)
        self.assertIn("settings", {kw.arg for kw in app_calls[0].keywords})

        thread_calls = [
            node for node in ast.walk(web_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Thread"
        ]
        scan_threads = [
            node for node in thread_calls
            if any(kw.arg == "target" and scanmod_run_callable(kw.value)
                   for kw in node.keywords)
        ]
        self.assertEqual(len(scan_threads), 2)
        for thread in scan_threads:
            kwargs = next(kw.value for kw in thread.keywords if kw.arg == "kwargs")
            self.assertIsInstance(kwargs, ast.Dict)
            names = {key.value for key in kwargs.keys if isinstance(key, ast.Constant)}
            self.assertIn("settings", names)

    def test_legacy_scan_call_reads_environment_at_runtime_and_fails_closed(self):
        from asm import scan

        with mock.patch.dict(os.environ, {"ASM_WORKERS": "3"}, clear=True), \
                mock.patch.object(scan.store, "scan_mark_pid"), \
                mock.patch.object(scan.store, "scan_clear_pid"), \
                mock.patch.object(scan.store, "scan_log"), \
                mock.patch.object(scan.store, "scan_finish"), \
                mock.patch.object(scan, "_run") as run_scan:
            scan.run(902)
        self.assertEqual(run_scan.call_args.args[1]["workers"], 3)

        with mock.patch.dict(os.environ, {"ASM_WORKERS": "0"}, clear=True), \
                mock.patch.object(scan.store, "scan_mark_pid"), \
                mock.patch.object(scan.store, "scan_clear_pid"), \
                mock.patch.object(scan.store, "scan_log") as log_scan, \
                mock.patch.object(scan.store, "scan_finish") as finish_scan, \
                mock.patch.object(scan, "_run") as run_scan:
            scan.run(903)
        run_scan.assert_not_called()
        finish_scan.assert_called_once_with(903, "error", error=mock.ANY)
        self.assertIn("ASM_WORKERS", log_scan.call_args_list[0].args[1])

    def test_cli_captures_explicit_provenance_and_honors_child_scan_snapshot(self):
        project_root = pathlib.Path(__file__).resolve().parents[1]
        code = r'''
import json
import app
settings = app._scan_settings_snapshot()
print(json.dumps({"explicit": app._EXPLICIT_CONFIG_ENVIRONMENT,
                  "workers": settings.scan.workers,
                  "profile": settings.engines.profile}, sort_keys=True))
'''
        with tempfile.TemporaryDirectory(prefix="asm-cli-config-") as tmp:
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("ASM_")}
            env.update({
                "ASM_DB": os.path.join(tmp, "isolated.sqlite"),
                "ASM_WORKERS": "99",
                "_ASM_EXPLICIT_CONFIG_SNAPSHOT": json.dumps({
                    "ASM_WORKERS": "5", "ASM_PROFILE": "operator-profile",
                    "ASM_LLM_KEY": "synthetic-secret-sentinel",
                }),
                "_ASM_SCAN_SETTINGS_SNAPSHOT": json.dumps({
                    "scan": {"workers": 3},
                    "config": {"ASM_PROFILE": "pentest", "ASM_RATE_SPREAD": "0"},
                }),
            })
            prior_path = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (str(project_root) +
                                 (os.pathsep + prior_path if prior_path else ""))
            proc = subprocess.run(
                [sys.executable, "-c", code], cwd=project_root, env=env,
                text=True, capture_output=True, check=False, timeout=30,
            )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(result["explicit"], {
            "ASM_WORKERS": "5", "ASM_PROFILE": "operator-profile",
        })
        self.assertEqual(result["workers"], 3)
        self.assertEqual(result["profile"], "pentest")
        self.assertNotIn("synthetic-secret-sentinel", proc.stdout)

    def test_settings_module_does_not_read_process_environment(self):
        """Зафиксировать запрет на import-time os.environ/os.getenv access."""
        module_path = pathlib.Path(__file__).resolve().parents[1] / "asm" / "settings.py"
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        violations = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute) and node.attr == "environ"
                    and isinstance(node.value, ast.Name) and node.value.id == "os"):
                violations.append("os.environ")
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "getenv"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"):
                violations.append("os.getenv")
        self.assertEqual(violations, [])
        self.assertEqual(asdict(Settings().scan), asdict(ScanSettings()))


class TestModePresetMappings(unittest.TestCase):
    def test_preset_values_are_copy_returning_and_side_effect_free(self):
        from asm import mode

        before = dict(os.environ)
        values = mode.preset_values("БОЕВОЙ")
        self.assertEqual(values, mode.PRESETS["combat"])
        self.assertIsNot(values, mode.PRESETS["combat"])
        values["ASM_PROFILE"] = "changed-only-in-copy"
        self.assertEqual(mode.PRESETS["combat"]["ASM_PROFILE"], "pentest")
        self.assertEqual(mode.preset_values("unknown"), {})
        self.assertEqual(dict(os.environ), before)

    def test_stored_preset_returns_mapping_without_mutating_environment(self):
        from asm import mode

        class StoreStub:
            def kv_get(self, key):
                self.key = key
                return "safe"

        stub = StoreStub()
        before = dict(os.environ)
        name, values = mode.stored_preset(stub)
        self.assertEqual(name, "safe")
        self.assertEqual(stub.key, mode.KV_KEY)
        self.assertEqual(values, mode.PRESETS["safe"])
        self.assertEqual(dict(os.environ), before)

    def test_web_snapshot_keeps_pre_adapter_explicit_values(self):
        from asm import web

        explicit = web._explicit_config_snapshot({
            "ASM_WORKERS": "2",
            "ASM_PROFILE": "operator-profile",
            "ASM_LLM_KEY": "synthetic-secret-sentinel",
        })
        mode_values = {
            "ASM_WORKERS": "6",
            "ASM_ACTIVE_SCAN": "1",
            "ASM_PROFILE": "pentest",
        }
        with mock.patch.object(web.modemod, "stored_preset",
                               return_value=("combat", mode_values)):
            settings = web._scan_settings_snapshot(explicit)

        self.assertEqual(settings.scan.workers, 2)
        self.assertNotIn("ASM_LLM_KEY", explicit)
        self.assertEqual(explicit["ASM_PROFILE"], "operator-profile")

    def test_web_snapshot_builder_uses_saved_mode_without_environment_mutation(self):
        from asm import mode, web

        preset = mode.preset_values("combat")
        preset["ASM_WORKERS"] = "6"
        with mock.patch.object(web.modemod, "stored_preset",
                               return_value=("combat", preset)) as stored, \
                mock.patch.dict(os.environ, {
                    "ASM_WORKERS": "4", "ASM_ACTIVE_SCAN": "0",
                }, clear=True):
            before = dict(os.environ)
            settings = web._scan_settings_snapshot()
            self.assertEqual(dict(os.environ), before)

        stored.assert_called_once_with(web.store)
        self.assertEqual(settings.scan.workers, 4)
        self.assertFalse(settings.scan.active_scan)
        self.assertFalse(settings.scan.deep_paths)

    def test_web_builder_resolves_the_saved_mode_for_each_new_snapshot(self):
        from asm import web

        preset_changes = [
            ("safe", {"ASM_WORKERS": "3"}),
            ("combat", {"ASM_WORKERS": "5"}),
        ]
        with mock.patch.object(web.modemod, "stored_preset",
                               side_effect=preset_changes) as stored, \
                mock.patch.dict(os.environ, {}, clear=True):
            first = web._scan_settings_snapshot()
            second = web._scan_settings_snapshot()

        self.assertEqual(first.scan.workers, 3)
        self.assertEqual(second.scan.workers, 5)
        self.assertEqual(stored.call_count, 2)


class TestSettingsConsumers(unittest.TestCase):
    """New operations read the immutable snapshot; secret paths stay legacy."""

    def test_auto_learn_reads_the_operation_snapshot(self):
        from asm import knowledge, store
        from asm.settings import use_settings

        with mock.patch.object(knowledge, "refinement_from_finding") as learn:
            with use_settings(Settings.from_sources(environment={"ASM_AUTO_LEARN": "0"})):
                store._learn_false_positive(1)
            learn.assert_not_called()

            with use_settings(Settings.from_sources(environment={"ASM_AUTO_LEARN": "1"})):
                store._learn_false_positive(2, note="fixture", operator="tester")
            learn.assert_called_once_with(2, note="fixture", operator="tester")

    def test_model_commands_and_engine_rate_use_the_same_snapshot(self):
        from asm import aiagent, engines, modelcmd
        from asm.settings import use_settings

        with mock.patch.object(aiagent, "config", return_value={"base": "fixture"}):
            with use_settings(Settings.from_sources(environment={"ASM_MODEL_CMDS": "off"})):
                self.assertFalse(modelcmd.enabled())
            with use_settings(Settings.from_sources(environment={"ASM_MODEL_CMDS": "on"})):
                self.assertTrue(modelcmd.enabled())

        settings = Settings.from_sources(environment={
            "ASM_PROFILE": "safe", "ASM_NAABU_RATE": "17", "ASM_RATE_SPREAD": "0",
        })
        with use_settings(settings):
            self.assertEqual(engines.rate_for("naabu"), 17)

    def test_stealth_and_vector_settings_are_operation_scoped(self):
        from asm import engines, stealth, vector
        from asm.settings import use_settings

        with mock.patch.object(stealth, "has_proxy", return_value=False), \
                mock.patch.object(stealth, "cover_state",
                                  return_value={"mode": "off", "raised": False}):
            with use_settings(Settings.from_sources(environment={"ASM_STEALTH": "require"})):
                self.assertFalse(stealth.outward_allowed()[0])
            with use_settings(Settings.from_sources(environment={"ASM_STEALTH": "warn"})):
                self.assertTrue(stealth.outward_allowed()[0])
        jitter_settings = Settings.from_sources(environment={"ASM_STEALTH_JITTER": "0.75"})
        with use_settings(jitter_settings):
            self.assertAlmostEqual(stealth.jitter(1.0, 0.0), 1.75)
        self.assertAlmostEqual(stealth.jitter(1.0, 0.0, settings=jitter_settings), 1.75)
        with mock.patch.dict(os.environ, {
                "ASM_STEALTH_JITTER": "0.25",
        }):
            self.assertAlmostEqual(stealth.jitter(1.0, 0.0), 1.25)
        with mock.patch.dict(os.environ, {
                "ASM_STEALTH": "off", "ASM_STEALTH_PATCH_ENGINES": "0",
        }):
            self.assertNotIn("ASM_UA", stealth.subprocess_env({}))
            self.assertFalse(stealth.status()["engine_ua_patched"])

        with use_settings(Settings.from_sources(environment={
                "ASM_VECTOR_DIM": "13", "ASM_EMBED": "off"})):
            self.assertEqual(len(vector._hashed_vector("settings snapshot")), 13)
        with mock.patch.dict(os.environ, {
                "ASM_PROFILE": "safe", "ASM_NAABU_RATE": "21",
                "ASM_RATE_SPREAD": "0", "ASM_VECTOR_DIM": "17", "ASM_EMBED": "off",
        }):
            self.assertEqual(engines.rate_for("naabu"), 21)
            self.assertEqual(len(vector._hashed_vector("legacy environment")), 17)

    def test_runtime_paths_use_snapshot_and_keep_legacy_environment_fallback(self):
        from asm import chat, drafts, knowledge
        from asm.settings import use_settings

        with mock.patch.dict(os.environ, {"ASM_DRAFT_DIR": "/legacy/drafts"}):
            self.assertEqual(drafts._draft_dir(), "/legacy/drafts")

        with use_settings(Settings.from_sources(environment={
                "ASM_DRAFT_DIR": "/snapshot/drafts",
                "ASM_KB_DIR": "/snapshot/kb",
                "ASM_MATERIALS": "/snapshot/materials",
        })):
            self.assertEqual(drafts._draft_dir(), "/snapshot/drafts")
            self.assertEqual(knowledge._playbooks_dir(), os.path.join("/snapshot/kb", "playbooks"))
            self.assertEqual(chat._materials_dir(), "/snapshot/materials")

    def test_mode_summary_reports_snapshot_values_not_import_time_environment(self):
        from asm import mode
        from asm.settings import use_settings

        settings = Settings.from_environment_snapshot(
            {}, mode_values=mode.preset_values("combat"),
        )
        with mock.patch.object(mode.store, "kv_get", return_value="combat"), \
                use_settings(settings):
            summary = mode.current()
        self.assertEqual(summary["mode"], "combat")
        self.assertEqual(summary["env"]["ASM_PROFILE"], "pentest")
        self.assertEqual(summary["env"]["ASM_STEALTH"], "warn")


if __name__ == "__main__":
    unittest.main()
