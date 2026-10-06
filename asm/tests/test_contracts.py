"""Pure tests for typed scan/agent payload contracts and legacy adapters."""
from __future__ import annotations

import unittest

from asm.contracts import (
    Asset, ContractError, Finding, ProbeResult, ScanContext, StageResult,
    StageStatus, Step,
)
from asm.settings import Settings


class TestStageResult(unittest.TestCase):
    def test_all_statuses_are_distinct_and_failed_cannot_look_successful(self):
        self.assertEqual(StageResult.ok({"count": 0}).status, StageStatus.OK)
        partial = StageResult.partial([1], issues=("one source unavailable",))
        self.assertEqual(partial.status, StageStatus.PARTIAL)
        self.assertEqual(partial.value, [1])
        self.assertEqual(StageResult.not_run(reason="disabled").status, StageStatus.NOT_RUN)
        self.assertEqual(StageResult.failed("timeout").status, StageStatus.FAILED)
        with self.assertRaisesRegex(ContractError, "нужна причина"):
            StageResult(StageStatus.FAILED)
        with self.assertRaisesRegex(ContractError, "только для failed"):
            StageResult(StageStatus.OK, error="timeout")


class TestBoundaryModels(unittest.TestCase):
    def test_asset_adapter_preserves_unknown_fields_and_meta(self):
        legacy = {
            "kind": "service", "value": "192.0.2.10:443",
            "meta": {"port": 443, "source": "fixture"}, "extension": [1, 2],
        }
        model = Asset.from_legacy(legacy)
        self.assertEqual(model.kind, "service")
        self.assertEqual(model.value, "192.0.2.10:443")
        self.assertEqual(model.to_legacy(), legacy)
        self.assertNotIn("extension", model.meta)

    def test_finding_adapter_preserves_sparse_and_extended_shapes(self):
        legacy = {
            "asset": "example.test", "title": "Fixture finding", "severity": "high",
            "port": 443, "cvss": 7.5, "evidence": {"matcher": "x"},
            "provider_extension": {"opaque": True},
        }
        model = Finding.from_legacy(legacy)
        self.assertEqual((model.asset, model.title, model.severity),
                         ("example.test", "Fixture finding", "high"))
        self.assertEqual(model.to_legacy(), legacy)
        self.assertEqual(Finding.from_legacy({"kind": "legacy-sparse"}).to_legacy(),
                         {"kind": "legacy-sparse"})

    def test_probe_result_and_step_adapters_keep_legacy_spellings(self):
        probe = {"url": "https://example.test", "status": 200,
                 "tls": {"subject_cn": "example.test"}, "extra": "preserved"}
        step = {"action_id": "read_report", "title": "Read", "status": "proposed",
                "params": {"scan_id": 9}, "opaque": 17}
        self.assertEqual(ProbeResult.from_legacy(probe).to_legacy(), probe)
        step_model = Step.from_legacy(step)
        self.assertEqual(step_model.action, "read_report")
        self.assertEqual(step_model.status, "proposed")
        self.assertEqual(step_model.to_legacy(), step)
        planner_step = Step.from_legacy({"action": "list_targets", "why": "inspect"})
        self.assertEqual(planner_step.action, "list_targets")
        self.assertEqual(planner_step.to_legacy(), {"action": "list_targets", "why": "inspect"})

    def test_invalid_boundary_shapes_fail_without_echoing_payload_values(self):
        bad = {"kind": "asset-fixture-secret", "value": None, "meta": []}
        with self.assertRaisesRegex(ContractError, "asset.value") as caught:
            Asset.from_legacy(bad)
        self.assertNotIn("asset-fixture-secret", str(caught.exception))
        with self.assertRaisesRegex(ContractError, "finding.cvss"):
            Finding.from_legacy({"cvss": "not-a-number-fixture"})
        with self.assertRaisesRegex(ContractError, "step.params"):
            Step.from_legacy({"action": "fixture", "params": []})

    def test_scan_context_owns_independent_mutable_state_and_settings_snapshot(self):
        first = ScanContext(1, {"id": 10}, "example.test", False, Settings())
        second = ScanContext(2, {"id": 11}, "other.test", False, Settings())
        first.assets.append({"kind": "domain", "value": "example.test"})
        first.record_stage("discovery", StageResult.partial([], issues=("source down",)))
        self.assertEqual(second.assets, [])
        self.assertNotIn("discovery", second.stage_results)
        self.assertEqual(first.stage_results["discovery"].status, StageStatus.PARTIAL)


class TestPipelineStageBoundary(unittest.TestCase):
    def setUp(self):
        self.ctx = ScanContext(3, {"id": 30}, "fixture.test", False, Settings())

    def test_skip_reason_keeps_legacy_value_but_marks_stage_not_run(self):
        from asm import scan

        legacy_value = ({"fixture": True}, [])
        returned = scan._run_stage(
            self.ctx, "optional", lambda: legacy_value,
            skip_reason="disabled for this operation",
        )
        self.assertIs(returned, legacy_value)
        self.assertIs(self.ctx.values["optional"], legacy_value)
        result = self.ctx.stage_results["optional"]
        self.assertEqual(result.status, StageStatus.NOT_RUN)
        self.assertEqual(result.issues, ("disabled for this operation",))

    def test_explicit_failed_result_is_not_returned_as_successful_output(self):
        from asm import scan

        with self.assertRaisesRegex(RuntimeError, "stage lookup returned a failed result"):
            scan._run_stage(
                self.ctx, "lookup", lambda: StageResult.failed("fixture failure"),
            )
        self.assertEqual(self.ctx.stage_results["lookup"].status, StageStatus.FAILED)
        self.assertEqual(self.ctx.stage_results["lookup"].error, "fixture failure")
        self.assertIsNone(self.ctx.values["lookup"])


if __name__ == "__main__":
    unittest.main()
