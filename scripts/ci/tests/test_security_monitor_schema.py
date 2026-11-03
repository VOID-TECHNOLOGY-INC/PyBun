"""Wire-shape checks for explicit monitor actions, persistence, and replay."""

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[3]


def failure_envelope():
    return {
        "version": "2", "command": "pybun audit monitor", "status": "error",
        "duration_ms": 0, "events": [], "diagnostics": [],
        "detail": {
            "contract_version": "2", "operation": "security_monitor", "action": "check",
            "status": "error", "exit_code": 3, "commit_status": "not_committed",
            "newly_committed_events": [], "newly_committed_count": 0,
            "newly_committed_truncated": False, "newly_committed_gap": False,
            "diagnostics": [{"code": "E_MONITOR_UNAVAILABLE", "message": "Unavailable."}],
        },
    }


class SecurityMonitorSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads((ROOT / "schema/schema_v2.json").read_text())
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def assert_valid(self, value):
        errors = list(self.validator.iter_errors(value))
        self.assertFalse(errors, "\n".join(str(error) for error in errors))

    def assert_invalid(self, value):
        self.assertTrue(list(self.validator.iter_errors(value)), value)

    def golden(self):
        value = json.loads((ROOT / "tests/fixtures/security_monitor_v2.json").read_text())
        self.assert_valid(value)
        return value

    def test_operational_failure_uses_monitor_contract(self):
        self.assert_valid(failure_envelope())

    def test_canonical_monitor_wire_fixture(self):
        value = self.golden()
        self.assertEqual(value["version"], "2")
        self.assertEqual(value["detail"]["operation"], "security_monitor")
        self.assertIn("current", value["detail"])
        self.assertIn("replay", value["detail"])

    def test_six_actions_and_fixed_invalid_request_discriminator(self):
        for action in ("add", "list", "check", "events", "configure", "remove"):
            with self.subTest(action=action):
                value = failure_envelope()
                value["detail"]["action"] = action
                self.assert_valid(value)
        value = failure_envelope()
        value["detail"]["action"] = "invalid"
        value["detail"]["exit_code"] = 2
        self.assert_valid(value)
        for field, bad in (("action", "automatic_upgrade"), ("exit_code", 0),
                           ("commit_status", "committed")):
            with self.subTest(field=field):
                invalid = copy.deepcopy(value)
                invalid["detail"][field] = bad
                self.assert_invalid(invalid)

    def test_freshness_ttl_accepts_zero_without_relaxing_integer_bounds(self):
        ttl = self.schema["$defs"]["MonitorConfig"]["properties"]["freshness_ttl_seconds"]
        validator = Draft202012Validator(ttl)
        for value in (0, 1, 86400):
            with self.subTest(valid=value):
                self.assertFalse(list(validator.iter_errors(value)))
        for value in (-1, 0.5, "0", None, False):
            with self.subTest(invalid=value):
                self.assertTrue(list(validator.iter_errors(value)))

    def test_commit_state_is_required_and_orthogonal_to_errors(self):
        for state in ("not_committed", "committed", "indeterminate"):
            value = failure_envelope()
            value["detail"]["commit_status"] = state
            self.assert_valid(value)
        invalid = failure_envelope()
        del invalid["detail"]["commit_status"]
        self.assert_invalid(invalid)
        invalid["detail"]["commit_status"] = "rolled_back"
        self.assert_invalid(invalid)

    def test_command_discriminator_cannot_fall_back_to_backend_result(self):
        invalid = failure_envelope()
        invalid["detail"] = {"contract_version": "2", "error": "Failed.", "code": "E_FAKE"}
        self.assert_invalid(invalid)

    def test_replay_cursor_is_distinct_from_assessment_continuation(self):
        definitions = self.schema["$defs"]
        self.assertIn("AssessmentContinuation", definitions)
        self.assertIn("EventReplayCursor", definitions)
        replay = definitions["ReplayPage"]["properties"]
        self.assertEqual(replay["origin_cursor"]["$ref"], "#/$defs/EventReplayCursor")
        cursor = Draft202012Validator(definitions["EventReplayCursor"])
        self.assertTrue(list(cursor.iter_errors({"monitor_id": "fake", "sequence": 0})))
        self.assertTrue(list(cursor.iter_errors("a" * 2049)))

    def test_replay_requires_summary_watermarks_and_resynchronization_fields(self):
        for field in ("current", "origin_cursor", "resync_cursor", "next_cursor",
                      "low_water_mark", "high_water_mark", "has_more", "events"):
            with self.subTest(field=field):
                invalid = self.golden()
                del invalid["detail"]["replay"][field]
                self.assert_invalid(invalid)

    def test_status_action_and_unsafe_remediation_fields_are_rejected(self):
        for field, bad in (("operation", "auto_update"), ("status", "safe"),
                           ("exit_code", 4), ("next_action", {"tool": "pip_install"})):
            with self.subTest(field=field):
                invalid = failure_envelope()
                invalid["detail"][field] = bad
                self.assert_invalid(invalid)
        invalid = failure_envelope()
        invalid["diagnostics"] = [{"level": "error", "message": "Unverified remedy.",
                                   "next_action": {"tool": "pip_install", "args": {}}}]
        self.assert_invalid(invalid)

    def test_omission_counts_are_explicit_and_never_complete(self):
        value = failure_envelope()
        value["detail"].update(status="partial", omitted={
            "registrations": 0, "current_findings": 2, "newly_committed_events": 1,
            "replay_events": 3, "assessment_details": 1, "threshold_matches": 4,
            "assessment_omissions": None,
        })
        self.assert_valid(value)
        for field in value["detail"]["omitted"]:
            invalid = copy.deepcopy(value)
            del invalid["detail"]["omitted"][field]
            self.assert_invalid(invalid)
        value["detail"].update(status="complete", exit_code=0)
        value["status"] = "ok"
        self.assert_invalid(value)

    def test_staged_bounds_can_omit_duplicate_assessment_without_dropping_findings(self):
        value = failure_envelope()
        value["detail"].update(status="partial", omitted={
            "assessment_details": 1, "threshold_matches": 2, "assessment_omissions": None,
        })
        self.assert_valid(value)
        for field in value["detail"]["omitted"]:
            invalid = copy.deepcopy(value)
            del invalid["detail"]["omitted"][field]
            self.assert_invalid(invalid)

    def test_nested_check_preserves_all_assessment_coverage_units(self):
        # Compose existing wire-shape fixtures; runtime equality is tested separately.
        value = self.golden()
        check = json.loads((ROOT / "tests/fixtures/security_check_v2.json").read_text())["detail"]
        value["detail"]["check"] = check
        self.assert_valid(value)
        for unit in ("inventory_instances", "advisory_records", "finding_clusters", "candidate_checks"):
            with self.subTest(unit=unit):
                invalid = copy.deepcopy(value)
                del invalid["detail"]["check"]["assessment"]["evidence_coverage"][unit]
                self.assert_invalid(invalid)

    def test_persisted_candidate_cannot_advertise_a_verified_update(self):
        candidate = {
            "source_id": "fixture", "auth_scope_id": "public", "version": "2",
            "artifacts": [], "qualified_remediation": False, "publication_available": False,
            "constraint_status": "unknown", "last_confirmed_at": 0,
        }
        validator = Draft202012Validator({"$ref": "#/$defs/MonitorCandidate",
                                         "$defs": self.schema["$defs"]})
        self.assertFalse(list(validator.iter_errors(candidate)))
        for field, bad in (("next_action", {"tool": "pip_install"}),
                           ("resolution_status", "verified"), ("verification_status", "passed")):
            with self.subTest(field=field):
                invalid = dict(candidate, **{field: bad})
                self.assertTrue(list(validator.iter_errors(invalid)))


if __name__ == "__main__":
    unittest.main()
