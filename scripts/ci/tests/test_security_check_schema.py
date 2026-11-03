"""Validate the bundled security-check wire contract with a real JSON Schema engine."""

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
import yaml


ROOT = Path(__file__).resolve().parents[3]


def failure_envelope():
    return {
        "version": "2",
        "command": "pybun audit check-updates",
        "status": "error",
        "duration_ms": 0,
        "detail": {
            "contract_version": "2",
            "operation": "security_check",
            "assessment_version": 1,
            "status": "error",
            "exit_code": 3,
            "assessment_id": None,
            "observation_id": None,
            "profile_id": None,
            "policy_digest": None,
            "assessment": None,
            "threshold_matches": [],
            "threshold_match_count": 0,
            "diagnostics": [{"code": "E_SECURITY_AUTHORITY", "message": "Unavailable."}],
        },
        "events": [],
        "diagnostics": [],
    }


class SecurityCheckSchemaTests(unittest.TestCase):
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
        value = json.loads((ROOT / "tests/fixtures/security_check_v2.json").read_text())
        self.assert_valid(value)
        return value

    def test_operational_failure_uses_the_new_branch(self):
        self.assert_valid(failure_envelope())

    def test_existing_backend_errors_remain_valid(self):
        value = failure_envelope()
        value["command"] = "pybun lock"
        value["detail"] = {"contract_version": "2", "error": "Failed.", "code": "E_BACKEND_FAILED"}
        self.assert_valid(value)

    def test_canonical_empty_assessment_envelope_is_valid(self):
        value = self.golden()
        self.assertEqual(value["version"], "2")
        self.assertEqual(value["detail"]["assessment_version"], 1)
        self.assertEqual(value["detail"]["assessment"]["inventory"]["packages"], [])

    def test_required_tag_profile_and_marker_environment(self):
        value = self.golden()
        target = value["detail"]["assessment"]["inventory"]["target"]
        for field in ("tag_profile", "marker_environment"):
            with self.subTest(field=field):
                invalid = copy.deepcopy(value)
                del invalid["detail"]["assessment"]["inventory"]["target"][field]
                self.assert_invalid(invalid)
        for field in target["tag_profile"]:
            with self.subTest(tag_field=field):
                invalid = copy.deepcopy(value)
                del invalid["detail"]["assessment"]["inventory"]["target"]["tag_profile"][field]
                self.assert_invalid(invalid)
        invalid = copy.deepcopy(value)
        invalid["detail"]["assessment"]["inventory"]["target"]["tag_profile"]["tags"] = []
        self.assert_invalid(invalid)
        for field in target["marker_environment"]:
            with self.subTest(marker_field=field):
                invalid = copy.deepcopy(value)
                del invalid["detail"]["assessment"]["inventory"]["target"]["marker_environment"][field]
                self.assert_invalid(invalid)

    def test_all_four_coverage_units_are_mandatory_and_distinct(self):
        value = self.golden()
        units = ("inventory_instances", "advisory_records", "finding_clusters", "candidate_checks")
        for location in ("evidence_coverage", "inventory"):
            for unit in units:
                with self.subTest(location=location, unit=unit):
                    invalid = copy.deepcopy(value)
                    coverage = invalid["detail"]["assessment"][location]
                    if location == "inventory":
                        coverage = coverage["coverage"]
                    del coverage[unit]
                    self.assert_invalid(invalid)
        invalid = copy.deepcopy(value)
        invalid["detail"]["assessment"]["evidence_coverage"] = {"complete": 0}
        self.assert_invalid(invalid)

    def test_unknown_versions_statuses_and_fields_are_rejected(self):
        for field, bad in (("contract_version", "1"), ("assessment_version", 2),
                           ("operation", "apply_updates"), ("status", "safe"),
                           ("exit_code", 4), ("next_action", {"tool": "pip_install"})):
            with self.subTest(field=field):
                invalid = self.golden()
                invalid["detail"][field] = bad
                self.assert_invalid(invalid)
        invalid = self.golden()
        invalid["detail"]["assessment"]["assessment_version"] = 2
        self.assert_invalid(invalid)

    def test_backend_error_escape_cannot_bypass_security_validation(self):
        invalid = self.golden()
        del invalid["detail"]["assessment"]["inventory"]["target"]["tag_profile"]
        invalid["detail"].update(error="not a backend result", code="E_FAKE")
        self.assert_invalid(invalid)

    def test_security_command_cannot_fall_back_to_a_backend_error(self):
        invalid = self.golden()
        del invalid["detail"]["operation"]
        invalid["detail"].update(error="not a backend result", code="E_FAKE")
        self.assert_invalid(invalid)
        # The command owns its contract even if all detail discriminators are lost.
        invalid["detail"] = {"contract_version": "2", "error": "Failed.", "code": "E_FAKE"}
        self.assert_invalid(invalid)

    def test_security_envelope_cannot_advertise_unsafe_remediation(self):
        for field, action in (("next_action", {"tool": "pip_install", "args": {}}),
                              ("fix_candidates", [{"command": "pybun upgrade", "description": "Fix",
                                                   "risk": "low", "auto_applicable": True}])):
            with self.subTest(field=field):
                invalid = self.golden()
                invalid["diagnostics"] = [{"level": "warning", "message": "Unverified remedy.",
                                           field: action}]
                self.assert_invalid(invalid)

    def test_candidate_evidence_cannot_claim_resolution_or_verification(self):
        # A wire-shape example only; acceptance of JSON does not qualify a remedy.
        qualification = {
            "freshness": {"kind": "fresh", "age_seconds": 0},
            "authoritative": False, "current_authoritative": False,
            "version": "2.0", "current_affected": "unknown", "affected": "unknown",
            "fix_evidence": "unavailable", "candidate_kind": None, "availability": "unknown",
            "fixed_boundaries": [], "published_remediation_basis": [], "providers": [],
            "coverage": self.golden()["detail"]["assessment"]["coverage"],
            "resolution_status": "not_checked", "verification_status": "not_run",
        }
        validator = Draft202012Validator({"$ref": "#/$defs/CandidateQualification",
                                         "$defs": self.schema["$defs"]})
        self.assertFalse(list(validator.iter_errors(qualification)))
        for field, value in (("resolution_status", "verified"), ("verification_status", "passed"),
                             ("candidate_kind", "verified_security_update"),
                             ("next_action", {"tool": "pip_install"})):
            with self.subTest(field=field):
                invalid = copy.deepcopy(qualification)
                invalid[field] = value
                self.assertTrue(list(validator.iter_errors(invalid)), invalid)

    def test_incomplete_and_omitted_evidence_cannot_claim_a_complete_observation(self):
        invalid = self.golden()
        invalid["detail"]["status"] = "complete"
        invalid["detail"]["exit_code"] = 3
        self.assert_invalid(invalid)
        value = failure_envelope()
        value["detail"]["threshold_match_count"] = 4
        value["detail"]["omitted"] = {
            "inventory_instances": 3, "advisory_records": 2,
            "finding_clusters": 1, "candidate_checks": 5, "threshold_matches": 4,
        }
        self.assert_valid(value)
        for unit in value["detail"]["omitted"]:
            invalid = copy.deepcopy(value)
            del invalid["detail"]["omitted"][unit]
            self.assert_invalid(invalid)

    def test_continuation_has_its_own_schema(self):
        self.assertIn("AssessmentContinuation", self.schema["$defs"])
        self.assertNotEqual(self.schema["$defs"]["AssessmentContinuation"],
                            self.schema["$defs"].get("EventReplayCursor"))
        invalid = self.golden()
        invalid["detail"]["assessment"]["continuation"] = {"monitor_id": "fake"}
        self.assert_invalid(invalid)

    def test_validator_dependency_is_installed_before_workflow_tests(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        steps = workflow["jobs"]["python-tests"]["steps"]
        install = next(i for i, step in enumerate(steps)
                       if "jsonschema==4.25.1" in step.get("run", ""))
        execute = next(i for i, step in enumerate(steps)
                       if "scripts/ci/tests" in step.get("run", ""))
        self.assertLess(install, execute)
        self.assertFalse(steps[execute].get("continue-on-error", False))


if __name__ == "__main__":
    unittest.main()
