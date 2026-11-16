import unittest
from datetime import date, timedelta

from ip_inventory.model import ReservedIp, Snapshot, SnapshotError, parse_date
from ip_inventory.rules import (
    exit_code,
    rule_dangling_assignment,
    rule_idle_unattached,
    rule_unnamed,
    rule_unowned,
    run_all,
)

AS_OF = date(2026, 11, 17)


def rip(days_old=10, attached="ocid1.instance.oc1..i1", name="svc", owner="team"):
    return ReservedIp(
        ocid="ocid1.publicip.oc1..x",
        ip_address="129.80.0.1",
        name=name,
        created_at=AS_OF - timedelta(days=days_old),
        assigned_entity_id=attached,
        tags={"owner": owner} if owner is not None else {},
    )


def snap(ips, known=("ocid1.instance.oc1..i1",)):
    return Snapshot(known_entities=frozenset(known), reserved_ips=tuple(ips))


class TestIp001Dangling(unittest.TestCase):
    def test_fires_on_unknown_entity(self):
        s = snap([rip(attached="ocid1.instance.oc1..gone")])
        out = rule_dangling_assignment(s, AS_OF)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "HIGH")

    def test_quiet_when_entity_known(self):
        self.assertEqual(rule_dangling_assignment(snap([rip()]), AS_OF), [])

    def test_unattached_is_not_dangling(self):
        self.assertEqual(rule_dangling_assignment(snap([rip(attached=None)]), AS_OF), [])


class TestIp002Idle(unittest.TestCase):
    def test_fires_over_30_days_unattached(self):
        s = snap([rip(days_old=45, attached=None)])
        self.assertEqual(len(rule_idle_unattached(s, AS_OF)), 1)

    def test_boundary_30_quiet(self):
        s = snap([rip(days_old=30, attached=None)])
        self.assertEqual(rule_idle_unattached(s, AS_OF), [])

    def test_attached_never_idle(self):
        s = snap([rip(days_old=400)])
        self.assertEqual(rule_idle_unattached(s, AS_OF), [])


class TestIp003Unowned(unittest.TestCase):
    def test_fires_without_owner(self):
        self.assertEqual(len(rule_unowned(snap([rip(owner=None)]), AS_OF)), 1)

    def test_blank_owner_counts(self):
        self.assertEqual(len(rule_unowned(snap([rip(owner=" ")]), AS_OF)), 1)


class TestIp004Unnamed(unittest.TestCase):
    def test_fires_without_name(self):
        self.assertEqual(len(rule_unnamed(snap([rip(name="")]), AS_OF)), 1)

    def test_named_quiet(self):
        self.assertEqual(rule_unnamed(snap([rip()]), AS_OF), [])


class TestAggregation(unittest.TestCase):
    def test_exit_code_2_on_high(self):
        s = snap([rip(attached="ocid1.instance.oc1..gone")])
        self.assertEqual(exit_code(run_all(s, AS_OF)), 2)

    def test_exit_code_1_on_medium_only(self):
        s = snap([rip(days_old=45, attached=None)])
        self.assertEqual(exit_code(run_all(s, AS_OF)), 1)

    def test_exit_code_0_when_clean(self):
        s = snap([rip()])
        self.assertEqual(exit_code(run_all(s, AS_OF)), 0)

    def test_sorted_high_first(self):
        s = snap([rip(days_old=45, attached=None, name="", owner=None),
                  rip(attached="ocid1.instance.oc1..gone")])
        findings = run_all(s, AS_OF)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[-1].severity, "LOW")


class TestParsing(unittest.TestCase):
    def test_parse_date_ok(self):
        self.assertEqual(parse_date("2026-01-02", "t"), date(2026, 1, 2))

    def test_parse_date_bad(self):
        with self.assertRaises(SnapshotError):
            parse_date("02/01/2026", "t")


if __name__ == "__main__":
    unittest.main()
