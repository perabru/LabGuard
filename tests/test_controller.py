import unittest
from unittest.mock import Mock, patch
from tempfile import TemporaryDirectory
from pathlib import Path
from labguard.controller import (ControllerError, ControllerTransport, create_transport,
                                normalize_snapshot, snapshot_capabilities, seed_ai_catalog)
from labguard.banlist import BanlistDatabase


class ControllerTests(unittest.TestCase):
    def test_observation_never_grants_mutations_even_with_untrusted_caps(self):
        snapshot={"mode":"observation","capabilities":{"inventory":True,"address_blocking":True}}
        raw=Mock();raw.request.return_value=snapshot
        wrapper=ControllerTransport("observation",raw)
        self.assertFalse(wrapper.request("snapshot")["capabilities"]["address_blocking"])
        with self.assertRaises(ControllerError):wrapper.request("set_address_block",kind="ip",address="192.168.1.4",blocked=True)
        self.assertTrue(all(call.args[0]=="snapshot" for call in raw.request.call_args_list))

    def test_equipment_capability_and_health_are_both_required(self):
        raw=Mock();raw.request.return_value={"mode":"equipment","capabilities":{"address_blocking":True},"health":{"firewall":True,"forwarding":False}}
        wrapper=ControllerTransport("routeros",raw)
        with self.assertRaises(ControllerError):wrapper.request("set_address_block",kind="ip",address="192.168.1.4",blocked=True)
        self.assertTrue(all(call.args[0]=="snapshot" for call in raw.request.call_args_list))
        raw.request.return_value["health"]["forwarding"]=True
        wrapper.request("set_address_block",kind="ip",address="192.168.1.4",blocked=True)
        self.assertEqual(raw.request.call_args.args,("set_address_block",))

    def test_mode_switch_cannot_grant_observation_transport_write_access(self):
        raw=Mock();raw.request.return_value={"mode":"gateway","health":{"firewall":True,"forwarding":True}}
        wrapper=ControllerTransport("observation",raw)
        with self.assertRaises(ControllerError):wrapper.request("set_address_block",kind="ip",address="192.168.1.4",blocked=True)
        raw.request.assert_called_once_with("snapshot")

    def test_closing_invalidates_session_and_closes_underlying_transport(self):
        raw=Mock();wrapper=ControllerTransport("routeros",raw)
        wrapper.close();wrapper.close();raw.close.assert_called_once()
        with self.assertRaises(ControllerError):wrapper.request("snapshot")

    def test_demo_is_explicit_and_legacy_caps_remain_compatible(self):
        wrapper=create_transport("demo")
        snapshot=wrapper.request("snapshot")
        self.assertEqual(snapshot["mode"],"demo")
        self.assertTrue(snapshot["capabilities"]["domain_filtering"])
        self.assertTrue(snapshot_capabilities({"mode":"gateway"})["address_blocking"])

    def test_unknown_adapter_and_invalid_snapshots_refuse(self):
        with self.assertRaises(ControllerError):create_transport("vivo-universal")
        with self.assertRaises(ControllerError):normalize_snapshot({"mode":"equipment","devices":None})
        self.assertFalse(snapshot_capabilities({"mode":"equipment","capabilities":{"domain_filtering":"true"}})["domain_filtering"])

    def test_ai_catalog_only_populates_local_database(self):
        with TemporaryDirectory() as temporary:
            db=BanlistDatabase(Path(temporary)/"data"/"banlist.sqlite3")
            result=seed_ai_catalog(db)
            self.assertEqual(len(result["added"]),23)
            self.assertEqual(db.summary()["pending"],23)
            self.assertEqual(db.summary()["owned_rules"],0)
            self.assertEqual(db.list_sites()[0]["category"],"Inteligência artificial")


if __name__=="__main__":unittest.main()
