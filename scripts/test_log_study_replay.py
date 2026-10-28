import datetime as dt
import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("log-study-replay.py")
SPEC = importlib.util.spec_from_file_location("log_study_replay", MODULE_PATH)
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)


class ReplayTimestampTests(unittest.TestCase):
    def test_access_retimestamp_keeps_client_prefix_and_fields(self):
        line = '192.0.2.10 - - [26/Oct/2026:00:00:11 +0000] "GET /probe HTTP/1.1" 404 123 "-" "scanner"'
        now = dt.datetime(2026, 10, 27, 21, 30, 0, tzinfo=dt.timezone(dt.timedelta(hours=7)))
        actual = REPLAY.stamp(line, "access", now)
        self.assertTrue(actual.startswith('192.0.2.10 - - [27/Oct/2026:21:30:00 +0700]'))
        self.assertIn('"GET /probe HTTP/1.1" 404 123', actual)

    def test_iso_timestamp_is_parsed_with_offset(self):
        line = "2026-10-24T23:17:57.023593+00:00 host kernel: [UFW BLOCK]"
        actual = REPLAY.parse_time(line, "syslog", 0)
        expected = dt.datetime.fromisoformat("2026-10-24T23:17:57.023593+00:00").timestamp()
        self.assertEqual(actual, expected)

    def test_iso_timestamp_is_rewritten_to_replay_time(self):
        line = "2026-10-24T23:17:57.023593+00:00 host sshd[42]: Failed password"
        now = dt.datetime(2026, 10, 27, 21, 30, 0, tzinfo=dt.timezone(dt.timedelta(hours=7)))
        actual = REPLAY.stamp(line, "syslog", now)
        self.assertTrue(actual.startswith("2026-10-27T21:30:00+07:00"))

    def test_legacy_syslog_timestamp_is_parsed_and_rewritten(self):
        line = "Oct 25 07:00:17 host sshd[42]: Failed password"
        self.assertGreater(REPLAY.parse_time(line, "syslog", 0), 0)
        now = dt.datetime(2026, 10, 27, 21, 30, 0, tzinfo=dt.timezone.utc)
        self.assertTrue(REPLAY.stamp(line, "syslog", now).startswith("Oct 27 21:30:00"))


if __name__ == "__main__":
    unittest.main()
