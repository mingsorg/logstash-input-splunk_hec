"""Offline regression checks; no Docker commands, containers or live credentials."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import lab
import validate


class LabToolsTest(unittest.TestCase):
    def test_report_paths_cannot_overwrite_credentials_or_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(lab, 'LAB', Path(directory)):
            root = Path(directory)
            secret = root / 'connection.json'
            secret.write_text('{"password":"private"}')
            with self.assertRaises(ValueError):
                lab.save_report(secret, {'mode': 'read-only existing-lab verification'})
            reports = root / 'reports'
            reports.mkdir()
            link = reports / 'link.json'
            link.symlink_to(secret)
            with self.assertRaises(ValueError):
                lab.save_report(link, {})
            unrelated = reports / 'unrelated.json'
            unrelated.write_text('{"password":"also private"}')
            with self.assertRaises(ValueError):
                lab.save_report(unrelated, {})
            self.assertEqual('{"password":"private"}', secret.read_text())
            self.assertEqual('{"password":"also private"}', unrelated.read_text())

    def test_reports_are_private_and_only_replace_recognized_previous_reports(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(lab, 'LAB', Path(directory)):
            path = Path(directory) / 'reports/validation.json'
            report = {'mode': 'read-only existing-lab verification', 'status': 'fail'}
            lab.save_report(path, report)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)
            report['status'] = 'pass'
            lab.save_report(path, report)
            self.assertEqual('pass', json.loads(path.read_text())['status'])

    def test_reverse_trace_scan_handles_large_utf8_lines_and_partial_final_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace.ndjson'
            large = ('重复' * 200000).encode()
            path.write_bytes(b'first\n' + large + b'\nlast\n{"partial":')
            self.assertEqual([b'last', large, b'first'], list(lab.reverse_lines(path)))
            self.assertEqual([b'last'], list(lab.reverse_lines(path, max_bytes=64)))
            path.write_bytes(b'{"incomplete":')
            self.assertEqual([], list(lab.reverse_lines(path)))

    def test_both_application_sources_must_be_fresh_and_have_expected_sourcetypes(self):
        def row(index, source, sourcetype, age=1):
            return {'index': index, 'source': source, 'sourcetype': sourcetype,
                    'count': '1', 'age_seconds': str(age)}
        rows = [row('_internal', 'splunkd.log', 'splunkd'), row('_audit', 'audit.log', 'audittrail', 99999),
                row('hec_demo', '/tmp/hec-chain.log', 'hec_chain_text'),
                row('hec_demo', '/tmp/hec-chain.json', 'hec_chain_json')]
        self.assertTrue(validate.complete_evidence(rows, 900))
        self.assertFalse(validate.complete_evidence(rows[:-1], 900))
        for key, value in (('age_seconds', '901'), ('sourcetype', 'wrong'), ('age_seconds', 'NaN')):
            changed = [dict(item) for item in rows]
            changed[-1][key] = value
            self.assertFalse(validate.complete_evidence(changed, 900))

    def test_total_deadline_kills_a_blocked_worker_and_saves_failure(self):
        real_popen = subprocess.Popen
        children = []
        def blocked_worker(arguments, **kwargs):
            child = real_popen([sys.executable, '-c', 'import time; time.sleep(10)'], **kwargs)
            children.append(child)
            return child
        with tempfile.TemporaryDirectory() as directory, patch.object(lab, 'LAB', Path(directory)):
            output = Path(directory) / 'reports/timeout.json'
            args = argparse.Namespace(timeout=.1, max_age=900, output=str(output))
            before = time.monotonic()
            with patch.object(validate, 'options', return_value=args), \
                    patch.object(validate.subprocess, 'Popen', side_effect=blocked_worker), \
                    patch.dict(os.environ, {'_TEST_LAB_VALIDATE_WORKER': ''}):
                self.assertEqual(1, validate.main())
            self.assertLess(time.monotonic() - before, 3)
            self.assertIsNotNone(children[0].poll())
            self.assertEqual('TimeoutError', json.loads(output.read_text())['error_type'])

    def test_bootstrap_secret_writer_sets_private_mode_even_for_existing_files(self):
        path = Path(__file__).parent / 'bootstrap/splunk_bootstrap.py'
        spec = importlib.util.spec_from_file_location('lab_splunk_bootstrap', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / 'seed.conf'
            secret.write_text('old')
            secret.chmod(0o644)
            module.private_write(secret, 'new private value')
            self.assertEqual(0o600, secret.stat().st_mode & 0o777)
            self.assertEqual('new private value', secret.read_text())


if __name__ == '__main__':
    unittest.main()
