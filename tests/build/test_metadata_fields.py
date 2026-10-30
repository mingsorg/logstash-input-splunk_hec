"""Failure-path checks for live metadata qualification, without Docker resources."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/interop'))
import metadata_fields
import run as interop_run


class MetadataQualificationTest(unittest.TestCase):
    def receiver(self, directory):
        return {'name': 'owned-receiver', 'directory': Path(directory),
                'port': 8088, 'tcp_port': 9997, 'artifact': {'file': 'test.gem', 'sha256': 'a' * 64}}

    def test_partial_sender_create_uses_unique_label_cleanup_for_both_transports(self):
        for transport in ('http', 'tcp'):
            with self.subTest(transport=transport), tempfile.TemporaryDirectory() as directory:
                row = {'status': 'fail'}
                calls = []
                def docker(*args, **kwargs):
                    calls.append(args)
                    if args[0] == 'create':
                        raise subprocess.TimeoutExpired('create', 120)
                    return 'owned-id' if args[0] == 'ps' else ''
                with patch.object(metadata_fields.runtime, 'docker', side_effect=docker):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        metadata_fields.run_sender('uf', transport, self.receiver(directory), 'localhost', [], 'none', row)
                ownership = row['sender_ownership_label']
                self.assertTrue(ownership.startswith('org.logstash.hec.metadata-run='))
                self.assertIn(('ps', '-aq', '--filter', 'label=' + ownership), calls)
                self.assertIn(('rm', '-f', '-v', 'owned-id'), calls)
                self.assertEqual('TimeoutExpired', row['error']['type'])

    def test_start_failure_removes_exact_created_container(self):
        for transport in ('http', 'tcp'):
            with self.subTest(transport=transport), tempfile.TemporaryDirectory() as directory:
                row = {'status': 'fail'}
                calls = []
                def docker(*args, **kwargs):
                    calls.append(args)
                    if args[0] == 'start':
                        raise subprocess.CalledProcessError(1, args)
                    return 'created-id' if args[0] == 'create' else ''
                with patch.object(metadata_fields.runtime, 'docker', side_effect=docker):
                    with self.assertRaises(subprocess.CalledProcessError):
                        metadata_fields.run_sender('hf', transport, self.receiver(directory), 'localhost', [], 'full', row)
                self.assertIn(('rm', '-f', '-v', 'created-id'), calls)
                self.assertFalse(any(args[0] == 'ps' for args in calls))

    def test_bare_scenario_assertion_has_an_error_and_still_cleans_up(self):
        row = {'status': 'fail'}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(metadata_fields.runtime, 'docker', side_effect=['created-id', '', 'host', '']) as docker, \
                patch.object(metadata_fields.tcp_senders, 'wait_for', side_effect=AssertionError()):
            with self.assertRaises(AssertionError):
                metadata_fields.run_sender('uf', 'tcp', self.receiver(directory), 'localhost', [], 'none', row)
        self.assertEqual({'type': 'AssertionError', 'message': 'AssertionError()'}, row['error'])
        self.assertEqual(('rm', '-f', '-v', 'created-id'), docker.call_args.args)

    def run_main(self, directory, docker, sender):
        root = Path(directory)
        (root / 'tests/interop/evidence').mkdir(parents=True)
        rt = self.receiver(directory)
        with patch.object(metadata_fields.runtime, 'ROOT', root), \
                patch.object(metadata_fields.runtime, 'artifact_info', return_value=rt['artifact']), \
                patch.object(metadata_fields.runtime, 'start_tcp_runtime', return_value=rt), \
                patch.object(metadata_fields, 'sender_network', return_value=([], 'localhost')), \
                patch.object(metadata_fields, 'run_sender', side_effect=sender), \
                patch.object(metadata_fields.tcp_senders, 'receiver_log_warnings', return_value=[]), \
                patch.object(metadata_fields.runtime, 'docker', side_effect=docker):
            result = metadata_fields.main()
        return result, json.loads((root / 'tests/interop/evidence/metadata-fields.json').read_text())

    def test_failed_logs_do_not_prevent_cleanup_or_failure_evidence(self):
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if args[0] == 'logs':
                raise RuntimeError('logs unavailable')
            return ''
        def fail_sender(*args):
            raise AssertionError()
        with tempfile.TemporaryDirectory() as directory:
            result, report = self.run_main(directory, docker, fail_sender)
        self.assertEqual(1, result)
        self.assertEqual('fail', report['status'])
        self.assertEqual('AssertionError', report['error']['type'])
        self.assertEqual('RuntimeError', report['diagnostic_errors'][0]['type'])
        self.assertIn(('rm', '-f', '-v', 'owned-receiver'), calls)
        row = report['runs'][0]
        self.assertEqual(('minimum', 'http', 'uf', 'none', 'persisted'),
                         tuple(row[k] for k in ('runtime_role', 'transport', 'role', 'hec_metadata', 'queue')))
        self.assertEqual(metadata_fields.runtime.P['logstash.minimum.image'], row['receiver_image'])

    def test_receiver_cleanup_failure_cannot_report_pass(self):
        def docker(*args, **kwargs):
            if args[0] == 'rm':
                raise subprocess.CalledProcessError(1, args)
            return ''
        def pass_sender(*args):
            args[-1]['status'] = 'pass'
        with tempfile.TemporaryDirectory() as directory:
            result, report = self.run_main(directory, docker, pass_sender)
        self.assertEqual(1, result)
        self.assertEqual('fail', report['status'])
        self.assertTrue(report['cleanup_errors'])

    def test_sender_cleanup_failure_is_retained(self):
        row = {}
        with patch.object(metadata_fields.runtime, 'docker', side_effect=subprocess.CalledProcessError(1, 'rm')):
            self.assertFalse(metadata_fields.cleanup_sender('created-id', 'unused-label', row))
        self.assertEqual('created-id', row['cleanup_errors'][0]['container'])

    def test_metadata_stage_is_registered_and_included_in_all(self):
        with patch.object(sys, 'argv', ['run.py', '--stage', 'metadata']), patch.object(interop_run, 'run') as run:
            self.assertEqual(0, interop_run.main())
            run.assert_called_once_with('metadata_fields.py')
        with patch.object(sys, 'argv', ['run.py', '--stage', 'all']), \
                patch.object(interop_run, 'run', side_effect=RuntimeError('stop after first stage')) as run:
            with self.assertRaisesRegex(RuntimeError, 'stop after first stage'):
                interop_run.main()
            run.assert_called_once_with('metadata_fields.py')


if __name__ == '__main__':
    unittest.main()
