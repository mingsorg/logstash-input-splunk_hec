"""Build-cache and fixture failure paths, without creating Docker resources."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/interop'))
import senders
import start_oracle
import splunk_bootstrap

spec=importlib.util.spec_from_file_location('hec_bootstrap',ROOT/'scripts/bootstrap.py')
bootstrap=importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class HelpersTest(unittest.TestCase):
    def test_event_reader_waits_for_complete_lines_without_masking_bad_complete_events(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'events.ndjson'
            path.write_bytes(b'{"event":"complete"}\n'+b'{"event":"\xe9\x87')
            self.assertEqual([{'event':'complete'}],senders.runtime.read_events(path))
            path.write_bytes('{"event":"complete"}\n{"event":"重复"}\n'.encode())
            self.assertEqual(2,len(senders.runtime.read_events(path)))
            path.write_bytes(b'invalid complete line\n')
            with self.assertRaises(ValueError):senders.runtime.read_events(path)

    def test_native_pid_reader_accepts_worker_lines_and_waits_for_restart_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory);pid=home/'var/run/splunk/splunkd.pid'
            pid.parent.mkdir(parents=True)
            pid.write_text('987654321\n987654322\n')
            with patch.object(splunk_bootstrap.os,'kill'):
                self.assertEqual(987654321,splunk_bootstrap.daemon_pid(home))
            pid.write_text('987654321restarting\n')
            with patch.object(splunk_bootstrap.os,'kill') as inspect:
                self.assertIsNone(splunk_bootstrap.daemon_pid(home));inspect.assert_not_called()
            pid.write_text('987654321\n')
            with patch.object(splunk_bootstrap.os,'kill',side_effect=ProcessLookupError):
                self.assertIsNone(splunk_bootstrap.daemon_pid(home))

    def test_native_bootstrap_refuses_unowned_host_execution(self):
        with patch.dict(splunk_bootstrap.os.environ,{'HEC_FIXTURE_OWNED':''}),\
            patch.object(splunk_bootstrap.subprocess,'run') as execute:
            with self.assertRaisesRegex(RuntimeError,'owned Docker fixture'):
                splunk_bootstrap.start('/opt/splunk','fixture-password')
            execute.assert_not_called()

    def test_direct_sender_ready_requires_native_marker_not_stock_health(self):
        state='{"Running":true,"Health":{"Status":"healthy"}}'
        absent=subprocess.CompletedProcess([],1)
        present=subprocess.CompletedProcess([],0)
        with patch.dict(senders.os.environ,{'HEC_STARTUP_MODE':'direct'}),\
            patch.object(senders.runtime,'docker',return_value=state),\
            patch.object(senders.subprocess,'run',side_effect=[absent,absent,present]) as probe,\
            patch.object(senders.time,'sleep'):
            senders.sender_ready('owned-fixture',timeout=5)
            self.assertEqual(3,probe.call_count)

    def test_native_sender_bootstrap_disables_racy_root_healthcheck(self):
        with patch.dict(senders.os.environ,{'HEC_STARTUP_MODE':'direct'}):
            self.assertIn('--no-healthcheck',senders.sender_bootstrap_args('owned-fixture'))
        with patch.dict(senders.os.environ,{'HEC_STARTUP_MODE':'official'}):
            self.assertNotIn('--no-healthcheck',senders.sender_bootstrap_args('owned-fixture'))

    def test_cache_tracks_image_and_keeps_last_complete_api_after_failed_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            cache=Path(directory)
            def extract(image,destination):
                destination.mkdir();(destination/'logstash-core.jar').write_text(image)
            with patch.object(bootstrap,'extract_api',side_effect=extract) as extraction:
                bootstrap.ensure_api('image@first',cache)
                bootstrap.ensure_api('image@first',cache)
                self.assertEqual(1,extraction.call_count)
                bootstrap.ensure_api('image@second',cache)
                self.assertEqual(2,extraction.call_count)
            with patch.object(bootstrap,'extract_api',side_effect=OSError('copy failed')):
                with self.assertRaises(OSError):bootstrap.ensure_api('image@third',cache)
            self.assertEqual('image@second',(cache/'logstash-jars/logstash-core.jar').read_text())
            self.assertEqual('image@second',(cache/'logstash-jars/.source-image').read_text())

    def test_gradle_execution_uses_the_version_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            cache=Path(directory);executable=cache/'gradle-selected/bin/gradle'
            executable.parent.mkdir(parents=True);executable.touch()
            with patch.object(bootstrap,'CACHE',cache),patch.dict(bootstrap.P,{'gradle.version':'selected'}),\
                patch.object(bootstrap,'ensure_api'),patch.object(bootstrap.os,'execv') as execute,\
                patch.object(sys,'argv',['bootstrap.py','--run-gradle','--version']):
                bootstrap.main()
            self.assertEqual(str(executable),execute.call_args.args[0])
            self.assertEqual('--version',execute.call_args.args[1][-1])

    def test_sender_network_resolves_native_linux_and_desktop_without_dns_assumptions(self):
        with patch.dict(senders.os.environ,{'HEC_SENDER_NETWORK':'auto'}):
            with patch.object(senders.runtime,'docker',return_value='Docker Desktop'):
                self.assertEqual(([],'host.docker.internal'),senders.sender_network())
            with patch.object(senders.runtime,'docker',return_value='Ubuntu Linux'):
                self.assertEqual((['--network','host'],'localhost'),senders.sender_network())
        with patch.dict(senders.os.environ,{'HEC_SENDER_NETWORK':'bridge'}),patch.object(senders.runtime,'docker') as docker:
            self.assertEqual(([],'host.docker.internal'),senders.sender_network());docker.assert_not_called()

    def test_failed_oracle_start_removes_only_its_created_container_id(self):
        identity='a'*64;calls=[]
        def run(arguments,**kwargs):
            calls.append(arguments)
            if arguments[1]=='start':raise subprocess.CalledProcessError(1,arguments)
            return subprocess.CompletedProcess(arguments,0,stdout='')
        with patch.object(start_oracle.subprocess,'check_output',return_value=identity),\
            patch.object(start_oracle.subprocess,'run',side_effect=run):
            with self.assertRaises(subprocess.CalledProcessError):start_oracle.create_oracle()
        self.assertIn(['docker','rm','-f','-v',identity],calls)
        self.assertNotIn(['docker','rm','-f','-v','hec-spec-oracle'],calls)

    def test_create_timeout_finds_only_the_unique_ownership_label(self):
        identity='b'*64;calls=[]
        def run(arguments,**kwargs):
            calls.append(arguments)
            return subprocess.CompletedProcess(arguments,0,stdout=identity+'\n' if arguments[1]=='ps' else '')
        with patch.object(start_oracle.subprocess,'check_output',side_effect=subprocess.TimeoutExpired('create',120)),\
            patch.object(start_oracle.subprocess,'run',side_effect=run):
            with self.assertRaises(subprocess.TimeoutExpired):start_oracle.create_oracle()
        query=next(arguments for arguments in calls if arguments[1]=='ps')
        self.assertTrue(query[-1].startswith('label=org.logstash.hec.oracle-run='))
        self.assertIn(['docker','rm','-f','-v',identity],calls)

    def relay_handler(self,directory):
        handlers=[]
        def unavailable(address,handler):handlers.append(handler);raise OSError('port in use')
        with patch.object(senders,'CAPTURES',Path(directory)/'captures'),\
            patch.object(senders,'sender_network',return_value=([],'host.docker.internal')),\
            patch.object(senders.runtime,'run',return_value=({},'owned-runtime',Path(directory),12345,None)),\
            patch.object(senders,'ThreadingHTTPServer',side_effect=unavailable),\
            patch.object(senders.subprocess,'run') as cleanup:
            with self.assertRaises(OSError):senders.main()
            self.assertEqual(['docker','rm','-f','-v','owned-runtime'],cleanup.call_args.args[0])
        return handlers[0]

    def test_relay_bind_failure_cleans_up_the_retained_runtime(self):
        with tempfile.TemporaryDirectory() as directory:self.relay_handler(directory)

    def test_relay_rejects_negative_and_stalled_lengths_without_an_unbounded_read(self):
        with tempfile.TemporaryDirectory() as directory:
            handler=self.relay_handler(directory)
            for length,status in [('-1',400),('invalid',400),(str(11<<20),413)]:
                request=object.__new__(handler);request.headers={'Content-Length':length}
                request.connection=Mock();request.rfile=Mock();request.send_error=Mock()
                request.do_POST();request.send_error.assert_called_once_with(status);request.rfile.read.assert_not_called()
            request=object.__new__(handler);request.headers={'Content-Length':'5'}
            request.connection=Mock();request.rfile=Mock();request.rfile.read.side_effect=TimeoutError()
            request.send_error=Mock();request.do_POST();request.send_error.assert_called_once_with(408)


class ConfigurationDocumentTest(unittest.TestCase):
    """The configuration reference must not drift from the plugin schema."""
    def test_every_configuration_option_and_policy_key_is_documented(self):
        import re
        source=(ROOT/'src/main/java/org/logstashplugins/hec/SplunkHec.java').read_text()
        options=set(re.findall(r'PluginConfigSpec\.\w+Setting\("([a-z0-9_]+)"',source))
        options|=set(re.findall(r'Map\.entry\("([a-z0-9_]+)",',source))
        self.assertGreaterEqual(len(options),30,options)
        document=(ROOT/'docs/configuration.md').read_text()
        missing=sorted(name for name in options if '`'+name+'`' not in document)
        self.assertEqual([],missing,'options missing from docs/configuration.md')
        tokens=(ROOT/'src/main/java/org/logstashplugins/hec/TokenStore.java').read_text()
        keys=set(re.findall(r'"([A-Za-z]+)"',re.search(r'GLOBAL = Set.of\((.*?)\);',tokens,re.S).group(1)))|{'token','indexes'}
        undocumented=sorted(key for key in keys if '`'+key+'`' not in document)
        self.assertEqual([],undocumented,'policy keys missing from docs/configuration.md')
        for standard in ('id','enable_metric','add_field','tags','type'):
            self.assertIn('`'+standard+'`',document)

    def test_every_option_documented_has_a_default_row_that_matches_the_source(self):
        import re
        source=(ROOT/'src/main/java/org/logstashplugins/hec/SplunkHec.java').read_text()
        document=(ROOT/'docs/configuration.md').read_text()
        for name,default in re.findall(r'PluginConfigSpec\.(?:string|num|boolean)Setting\("([a-z0-9_]+)",("[^"]*"|\w+)\)',source):
            row=next((line for line in document.splitlines() if line.startswith('| `'+name+'`')),None)
            self.assertIsNotNone(row,name)
            expected=default.strip('"')
            if expected and expected!='0':self.assertTrue(expected in row or expected in row.replace(',',''),name+' default '+expected+' not in '+row)


if __name__=='__main__':unittest.main()
