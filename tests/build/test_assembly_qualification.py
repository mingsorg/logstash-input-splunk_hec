"""Regression checks for qualification assertions and finite capture ownership."""
import copy
import io
import socket
import socketserver
import ssl
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/interop'))
import assembly
import wire_assembly
import check_assembly_qualification


class AssemblyQualificationTest(unittest.TestCase):
    def test_artifact_binding_rejects_stale_jar_and_packaged_docs(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);jar_name='logstash-input-splunk_hec-0.2.0.jar'
            jar=root/'build/libs'/jar_name;jar.parent.mkdir(parents=True);jar.write_bytes(b'compiled-current')
            (root/'README.md').write_text('current docs')
            data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w:gz') as archive:
                for name,value in {'vendor/jars/'+jar_name:b'compiled-current','README.md':b'current docs'}.items():
                    entry=tarfile.TarInfo(name);entry.size=len(value);archive.addfile(entry,io.BytesIO(value))
            gem=root/'test.gem'
            with tarfile.open(gem,'w:') as archive:
                value=data.getvalue();entry=tarfile.TarInfo('data.tar.gz');entry.size=len(value);archive.addfile(entry,io.BytesIO(value))
            with patch.multiple(check_assembly_qualification.runtime,ROOT=root,GEM=gem,VERSION='0.2.0'):
                self.assertEqual(2,len(check_assembly_qualification.packaged_files_match_build()))
                jar.write_bytes(b'compiled-newer')
                with self.assertRaisesRegex(RuntimeError,'vendor/jars'):check_assembly_qualification.packaged_files_match_build()
                jar.write_bytes(b'compiled-current');(root/'README.md').write_text('newer docs')
                with self.assertRaisesRegex(RuntimeError,'README.md'):check_assembly_qualification.packaged_files_match_build()

    def test_validator_digest_binds_reports_to_their_producing_assertions(self):
        runtime=check_assembly_qualification.runtime
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);base=root/'tests/interop';base.mkdir(parents=True)
            (base/'a.py').write_text('assert 1');(base/'check_assembly_qualification.py').write_text('gate v1')
            (base/'evidence').mkdir();(base/'evidence/report.json').write_text('{}');(base/'evidence/0.2.0').mkdir();(base/'evidence/0.2.0/out.json').write_text('{}')
            (root/'versions.properties').write_text('a=1');(root/'VERSION').write_text('0.2.0');(root/'scripts').mkdir();(root/'scripts/s.py').write_text('x')
            with patch.object(runtime,'ROOT',root):
                first=runtime.validators_info()
                (base/'check_assembly_qualification.py').write_text('gate v2');(base/'evidence/0.2.0/out.json').write_text('{"x":1}')
                self.assertEqual(first,runtime.validators_info(),'the gate and per-release evidence output are not producers')
                (root/'scripts/s.py').write_text('y')
                self.assertNotEqual(first,runtime.validators_info(),'build scripts and pins are producers')
                (root/'scripts/s.py').write_text('x')
                (base/'evidence/report.json').write_text('{"corpus":1}')
                self.assertNotEqual(first,runtime.validators_info(),'top-level evidence is an input corpus')
                (base/'evidence/report.json').write_text('{}')
                (base/'a.py').write_text('assert 2')
                self.assertNotEqual(first,runtime.validators_info(),'an edited assertion must invalidate retained reports')

    def fixture(self,role,transport):
        events=[]
        for name in ('a','b'):
            for suffix in ('one','two'):
                text=f'START {name} {suffix}\n  '+('trace' if suffix=='one' else 'end')+' '+name
                if role=='uf':text+='\n\n' if suffix=='one' else ('\n' if transport=='tcp' else '')
                events.append(dict(event=text,source=f'/tmp/hec-assembly-{name}.log',index='main',
                                   sourcetype='hec_assembly_selected',s2s_metadata={'path':f'/tmp/hec-assembly-{name}.log'}))
        for text in ('fallback','  separate','repeat'):
            events.append(dict(event=text,source='/tmp/hec-assembly-fallback.log',sourcetype='hec_assembly_fallback'))
        events.append(dict(event='{}',source='/tmp/hec-source.json',sourcetype='json',fields={'a.b{}':['first','second']}))
        return events

    def test_exact_delimiters_reject_missing_blank_line_or_extra_newline(self):
        for role in ('uf','hf'):
            for transport in ('http','tcp'):
                with self.subTest(role=role,transport=transport):
                    events=self.fixture(role,transport)
                    assembly.check(events,role,'none',transport)
                    altered=copy.deepcopy(events)
                    altered[0]['event']=altered[0]['event'][:-1] if role=='uf' else altered[0]['event']+'\n'
                    with self.assertRaises(AssertionError):assembly.check(altered,role,'none',transport)

    def test_stalled_tls_client_does_not_block_accept_or_cleanup(self):
        started=threading.Event();second=threading.Event()
        class Server(wire_assembly.FiniteTLS,socketserver.ThreadingTCPServer):
            daemon_threads=False
            def finish_request(self,request,address):
                (second if started.is_set() else started).set()
                super().finish_request(request,address)
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):raise AssertionError('no TLS client hello was sent')
        with patch.object(wire_assembly,'HANDSHAKE_TIMEOUT',0.2):
            server=Server(('127.0.0.1',0),Handler)
            server.tls_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.02});thread.start()
            try:
                with socket.create_connection(server.server_address,timeout=2) as first:
                    self.assertTrue(started.wait(2))
                    with socket.create_connection(server.server_address,timeout=2):
                        self.assertTrue(second.wait(2),'first handshake must not block the accept loop')
                        began=time.monotonic();server.shutdown();server.server_close();thread.join(2)
                        self.assertLess(time.monotonic()-began,2)
                        self.assertFalse(thread.is_alive())
            finally:
                server.shutdown();server.server_close();thread.join(2)
