"""Packaged current UF bootstrap and synthetic source writer; container-only."""
import json
import os
from pathlib import Path
import shutil
import threading
import time
from configure import configure
from splunk_bootstrap import start, supervise

home, app = configure('uf', '/opt/splunkforwarder')
shutil.copyfile('/demo/logstash/state/identity/server.crt', app / 'trusted-logstash.crt')
run_id = os.environ['DEMO_RUN_ID']


def emit():
    sequence = 0
    while True:
        sequence += 1
        with Path('/tmp/hec-chain.log').open('a') as output:
            output.write('hec_chain_demo run=' + run_id + ' sequence=' + str(sequence) +
                         ' path=UF->HEC_S2S->Logstash->HEC->Splunk message=hello_from_universal_forwarder\n')
        if sequence == 1 or sequence % 6 == 0:
            with Path('/tmp/hec-chain.json').open('a') as output:
                output.write(json.dumps({'time': str(time.time()), 'demo': 'hec_chain_demo',
                    'run': run_id, 'sequence': sequence, 'message': 'native JSON from UF',
                    'labels': ['uf', 'hec-s2s', 'logstash', 'splunk']}) + '\n')
        time.sleep(5)


threading.Thread(target=emit, daemon=True).start()
supervise(start(home, os.environ['SPLUNK_PASSWORD']), home)
