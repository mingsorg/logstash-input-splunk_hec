#!/usr/bin/env python3
"""Inspect the existing lab; optionally export an ignored mode-600 Compose environment file."""
import argparse
import json
import os
from pathlib import Path
import sys
import lab


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', help='existing directory containing connection.json; discovered from Docker by default')
    parser.add_argument('--write-env', metavar='PATH', help='write a NEW local Compose env file; never prints its credentials')
    args = parser.parse_args()
    try:
        rows = lab.inspect()
        inventory = []
        for name, row in rows.items():
            inventory.append({'name': name, 'hostname': row['Config']['Hostname'],
                'image': row['Config']['Image'], 'running': row['State']['Running'],
                'restarting': row['State'].get('Restarting', False),
                'networks': sorted(row['NetworkSettings']['Networks']),
                'ports': row['NetworkSettings']['Ports'],
                'storage': [{'type': item['Type'], 'destination': item['Destination'],
                             'writable': item['RW']} for item in row['Mounts']]})
        output = {'status': 'pass', 'mode': 'existing-container inspection; no deployment', 'containers': inventory}
        if args.write_env:
            state, secret = lab.credentials(rows, args.state_dir)
            indexer, logstash, uf = (rows[name] for name in lab.NAMES)
            values = {
                'TEST_LAB_STATE': str(state),
                'PLUGIN_REPOSITORY': lab.mount(logstash, '/work')['Source'],
                'TEST_LAB_NETWORK': 'hec-demo-chain',
                'INDEXER_ETC_VOLUME': lab.mount(indexer, '/opt/splunk/etc')['Name'],
                'INDEXER_VAR_VOLUME': lab.mount(indexer, '/opt/splunk/var')['Name'],
                'UF_ETC_VOLUME': lab.mount(uf, '/opt/splunkforwarder/etc')['Name'],
                'UF_VAR_VOLUME': lab.mount(uf, '/opt/splunkforwarder/var')['Name'],
                'SPLUNK_IMAGE': indexer['Config']['Image'], 'LOGSTASH_IMAGE': logstash['Config']['Image'],
                'UF_IMAGE': uf['Config']['Image'],
                'SPLUNK_WEB_PORT': str(lab.port(indexer, 8000)),
                'SPLUNK_HEC_PORT': str(lab.port(indexer, 8088)),
                'SPLUNK_MANAGEMENT_PORT': str(lab.port(indexer, 8089)),
                'LOGSTASH_HEC_PORT': str(lab.port(logstash, 8088)),
                'SPLUNK_PASSWORD': secret['password'], 'HEC_INPUT_TOKEN': secret['input_token'],
                'SPLUNK_HEC_TOKEN': secret['indexer_hec_token'], 'DEMO_RUN_ID': secret['run_id']}
            if any('hec-demo-chain' not in row['NetworkSettings']['Networks'] for row in rows.values()):
                raise RuntimeError('the documented existing network is absent')
            # Single-quoted dotenv values are literal (including $ and #). Refuse
            # unsupported quoting/control characters instead of corrupting a secret.
            if any(not isinstance(value, str) or any(char in value for char in "'\r\n") for value in values.values()):
                raise RuntimeError('a value cannot be represented in the local dotenv export')
            destination = Path(args.write_env).expanduser().resolve()
            if destination != lab.LAB / '.env.local':
                raise RuntimeError('--write-env must target docker/test-lab/.env.local (ignored by Git)')
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as handle:
                handle.write('\n'.join(key + "='" + value + "'" for key, value in values.items()) + '\n')
            output['local_env_file'] = str(destination)
        print(json.dumps(output, indent=2))
        return 0
    except Exception as failure:
        print(json.dumps({'status': 'fail', 'error_type': type(failure).__name__,
                          'error': str(failure)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
