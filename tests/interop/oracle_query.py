"""Read only synthetic fixture-source events from the owned local Splunk oracle."""
import base64
import json
import re
import ssl
import urllib.parse
import urllib.request


def source_events(hostname):
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,128}',hostname):raise ValueError('invalid fixture hostname')
    search='search index=main earliest=0 source="/tmp/hec-source.*" host="'+hostname+'" | table _raw _time host source sourcetype index'
    data=urllib.parse.urlencode({'search':search,'output_mode':'json'}).encode()
    request=urllib.request.Request('https://127.0.0.1:18089/services/search/jobs/export',data=data,
        headers={'Authorization':'Basic '+base64.b64encode(b'admin:HecOracle-Test-Only-487!').decode()})
    # Management belongs to this disposable oracle; input TLS is verified in its
    # separate scenarios. No customer/server credentials are used by this query.
    with urllib.request.urlopen(request,context=ssl._create_unverified_context(),timeout=30) as reply:
        return [json.loads(line)['result'] for line in reply if b'"result"' in line]
