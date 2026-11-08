"""Offline, version-aware authenticated assembly-state probes for owned spools."""
import copy
import hashlib
import json
import struct
import re

SAFETY_MAXIMUM=67108863
HASH=re.compile(r'[a-f0-9]{64}\Z')

def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate JSON key')
        result[key]=value
    return result

def loads(data):
    return json.loads(data,object_pairs_hook=unique_object,parse_constant=lambda value:(_ for _ in ()).throw(ValueError('invalid JSON number')))

def envelope(value):
    if not isinstance(value,dict) or set(value)!={'map'}:raise ValueError('invalid assembly envelope')
    tagged(value)

def tagged(value):
    if not isinstance(value,dict):
        if value is None or isinstance(value,(str,bool)):return
        raise ValueError('untagged assembly value')
    if len(value)!=1:raise ValueError('invalid tagged value')
    if 'map' in value:
        if not isinstance(value['map'],list):raise ValueError('invalid tagged map shape')
        keys=set()
        for pair in value['map']:
            if not isinstance(pair,list) or len(pair)!=2 or not isinstance(pair[0],str) or pair[0] in keys:raise ValueError('invalid tagged map')
            keys.add(pair[0]);tagged(pair[1])
    elif 'list' in value:
        if not isinstance(value['list'],list):raise ValueError('invalid tagged list shape')
        for item in value['list']:tagged(item)
    elif 'timestamp' in value:
        from datetime import datetime
        if not isinstance(value['timestamp'],str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)',value['timestamp']):raise ValueError('invalid timestamp shape')
        datetime.fromisoformat(value['timestamp'].replace('Z','+00:00'))
    elif 'number' in value:
        pair=value['number']
        if not isinstance(pair,list) or len(pair)!=2 or not all(isinstance(item,str) for item in pair):raise ValueError('invalid tagged number')
        kind,text=pair
        if kind not in ('Long','Integer','Double','BigInteger','BigDecimal'):raise ValueError('invalid tagged number')
        from decimal import Decimal
        number=Decimal(text)
        if not number.is_finite():raise ValueError('nonfinite tagged number')
        if kind in ('Long','Integer','BigInteger'):
            if not re.fullmatch(r'[+-]?[0-9]+',text):raise ValueError('invalid tagged integer')
            if kind=='Long' and not -(2**63)<=int(text)<2**63:raise ValueError('integer range')
            if kind=='Integer' and not -(2**31)<=int(text)<2**31:raise ValueError('integer range')
    else:raise ValueError('invalid tagged value')

def validate(state):
    if len(state['pending'])>10000 or len(state['outbox'])>40000 or len(state['receipts'])>4096:raise ValueError('assembly safety bound exceeded')
    for key,value in state['pending'].items():
        if not HASH.fullmatch(key) or not value['contributions'] or value['timeout']<1 or value['eventLimit']<1 or value['touched']<0 or not HASH.fullmatch(value['chain']) or not HASH.fullmatch(value['rule']):raise ValueError('invalid pending state')
        envelope(value['envelope'])
    ids=set()
    for value in state['outbox']:
        if value['id'] in ids:raise ValueError('duplicate output identity')
        ids.add(value['id']);envelope(value['envelope'])
    for key,value in state['receipts'].items():
        if not HASH.fullmatch(key) or not HASH.fullmatch(value):raise ValueError('invalid receipt')

def reorder(values,order,label):
    if order is None:return values
    if len(order)!=len(values) or set(order)!=set(values):raise ValueError('invalid '+label+' order')
    return {key:values[key] for key in order}

def apply(state,transaction):
    state=copy.deepcopy(state)
    if transaction['configuration']!=state['configuration']:raise ValueError('configuration mismatch')
    touched=set()
    for key in transaction['removePending']:
        if key in touched or key not in state['pending']:raise ValueError('invalid pending removal')
        touched.add(key);del state['pending'][key]
    for change in transaction['pending']:
        if change['key'] in touched:raise ValueError('duplicate pending operation')
        touched.add(change['key']);value=copy.deepcopy(change['value'])
        if change['prior'] is not None:
            prior=state['pending'].get(change['key'])
            if prior is None or prior['chain']!=change['prior'] or value['text']!='' or value['contributions'] or value['envelope'] is not None or any(
                prior[field]!=value[field] for field in ('rule','origin','attributes','timeout','eventLimit','sender')):raise ValueError('invalid pending append')
            value['text']=prior['text']+change['text'];value['contributions']=prior['contributions']+change['contributions'];value['envelope']=prior['envelope']
        elif change['text'] is not None or change['contributions'] is not None:raise ValueError('invalid pending replacement')
        state['pending'][change['key']]=value
    state['pending']=reorder(state['pending'],transaction.get('pendingOrder'),'pending')
    touched=set()
    for identity in transaction['removeOutputs']:
        matches=[value for value in state['outbox'] if value['id']==identity]
        if identity in touched or len(matches)!=1:raise ValueError('invalid output removal')
        touched.add(identity);state['outbox'].remove(matches[0])
    ids={value['id'] for value in state['outbox']}
    if len(ids)!=len(state['outbox']):raise ValueError('duplicate output identity')
    for value in transaction['outputs']:
        if value['id'] in ids or value['id'] in touched:raise ValueError('duplicate output operation')
        ids.add(value['id']);state['outbox'].append(value)
    touched=set()
    for key in transaction['removeReceipts']:
        if key in touched or key not in state['receipts']:raise ValueError('invalid receipt removal')
        touched.add(key);del state['receipts'][key]
    for key,value in transaction['receipts'].items():
        if key in touched or key in state['receipts'] or not HASH.fullmatch(key) or not HASH.fullmatch(value):raise ValueError('invalid receipt operation')
        state['receipts'][key]=value
    state['receipts']=reorder(state['receipts'],transaction.get('receiptOrder'),'receipt');state['blocked']=transaction['blocked']
    validate(state)
    return state


def checked(path):
    data=path.read_bytes()
    if len(data)<65 or data[64:65]!=b'\n' or hashlib.sha256(data[65:]).hexdigest().encode()!=data[:64]:
        raise ValueError('invalid assembly checksum: '+str(path))
    return loads(data[65:])


def journal_path(directory):
    pointer=checked(directory/'current-v3')
    return directory/('journal-v3-'+str(pointer['generation']))


def retained_bytes(directory):
    """Digest-relevant bytes; inspect a quiescent input or only the committed prefix."""
    if not (directory/'current-v3').exists():return (directory/'state').read_bytes()
    pointer=(directory/'current-v3').read_bytes()
    generation=checked(directory/'current-v3')['generation']
    return pointer+(directory/('snapshot-v3-'+str(generation))).read_bytes()+journal_path(directory).read_bytes()


def read(directory):
    if not (directory/'current-v3').exists():
        state=checked(directory/'state');validate(state);return state
    pointer=checked(directory/'current-v3')
    if pointer['generation']<1 or pointer['sequence']<0 or not HASH.fullmatch(pointer['snapshot']):raise ValueError('invalid generation pointer')
    snapshot_path=directory/('snapshot-v3-'+str(pointer['generation']))
    snapshot=checked(snapshot_path)
    if hashlib.sha256(snapshot_path.read_bytes()[65:]).hexdigest()!=pointer['snapshot'] or snapshot['sequence']!=pointer['sequence']:
        raise ValueError('assembly generation mismatch')
    state=copy.deepcopy(snapshot['state']);validate(state);sequence=snapshot['sequence']
    data=journal_path(directory).read_bytes();position=0
    while position<len(data):
        if len(data)-position<88:break
        header=data[position:position+88]
        magic,version,ordinal,length=struct.unpack('>IIQQ',header[:24])
        if magic!=0x53325333 or version!=3 or ordinal!=sequence+1 or length>2*SAFETY_MAXIMUM+4096-88 or hashlib.sha256(header[:24]).digest()!=header[24:56]:
            raise ValueError('invalid transaction framing')
        if len(data)-position-88<length:break
        payload=data[position+88:position+88+length]
        if hashlib.sha256(payload).digest()!=header[56:88]:raise ValueError('complete transaction corruption')
        state=apply(state,loads(payload))
        sequence=ordinal;position+=88+length
    return state
