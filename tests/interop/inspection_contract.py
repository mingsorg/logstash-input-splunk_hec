"""Strict test validator for the JSON Schema vocabulary emitted by the inspector.

No runtime dependency is added to the installed command. Unknown schema keywords
fail here instead of silently making an assertion ineffective.
"""
import re
def validate(schema, value):
    supported = {'type', 'const', 'enum', 'minimum', 'minLength', 'properties', 'required',
                 'additionalProperties', 'oneOf', 'anyOf', 'not', 'items', 'pattern'}
    if set(schema)-supported:
        raise ValueError('unsupported schema vocabulary')
    def matches(child):
        try:
            validate(child, value)
            return True
        except ValueError:
            return False
    if 'const' in schema and (value != schema['const'] or isinstance(value, bool) != isinstance(schema['const'], bool)):
        raise ValueError('const mismatch')
    if 'enum' in schema and value not in schema['enum']:
        raise ValueError('enum mismatch')
    if 'type' in schema:
        types = schema['type'] if isinstance(schema['type'], list) else [schema['type']]
        checks = {'object': lambda: isinstance(value, dict), 'array': lambda: isinstance(value, list),
                  'string': lambda: isinstance(value, str), 'boolean': lambda: isinstance(value, bool),
                  'integer': lambda: isinstance(value, int) and not isinstance(value, bool),
                  'null': lambda: value is None}
        if any(t not in checks for t in types) or not any(checks[t]() for t in types):
            raise ValueError('type mismatch')
    if 'oneOf' in schema and sum(matches(child) for child in schema['oneOf']) != 1:
        raise ValueError('oneOf mismatch')
    if 'anyOf' in schema and not any(matches(child) for child in schema['anyOf']):
        raise ValueError('anyOf mismatch')
    if 'not' in schema and matches(schema['not']):
        raise ValueError('not mismatch')
    if isinstance(value, dict):
        if not set(schema.get('required', [])) <= value.keys():
            raise ValueError('required property missing')
        properties = schema.get('properties', {})
        if schema.get('additionalProperties') is False and value.keys()-properties.keys():
            raise ValueError('unknown property')
        for key in value.keys() & properties.keys():
            validate(properties[key], value[key])
    if isinstance(value, list) and 'items' in schema:
        for item in value:
            validate(schema['items'], item)
    if isinstance(value, int) and not isinstance(value, bool) and value < schema.get('minimum', value):
        raise ValueError('minimum mismatch')
    if isinstance(value, str) and len(value) < schema.get('minLength', 0):
        raise ValueError('minLength mismatch')
    if isinstance(value, str) and 'pattern' in schema and re.search(schema['pattern'],value) is None:
        raise ValueError('pattern mismatch')
