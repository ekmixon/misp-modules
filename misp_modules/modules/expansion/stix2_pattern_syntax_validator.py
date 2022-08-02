import json
try:
    from stix2patterns.validator import run_validator
except ImportError:
    print("stix2 patterns python library is missing, use 'pip3 install stix2-patterns' to install it.")

misperrors = {'error': 'Error'}
mispattributes = {'input': ['stix2-pattern'], 'output': ['text']}
moduleinfo = {'version': '0.1', 'author': 'Christian Studer', 'module-type': ['hover'],
              'description': 'An expansion hover module to perform a syntax check on stix2 patterns.'}
moduleconfig = []


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('stix2-pattern'):
        misperrors['error'] = 'STIX2 pattern missing'
        return misperrors
    pattern = request.get('stix2-pattern')
    syntax_errors = []
    for p in pattern[1:-1].split(' AND '):
        if syntax_validator := run_validator(f"[{p}]"):
            syntax_errors.extend(iter(syntax_validator))
    if syntax_errors:
        s = 's' if len(syntax_errors) > 1 else ''
        s_errors = "".join(f"{error[6:]}\n" for error in syntax_errors)
        result = f"Syntax error{s}: \n{s_errors[:-1]}"
    else:
        result = "Syntax valid"
    return {'results': [{'types': mispattributes['output'], 'values': result}]}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
