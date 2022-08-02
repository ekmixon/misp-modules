# -*- coding: utf-8 -*-

import json
try:
    from onyphe import Onyphe
except ImportError:
    print("pyonyphe module not installed.")

misperrors = {'error': 'Error'}

mispattributes = {'input': ['ip-src', 'ip-dst', 'hostname', 'domain'],
                  'output': ['hostname', 'domain', 'ip-src', 'ip-dst', 'url']}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Sebastien Larinier @sebdraven',
              'description': 'Query on Onyphe',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ['apikey']


def handler(q=False):
    if not q:
        return False
    request = json.loads(q)

    if not request.get('config') or not request['config'].get('apikey'):
        misperrors['error'] = 'Onyphe authentication is missing'
        return misperrors

    api = Onyphe(request['config'].get('apikey'))

    if not api:
        misperrors['error'] = 'Onyphe Error instance api'

    ip = ''
    if request.get('ip-src'):
        ip = request['ip-src']
        return handle_ip(api, ip, misperrors)
    elif request.get('ip-dst'):
        ip = request['ip-dst']
        return handle_ip(api, ip, misperrors)
    elif request.get('domain'):
        domain = request['domain']
        return handle_domain(api, domain, misperrors)
    elif request.get('hostname'):
        hostname = request['hostname']
        return handle_domain(api, hostname, misperrors)
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors


def handle_domain(api, domain, misperrors):
    result_filtered = {"results": []}

    r, status_ok = expand_pastries(api, misperrors, domain=domain)

    if status_ok:
        result_filtered['results'].extend(r)
    else:
        misperrors['error'] = 'Error pastries result'
        return misperrors

    r, status_ok = expand_datascan(api, misperrors, domain=domain)

    if status_ok:
        result_filtered['results'].extend(r)
    else:
        misperrors['error'] = 'Error datascan result '
        return misperrors

    r, status_ok = expand_threatlist(api, misperrors, domain=domain)

    if status_ok:
        result_filtered['results'].extend(r)
    else:
        misperrors['error'] = 'Error threat list'
        return misperrors

    return result_filtered


def handle_ip(api, ip, misperrors):
    result_filtered = {"results": []}

    r, status_ok = expand_syscan(api, ip, misperrors)

    if status_ok:
        result_filtered['results'].extend(r)
    else:
        misperrors['error'] = "Error syscan result"

    r, status_ok = expand_pastries(api, misperrors, ip=ip)

    if status_ok:
        result_filtered['results'].extend(r)
    else:
        misperrors['error'] = 'Error pastries result'
        return misperrors

    r, status_ok = expand_datascan(api, misperrors, ip=ip)

    if status_ok:
        result_filtered['results'].extend(r)
    else:
        misperrors['error'] = 'Error datascan result '
        return misperrors

    r, status_ok = expand_forward(api, ip, misperrors)

    if status_ok:
        result_filtered['results'].extend(r)
    else:
        misperrors['error'] = 'Error forward result'
        return misperrors

    r, status_ok = expand_reverse(api, ip, misperrors)

    if status_ok:
        result_filtered['results'].extend(r)
    else:
        misperrors['error'] = 'Error reverse result'
        return misperrors

    r, status_ok = expand_threatlist(api, misperrors, ip=ip)

    if status_ok:
        result_filtered['results'].extend(r)
    else:
        misperrors['error'] = 'Error threat list'
        return misperrors

    return result_filtered


def expand_syscan(api, ip, misperror):
    status_ok = False
    r = []
    results = api.synscan(ip)

    if results['status'] == 'ok':
        status_ok = True
        asn_list = []
        os_list = []
        geoloc = []
        orgs = []
        for elem in results['results']:
            asn_list.append(elem['asn'])
            os_target = elem['os']
            geoloc.append(elem['location'])
            orgs.append(elem['organization'])
            if os_target not in ['Unknown', 'Undefined']:
                os_list.append(os_target)
        r.extend(
            (
                {
                    'types': ['target-machine'],
                    'values': list(set(os_list)),
                    'categories': ['Targeting data'],
                    'comment': f'OS found on {ip} with synscan of Onyphe',
                },
                {
                    'types': ['target-location'],
                    'values': list(set(geoloc)),
                    'categories': ['Targeting data'],
                    'comment': f'Geolocalisation of {ip} found with synscan of Onyphe',
                },
                {
                    'types': ['target-org'],
                    'values': list(set(orgs)),
                    'categories': ['Targeting data'],
                    'comment': f'Organisations of {ip} found with synscan of Onyphe',
                },
                {
                    'types': ['AS'],
                    'values': list(set(asn_list)),
                    'categories': ['Network activity'],
                    'comment': f'As number of {ip} found with synscan of Onyphe',
                },
            )
        )

    return r, status_ok


def expand_datascan(api, misperror, **kwargs):
    status_ok = False
    r = []
    # ip = ''
    query = ''
    if 'ip' in kwargs:
        query = kwargs.get('ip')
        results = api.datascan(query)
    else:
        query = kwargs.get('domain')
        results = api.search_datascan(f'domain:{query}')

    if results['status'] == 'ok':
        status_ok = True
        asn_list = []
        geoloc = []
        orgs = []
        ports = []

        for elem in results['results']:
            asn_list.append(elem['asn'])
            geoloc.append(elem['location'])
            orgs.append(elem['organization'])
            ports.append(elem['port'])

        r.extend(
            (
                {
                    'types': ['port'],
                    'values': list(set(ports)),
                    'categories': ['Other'],
                    'comment': f'Ports of {query} found with datascan of Onyphe',
                },
                {
                    'types': ['target-location'],
                    'values': list(set(geoloc)),
                    'categories': ['Targeting data'],
                    'comment': f'Geolocalisation of {query} found with synscan of Onyphe',
                },
                {
                    'types': ['target-org'],
                    'values': list(set(orgs)),
                    'categories': ['Targeting data'],
                    'comment': f'Organisations of {query} found with synscan of Onyphe',
                },
                {
                    'types': ['AS'],
                    'values': list(set(asn_list)),
                    'categories': ['Network activity'],
                    'comment': f'As number of {query} found with synscan of Onyphe',
                },
            )
        )

    return r, status_ok


def expand_reverse(api, ip, misperror):
    status_ok = False
    r = None
    status_ok = False
    results = api.reverse(ip)

    domains_reverse = []

    domains = []
    if results['status'] == 'ok':
        status_ok = True

    for elem in results['results']:
        domains_reverse.append(elem['reverse'])
        domains.append(elem['domain'])

    r = [
        {
            'types': ['domain'],
            'values': list(set(domains)),
            'categories': ['Network activity'],
            'comment': f'Domains of {ip} from forward service of Onyphe',
        },
        {
            'types': ['domain'],
            'values': list(set(domains_reverse)),
            'categories': ['Network activity'],
            'comment': f'Reverse Domains of {ip} from forward service of Onyphe',
        },
    ]

    return r, status_ok


def expand_forward(api, ip, misperror):
    results = api.forward(ip)

    domains_forward = []

    domains = []
    status_ok = results['status'] == 'ok'
    for elem in results['results']:
        domains_forward.append(elem['forward'])
        domains.append(elem['domain'])

    r = [
        {
            'types': ['domain'],
            'values': list(set(domains)),
            'categories': ['Network activity'],
            'comment': f'Domains of {ip} from forward service of Onyphe',
        },
        {
            'types': ['domain'],
            'values': list(set(domains_forward)),
            'categories': ['Network activity'],
            'comment': f'Forward Domains of {ip} from forward service of Onyphe',
        },
    ]

    return r, status_ok


def expand_pastries(api, misperror, **kwargs):
    status_ok = False
    r = []

    query = None
    result = None
    if 'ip' in kwargs:
        query = kwargs.get('ip')
        result = api.pastries(query)
    if 'domain' in kwargs:
        query = kwargs.get('domain')
        result = api.search_pastries(f'domain:{query}')

    if result['status'] == 'ok':
        status_ok = True
        urls_pasties = []
        domains = []
        ips = []
        for item in result['results']:
            if (
                item['@category'] == 'pastries'
                and item['source'] == 'pastebin'
            ):
                urls_pasties.append(f"https://pastebin.com/raw/{item['key']}")

                if 'domain' in item:
                    domains.extend(item['domain'])
                if 'ip' in item:
                    ips.extend(item['ip'])
                if 'hostname' in item:
                    domains.extend(item['hostname'])

        r.extend(
            (
                {
                    'types': ['url'],
                    'values': urls_pasties,
                    'categories': ['External analysis'],
                    'comment': f'URLs of pasties where {query} has found',
                },
                {
                    'types': ['domain'],
                    'values': list(set(domains)),
                    'categories': ['Network activity'],
                    'comment': 'Domains found in pasties of Onyphe',
                },
                {
                    'types': ['ip-dst'],
                    'values': list(set(ips)),
                    'categories': ['Network activity'],
                    'comment': 'IPs found in pasties of Onyphe',
                },
            )
        )

    return r, status_ok


def expand_threatlist(api, misperror, **kwargs):
    status_ok = False
    r = []

    query = None

    threat_list = []

    if 'ip' in kwargs:
        query = kwargs.get('ip')
        results = api.threatlist(query)
    else:
        query = kwargs.get('domain')
        results = api.search_threatlist(f'domain:{query}')

    if results['status'] == 'ok':
        status_ok = True
        threat_list = [
            f"seen {item['seen_date']} on {item['threatlist']} "
            for item in results['results']
        ]


        r.append(
            {
                'types': ['comment'],
                'categories': ['Other'],
                'values': threat_list,
                'comment': f'{query} is present in threatlist',
            }
        )


    return r, status_ok


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
