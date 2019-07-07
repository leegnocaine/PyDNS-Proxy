#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# PyDNS Proxy
# Single file python dns proxy that supports UDP, TCP and DOH
# Author: leegnocaine
# Thanks henices/Tcp-DNS-proxy for inspiration
#
#


import os, argparse, json, logging, struct, time, socket, traceback
from threading import Thread, Lock
from multiprocessing.dummy import Pool
try:
    import SocketServer
except:
    import socketserver as SocketServer

#predefined
CFGFILE = ''
LOCK = Lock()
LOGGER = logging.getLogger(__name__)
DISABLE_DOH = False
DOHCONN = None
SPEEDTEST = None
RECORDTYPE = {1:'A', 28:'AAAA', 5:'CNAME', 12:'PTR', 2:'NS'}
#need lock to change
CFG = {}
CACHE = {}



def hexdump(src, width=16):
    ''' default width 16
    '''
    if not src:
        return ''
    FILTER = ''.join([(x < 0x7f and x > 0x1f) and chr(x) or '.' for x in range(256)])
    result = []
    for i in range(0, len(src), width):
        s = src[i:i + width]
        if type(s) == type(''):
            hexa = ' '.join(['%02X' % ord(x) for x in s])
        else:
            hexa = ' '.join(['%02X' % x for x in s])
        printable = s.translate(FILTER.encode('utf-8'))
        result.append('%#06X   %s   %s\n' % (i, hexa, printable))
    return ''.join(result)


def set_logger(log_file, set_level):
    logging.addLevelName(5, 'RAW')
    if log_file:
        handler = logging.FileHandler(filename=log_file)
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s'))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(set_level)


def load_cfg():
    global CFG

    try:
        LOGGER.warning('Loading PyDNS Proxy Config')
        with open(CFGFILE, "r") as file:
            LOCK.acquire()
            CFG = json.load(file)
            LOCK.release()
        CFG['socket_timeout']
        CFG['primary_dns_server']
        CFG['primary_dns_querymode']
        CFG['primary_dns_speedtest']
        CFG['private_host']
        CFG['redirect_domain']
        CFG['ipv6_only_domain']
        CFG['private_dns_server']
        CFG['private_dns_querymode']
        CFG['private_domain']
        CFG['internal_dns_server']
        CFG['internal_dns_querymode']
        CFG['internal_domain']
        CFG['internal_domain_exception']
        checklist_querymode = ['udp', 'tcp', 'doh']
        if DISABLE_DOH:
            checklist_querymode.remove('doh')
        if CFG['primary_dns_querymode'] not in checklist_querymode or CFG['private_dns_querymode'] not in checklist_querymode or CFG['internal_dns_querymode'] not in checklist_querymode:
            LOGGER.critical('Contains wrong query mode, check config failed.')
            os._exit(1)
        if (type(CFG['socket_timeout']) != type(1) and type(CFG['socket_timeout']) != type(1.1)) or CFG['socket_timeout'] < 0:
            LOGGER.critical('socket_timeout must be positive number, check config failed.')
            os._exit(1)
        DOHCONN.__init__()
        if CFG['primary_dns_querymode'] == 'doh':
            DOHCONN.setArgs(CFG['primary_dns_server'])
        if CFG['private_dns_querymode'] == 'doh':
            DOHCONN.setArgs(CFG['private_dns_server'])
        if CFG['internal_dns_querymode'] == 'doh':
            DOHCONN.setArgs(CFG['internal_dns_server'])
        DOHCONN.establish()
    except:
        LOGGER.critical('Loading config file error: \n%s' % traceback.format_exc())
        os._exit(1)
    else:
        LOGGER.warning('Query Timeout: %f' % (CFG['socket_timeout']))
        LOGGER.warning('Primary DNS Servers: \n%s' % CFG['primary_dns_server'])

        if CFG['primary_dns_speedtest'] and not SPEEDTEST.thread.isAlive():
            SPEEDTEST.setArgs(CFG['primary_dns_server'], CFG['primary_dns_querymode'], CFG['socket_timeout'])
            SPEEDTEST.thread.start()


def schedule_reload_cfg(interval):
    while True:
        load_cfg()
        time.sleep(interval)


def bytetodomain(byte):
    domain = b''
    i = 0
    length = struct.unpack('!B', byte[0:1])[0]
    while length != 0 and length < 0xC0:
        i += 1
        domain += byte[i:i + length]
        i += length
        length = struct.unpack('!B', byte[i:i + 1])[0]
        if length != 0 and length < 0xC0:
            domain += b'.'
        elif length >= 0xC0:
            domain += byte[i:i+2]
    return (domain, i+1)


def domaintobyte(domain):
    byte = b''
    domain = domain.decode('utf-8').split('.')
    for piece in domain:
        piece = piece.encode('utf-8')
        i = 0
        length = len(piece)
        byte += struct.pack('!B', length)
        for i in range(length):
            byte += struct.pack('!s', piece[i:i+1])
    byte += struct.pack('!B', 0)
    return byte


def resolve_data(data):
    try:
        result = {}
        result['PID'] = data[0:2]
        result['Flags'] = struct.unpack('!H', data[2:4])[0]
        result['qr'] = (result.get('Flags') & 0x8000) / 0x8000
        result['opcode'] = (result.get('Flags') & 0x7800) / 0x800
        result['aa'] = (result.get('Flags') & 0x0400) / 0x400
        result['tc'] = (result.get('Flags') & 0x0200) / 0x200
        result['rd'] = (result.get('Flags') & 0x0100) / 0x100
        result['ra'] = (result.get('Flags') & 0x0080) / 0x80
        result['zero'] = (result.get('Flags') & 0x0070) / 0x70
        result['rcode'] = result.get('Flags') & 0x000F
        result['qd_count'] = struct.unpack('!H', data[4:6])[0]
        result['an_count'] = struct.unpack('!H', data[6:8])[0]
        result['ns_count'] = struct.unpack('!H', data[8:10])[0]
        result['ar_count'] = struct.unpack('!H', data[10:12])[0]
        result['query'] = {}
        pointer = 12
        for i in range(result.get('qd_count')):
            result['query'][i] = {}
            increase=bytetodomain(data[pointer:])[1]
            result['query'][i]['q_domain'] = bytetodomain(data[pointer:])[0]
            result['query'][i]['q_type'] = struct.unpack('!H', data[pointer+increase:pointer+increase+2])[0]
            result['query'][i]['q_class'] = struct.unpack('!H', data[pointer+increase+2:pointer+increase+4])[0]
            pointer += increase+4

        if result.get('an_count') > 0:
            result['answer'] = {}
            offsettable = {}
            for i in range(result.get('an_count')):
                result['answer'][i] = {}
                startpoint = pointer
                if struct.unpack('!H', data[pointer:pointer+2])[0] >= 0xC000:
                    offset = struct.unpack('!H', data[pointer:pointer+2])[0] & 0x3FFF
                    if struct.unpack('!H', data[offset:offset+2])[0] >= 0xC000:
                        result['answer'][i]['a_domain'] = offsettable.get(struct.unpack('!H', data[offset:offset+2])[0])
                    else:
                        result['answer'][i]['a_domain'] = bytetodomain(data[offset:])[0]
                        offsettable[struct.unpack('!H', data[pointer:pointer+2])[0]] = result.get('answer').get(i).get('a_domain')
                    pointer += 2
                else:
                    result['answer'][i]['a_domain'] = bytetodomain(data[pointer:])[0]
                    pointer += bytetodomain(data[pointer:])[1]
                if result.get('answer').get(i).get('a_domain') and struct.unpack('!H', result.get('answer').get(i).get('a_domain')[-2:])[0] >= 0xC000:
                    offset = struct.unpack('!H', result.get('answer').get(i).get('a_domain')[-2:])[0] & 0x3FFF
                    result['answer'][i]['a_domain'] = result.get('answer').get(i).get('a_domain')[0:-2] + b'.' + bytetodomain(data[offset:])[0]
                result['answer'][i]['a_type'] = struct.unpack('!H', data[pointer:pointer+2])[0]
                result['answer'][i]['a_class'] = struct.unpack('!H', data[pointer+2:pointer+4])[0]
                result['answer'][i]['a_ttl'] = struct.unpack('!I', data[pointer+4:pointer+8])[0]
                result['answer'][i]['a_rdlength'] = struct.unpack('!H', data[pointer+8:pointer+10])[0]
                result['answer'][i]['a_rdata'] = data[pointer+10:pointer+10+result.get('answer').get(i).get('a_rdlength')]
                #ipv4 address
                if result.get('answer').get(i).get('a_type') == 0x0001:
                    result['answer'][i]['a_rdata'] = socket.inet_ntop(socket.AF_INET,result.get('answer').get(i).get('a_rdata'))
                #ipv6 address
                if result.get('answer').get(i).get('a_type') == 0x001C:
                    result['answer'][i]['a_rdata'] = socket.inet_ntop(socket.AF_INET6,result.get('answer').get(i).get('a_rdata'))
                #cname
                if result.get('answer').get(i).get('a_type') == 0x0005:
                    if struct.unpack('!H', result.get('answer').get(i).get('a_rdata')[0:2])[0] >= 0xC000:
                        offset = struct.unpack('!H', result.get('answer').get(i).get('a_rdata')[0:2])[0] & 0x3FFF
                        result['answer'][i]['a_rdata'] = bytetodomain(data[offset:])[0]
                    else:
                        result['answer'][i]['a_rdata'] = bytetodomain(result.get('answer').get(i).get('a_rdata'))[0]
                    if struct.unpack('!H', result.get('answer').get(i).get('a_rdata')[-2:])[0] >= 0xC000:
                        offset = struct.unpack('!H', result.get('answer').get(i).get('a_rdata')[-2:])[0] & 0x3FFF
                        result['answer'][i]['a_rdata'] = result.get('answer').get(i).get('a_rdata')[0:-2] + b'.' + bytetodomain(data[offset:])[0]
                pointer += 10+result.get('answer').get(i).get('a_rdlength')
                endpoint = pointer
                result['answer'][i]['RAW'] = data[startpoint:endpoint]
        result['OTHER'] = data[pointer:]
    except:
        LOGGER.error('Resolving data error: \n%s' % traceback.format_exc())
        return None
    return result


def build_request(parse_data, q_domain, q_type):
    if not q_domain:
        q_domain=parse_data.get('query').get(0).get('q_domain')
    if not q_type:
        q_type=parse_data.get('query').get(0).get('q_type')
    #query id
    request = parse_data.get('PID')
    request += struct.pack('!H', parse_data.get('Flags'))
    #query number
    request += struct.pack('!H', 1)
    request += struct.pack('!H', parse_data.get('an_count'))
    request += struct.pack('!H', parse_data.get('ns_count'))
    request += struct.pack('!H', parse_data.get('ar_count'))
    #header finished, start query
    request += domaintobyte(q_domain)
    request += struct.pack('!H', q_type)
    request += struct.pack('!H', parse_data.get('query').get(0).get('q_class'))
    return request


def build_resource(a_type, a_class, a_rdata):
    #offset flag, point to query domain name
    #'\xC0\x0C'
    resource = struct.pack('!H', 0xC000 + 12)
    resource += struct.pack('!H', a_type)
    resource += struct.pack('!H', a_class)
    #TTL
    resource += struct.pack('!I', 255)
    if a_type == 0x0001:
        resource += struct.pack('!H', 4)
        resource += socket.inet_pton(socket.AF_INET, a_rdata)
    elif a_type == 0x001C:
        resource += struct.pack('!H', 16)
        resource += socket.inet_pton(socket.AF_INET6, a_rdata)
    elif a_type == 0x0005 or a_type == 0x000C or a_type == 0x0002:
        resource += struct.pack('!H', len(domaintobyte(a_rdata)))
        resource += domaintobyte(a_rdata)
    return resource


def build_response(parse_data, an_count=0, resource=''):
    #query id
    response = parse_data.get('PID')
    #flag normally is 0x8180
    response += struct.pack('!H', 0x8000 + (parse_data.get('Flags') & 0x7F00) + 0x80)
    #query number
    response += struct.pack('!H', parse_data.get('qd_count'))
    #answer number
    response += struct.pack('!H', an_count)
    response += struct.pack('!H', parse_data.get('ns_count'))
    response += struct.pack('!H', parse_data.get('ar_count'))
    #header finished, start query
    response += domaintobyte(parse_data.get('query').get(0).get('q_domain'))
    response += struct.pack('!H', parse_data.get('query').get(0).get('q_type'))
    response += struct.pack('!H', parse_data.get('query').get(0).get('q_class'))
    if an_count > 0:
        response += resource
    return response


def private_host_query(parse_request):
    data=None
    answer = b''
    counter = 0

    for domain, rets in CFG['private_host'].items():
        if domain in parse_request.get('query').get(0).get('q_domain').decode('utf-8'):
            q_type = parse_request.get('query').get(0).get('q_type')
            a_class = parse_request.get('query').get(0).get('q_class')
            if q_type == 0x0001 or q_type == 0x001C:
                for ret in rets:
                    if '.' in ret and ret[0:1] != '!':
                        # A record
                        counter += 1
                        answer += build_resource(0x0001, a_class, ret)
                    elif ':' in ret and ret[0:1] != '!':
                        # AAAA record
                        counter += 1
                        answer += build_resource(0x001C, a_class, ret)
                    elif '!' in ret and ret[0:1] == '!':
                        # CNAME record
                        ret = ret[1:].encode('utf-8')
                        counter += 1
                        answer += build_resource(0x0005, a_class, ret)
            if q_type == 0x0005 or q_type == 0x000C or q_type == 0x0002:
                # CNAME PTR NS record
                for ret in rets:
                    if '!' in ret and ret[0:1] == '!':
                        ret = ret[1:].encode('utf-8')
                        counter += 1
                        answer += build_resource(q_type, a_class, ret)
            data=build_response(parse_request, counter, answer)
            LOGGER.debug('-> an_count: %s' % (counter))
            for i in range(counter):
                a_type = resolve_data(data).get('answer').get(i).get('a_type')
                LOGGER.debug('->-> a_type %r: %s' % (i, RECORDTYPE.get(a_type, a_type)))
            LOGGER.log(5, '-> RAW Private Response: \n%s' % hexdump(data))
            break
    return data


def QueryDNS(server, request, querymode, timeout, q_domain, q_type):
    '''proxy dns request

    Args:
        server: remote dns server
        request: dns request packet
        querymode: how to query remote server
        timeout: socket timeout
    Returns:
        dns response
    '''
    
    response = None
    try:
        if querymode == 'doh':
            response = DOHCONN.query(server, request, q_domain, q_type)
        else:
            addr, port = server.split('#')
            protocol = socket.SOCK_DGRAM
            if querymode == 'tcp':
                request = struct.pack('!H', len(request)) + request
                protocol = socket.SOCK_STREAM
            if '.' in addr:
                family = socket.AF_INET
            elif ':' in addr:
                family = socket.AF_INET6
            else:
                raise Exception('Server address has wrong format.')
            sock = socket.socket(family, protocol)
            # set socket timeout
            sock.settimeout(timeout)
            sock.connect((addr, int(port)))
            sock.send(request)
            response = sock.recv(2048)
            sock.settimeout(None)
    except socket.timeout:
        LOGGER.warning('Server %s: timeout' % addr)
    except:
        LOGGER.error('Server %s: \n%s' % (addr, traceback.format_exc()))
    finally:
        if 'sock' in locals():
            sock.close()
        return response


def legit_response_packet(parse_response, parse_request):
    if parse_response.get('PID') != parse_request.get('PID'):
        LOGGER.error('-> check pid failed!')
        return False

    if parse_response.get('qr') != 1:
        LOGGER.error('-> check qr failed: %s' %parse_response.get('qr'))
        return False
    
    return True


def transfer(request, client, socket):
    '''send udp dns response back to client program

    Args:
        request: udp dns request
        client: udp dns client address
        socket: udp dns socket

    Returns:
        None
    '''

    global CACHE

    if len(request) < 12:
        LOGGER.error('check request length failed!')
        return
    LOGGER.log(5, '-> RAW Request: \n%s' % hexdump(request))
    response = None
    parse_request = resolve_data(request)

    pid = parse_request.get('PID')
    q_type = parse_request.get('query').get(0).get('q_type')
    q_domain = parse_request.get('query').get(0).get('q_domain')
    cache_key = q_domain+struct.pack('!H', q_type)

    LOGGER.info('Receive: %s||%s %s' % (q_domain, RECORDTYPE.get(q_type, q_type), client))

    if (q_type == 0x0001 or q_type == 0x001C or q_type == 0x0005 or q_type == 0x000C or q_type == 0x0002) and parse_request.get('qd_count') == 0x0001 and \
            parse_request.get('an_count') == 0x0000 and parse_request.get('ns_count') == 0x0000 and \
            parse_request.get('ar_count') == 0x0000:
        response = private_host_query(parse_request)
    if response:
        socket.sendto(response, client)
        LOGGER.info('%s||%s -> hit from private host' % (q_domain, RECORDTYPE.get(q_type, q_type)))
        return

    if cache_key in CACHE:
        response = CACHE[cache_key].get('response')
        socket.sendto(pid + response, client)
        LOGGER.info('%s||%s -> hit from cache' % (q_domain, RECORDTYPE.get(q_type, q_type)))
        return

    filter_redirect = False
    filter_ipv6 = False
    bypass_internal = False
    querymode = CFG['primary_dns_querymode']
    if SPEEDTEST.fast_servers and not SPEEDTEST.thread.isAlive():
        dns_server_list = SPEEDTEST.fast_servers
    else:
        dns_server_list = CFG['primary_dns_server']

    if CFG['redirect_domain']:
        for domain,redirect in CFG['redirect_domain'].items():
            if domain == q_domain.decode('utf-8'):
                LOGGER.info('%s||%s -> mark from redirect_domain' % (q_domain, RECORDTYPE.get(q_type, q_type)))
                q_domain = redirect.encode('utf-8')
                filter_redirect = True
                break

    if (q_type == 0x0001 or q_type == 0x001C or q_type == 0x0005) and CFG['ipv6_only_domain']:
        for ipv6_only_domain in CFG['ipv6_only_domain']:
            if ipv6_only_domain == q_domain.decode('utf-8') or ('.'+ipv6_only_domain) in q_domain.decode('utf-8'):
                LOGGER.info('%s||%s -> mark from ipv6_only_domain (%s)' % (q_domain, RECORDTYPE.get(q_type, q_type), ipv6_only_domain))
                filter_ipv6 = True
                bypass_internal = True
                break

    if CFG['private_dns_server'] and CFG['private_domain']:
        for private_domain in CFG['private_domain']:
            if private_domain == q_domain.decode('utf-8') or ('.'+private_domain) in q_domain.decode('utf-8'):
                LOGGER.info('%s||%s -> mark from private_domain (%s)' % (q_domain, RECORDTYPE.get(q_type, q_type), private_domain))
                bypass_internal = True
                dns_server_list = CFG['private_dns_server']
                querymode = CFG['private_dns_querymode']
                break

    if CFG['internal_domain_exception']:
        for internal_domain_exception in CFG['internal_domain_exception']:
            if internal_domain_exception == q_domain.decode('utf-8') or ('.'+internal_domain_exception) in q_domain.decode('utf-8'):
                LOGGER.info('%s||%s -> mark from internal_domain_exception (%s)' % (q_domain, RECORDTYPE.get(q_type, q_type), internal_domain_exception))
                bypass_internal = True
                break

    if not bypass_internal and CFG['internal_dns_server'] and CFG['internal_domain']:
        for internal_domain in CFG['internal_domain']:
            if internal_domain == q_domain.decode('utf-8') or ('.'+internal_domain) in q_domain.decode('utf-8'):
                LOGGER.info('%s:%s mark from internal_domain (%s)' % (q_domain, RECORDTYPE.get(q_type, q_type), internal_domain))
                dns_server_list = CFG['internal_dns_server']
                querymode = CFG['internal_dns_querymode']
                break

    LOGGER.debug('%s||%s -> dns list: %s' % (q_domain, RECORDTYPE.get(q_type, q_type), dns_server_list))
    for server in dns_server_list:

        if filter_redirect:
            LOGGER.debug('%s -> redirect request filter, change request domain' % (q_domain))
            request = build_request(parse_request, q_domain, False)

        if filter_ipv6 and q_type == 0x0001:
            LOGGER.debug('%s||%s -> ipv4 request filter, change request type' % (q_domain, RECORDTYPE.get(q_type, q_type)))
            request = build_request(parse_request, False, 0x001C)
            parse_request = resolve_data(request)

        LOGGER.debug('Querying: %s||%s -> server: %s mode: %s' % (q_domain, RECORDTYPE.get(q_type, q_type), server, querymode))
        response = QueryDNS(server, request, querymode, CFG['socket_timeout'], q_domain, q_type)

        if response is None or len(response) < 12:
            LOGGER.error('%s||%s -> check response length failed!' % (q_domain, RECORDTYPE.get(q_type, q_type)))
            continue

        response = response
        if querymode == 'tcp':
            response = response[2:]
        LOGGER.log(5, '-> Server RAW Response: \n%s' % hexdump(response))
        
        parse_response = resolve_data(response)
        if not legit_response_packet(parse_response, parse_request):
            continue

        if filter_ipv6:
            if q_type == 0x0001:
                parse_response['query'][0]['q_type'] = 0x0001
            count_cname = 0
            count_ipv4 = 0
            count_ipv6 = 0
            for i in range(parse_response.get('an_count')):
                if parse_response.get('answer').get(i).get('a_type') == 0x0005:
                    count_cname += 1
                if parse_response.get('answer').get(i).get('a_type') == 0x0001:
                    count_ipv4 += 1
                if parse_response.get('answer').get(i).get('a_type') == 0x001C:
                    count_ipv6 += 1
            if count_ipv6 == 0 and count_cname == 0:
                LOGGER.debug('%s||%s -> ipv6 only filter, detect no ipv6 no cname in response' % (q_domain, RECORDTYPE.get(q_type, q_type)))
                continue
            elif count_ipv4 > 0:
                LOGGER.debug('%s||%s -> ipv6 only filter, detect ipv4 and ipv6 in response' % (q_domain, RECORDTYPE.get(q_type, q_type)))
                for i in range(parse_response.get('an_count')):
                    if parse_response.get('answer').get(i).get('a_type') == 0x0001:
                        del parse_response['answer'][i]
                        parse_response['an_count'] -= 1
            answers = ''
            for answer in parse_response.get('answer').items():
                answers += answer[1].get('RAW')
            response = build_response(parse_response, parse_response.get('an_count'), answers+parse_response.get('OTHER'))

        socket.sendto(response, client)
        LOGGER.info('Finish: %s||%s %s %s' % (q_domain, RECORDTYPE.get(q_type, q_type), server, client))

        if parse_response.get('an_count') > 0:
            if filter_ipv6 and count_ipv6 == 0:
                LOGGER.debug('%s||%s -> ipv6 only filter, no ip in response, skip cache' % (q_domain, RECORDTYPE.get(q_type, q_type)))
                break
            #running in thread, lock to prevent unexpected error
            LOCK.acquire()
            CACHE[cache_key] = {}
            CACHE[cache_key]['response'] = response[2:]
            CACHE[cache_key]['settime'] = time.time()
            CACHE[cache_key]['ttl'] = parse_response.get('answer').get(0).get('a_ttl')
            for key in list(CACHE):
                if CACHE.get(key).get('settime')+CACHE.get(key).get('ttl') < time.time():
                    del CACHE[key]
            LOCK.release()


        LOGGER.log(5, '-> q_domain: %s' % parse_response.get('query').get(0).get('q_domain'))
        q_t = parse_response.get('query').get(0).get('q_type')
        LOGGER.log(5, '-> q_type: %s' % RECORDTYPE.get(q_t, q_t))
        LOGGER.log(5, '-> an_count: %s' % parse_response.get('an_count'))
        for i in range(parse_response.get('an_count')):
            a_type = parse_response.get('answer').get(i).get('a_type')
            LOGGER.log(5, '->-> a_type %r: %s' % (i, RECORDTYPE.get(a_type, a_type)))
        LOGGER.log(5, '-> RAW Response: \n%s' % hexdump(response))

        break

    if response is None:
        LOGGER.error('Tried many times and failed to resolve %s' % q_domain)


def run_server(cmdargs):
    LOGGER.warning('Serving PyDNS Proxy on %s port %s ...' % (args.ip, args.port))
    reload_cfg = Thread(target=schedule_reload_cfg, args=[cmdargs.reload_interval])
    reload_cfg.setDaemon(True)
    reload_cfg.start()
    if cmdargs.port < 0 or cmdargs.port > 65535:
        LOGGER.critical('Wrong port to listen.')
        os._exit(1)
    if cmdargs.ip == '':
        if os.name == 'nt':
            serverv4 = ThreadedUDPServerV4(('', cmdargs.port), DNSRequestHandler)
            serverv6 = ThreadedUDPServerV6(('', cmdargs.port), DNSRequestHandler)
        else:
            serverv6 = ThreadedUDPServerV6(('', cmdargs.port), DNSRequestHandler)
    else:
        if '.' in cmdargs.ip:
            serverv4 = ThreadedUDPServerV4((cmdargs.ip, cmdargs.port), DNSRequestHandler)
        elif ':' in cmdargs.ip:
            serverv6 = ThreadedUDPServerV6((cmdargs.ip, cmdargs.port), DNSRequestHandler)
        else:
            LOGGER.critical('Wrong IP addess to listen.')
            os._exit(1)
    if 'serverv4' in locals():
        serverv4.serve_forever()
    if 'serverv6' in locals():
        serverv6.serve_forever()

class DaemonThreadingMixIn(SocketServer.ThreadingMixIn):
    daemon_threads = True

class ThreadedUDPServerV4(DaemonThreadingMixIn, SocketServer.UDPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True

class ThreadedUDPServerV6(DaemonThreadingMixIn, SocketServer.UDPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True

class DNSRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        client = self.client_address
        transfer(data, client, socket)

class DOHConnection():
    def __init__(self):
        self.servers = []
    
    def setArgs(self, servers):
        self.servers = list(set(servers + self.servers))

    def establish(self):
        self.conn = {}
        for server in self.servers:
            if server not in self.conn:
                self.conn[server] = []
            addr, port = server.split('#')
            if '/' not in addr:
                addr += '/'
            pos = addr.index('/')
            host = addr[:pos]
            path = addr[pos+1:]
            self.conn[server] = [HTTPConnection(host+':'+port), path]
    
    def query(self, server, buff, q_domain, q_type):
        LOGGER.debug('DOH request: %s||%s -> server: %s' % (q_domain, RECORDTYPE.get(q_type, q_type), server))
        req = self.conn[server][0].request('POST', '/'+self.conn[server][1], headers={'Content-Type':'application/dns-message','Content-Length':str(len(buff))}, body=buff)
        resp = self.conn[server][0].get_response(req)
        ret = resp.read()
        LOGGER.debug('DOH response: %s||%s -> status: %s' % (q_domain, RECORDTYPE.get(q_type, q_type), resp.status))
        LOGGER.log(5, 'DOH response headers: %s' % resp.headers)
        return ret


class SpeedTest():
    def __init__(self):
        #make sure isAlive() is functional
        self.thread = Thread(target=self.run)
        self.thread.daemon = True
        self.fast_servers = None

    def setArgs(self, servers, querymode, timeout):
        #make thead can run more than once
        self.thread = Thread(target=self.run)
        self.thread.daemon = True
        self.servers = servers
        self.querymode = querymode
        self.timeout = timeout

    def dnsping(self, server):
        q_domain = b'www.baidu.com'
        q_type = 0x0001
        buff = b'\x00\x0F\x01\x00\x00\x01'
        buff += b'\x00\x00\x00\x00\x00\x00'
        buff += domaintobyte(q_domain)
        buff += struct.pack('!H', q_type)
        buff += b'\x00\x01'
        
        begin = time.time()
        QueryDNS(server, buff, self.querymode, self.timeout, q_domain, q_type)
        cost = time.time() - begin
        return [server, cost]

    def run(self):
        servers = []
        for dummy_i in range(6):
            servers.extend(self.servers)

        LOGGER.warning('Performing dns server speed test ...')

        pool = Pool(len(servers))
        speed_list = pool.map(self.dnsping, servers)
        pool.close()
        pool.join()

        cost_dict = {}
        for k, v in speed_list:
            if k not in cost_dict:
                cost_dict[k] = 0
            cost_dict[k] += v

        self.fast_servers = sorted(cost_dict, key=cost_dict.get)
        LOGGER.info('Fully sorted server list: \n%s' %self.fast_servers)
        LOGGER.warning('Speed test done.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PyDNS Proxy')
    parser.add_argument('-c', dest='config_json',
                        required=False,
                        default='pydns.json',
                        help='JSON config file')
    parser.add_argument('-l', dest='log_file',
                        required=False,
                        default=None,
                        help='Log file')
    parser.add_argument('-raw', dest='raw',
                        action='store_true',
                        required=False,
                        default=False,
                        help='Show raw debug message')
    parser.add_argument('-debug', dest='debug',
                        action='store_true',
                        required=False,
                        default=False,
                        help='Show debug message')
    parser.add_argument('-info', dest='info',
                        action='store_true',
                        required=False,
                        default=False,
                        help='Show query info message')
    parser.add_argument('-i', '--interval',
                        dest='reload_interval',
                        type=int,
                        required=False,
                        default=43200,
                        help='Interval (seconds) to auto-reload config file')
    parser.add_argument('-port',
                        type=int,
                        default=53,
                        help='Port to listen')
    parser.add_argument('-ip',
                        default='',
                        help='IP address to listen')
    args = parser.parse_args()

    if args.raw:
        set_logger(args.log_file, 5)
    elif args.debug:
        set_logger(args.log_file, logging.DEBUG)
    elif args.info:
        set_logger(args.log_file, logging.INFO)
    else:
        set_logger(args.log_file, logging.WARNING)

    try:
        from hyper import HTTPConnection
    except:
        DISABLE_DOH = True
        LOGGER.warning('Hyper module does not exist, DOH is not functional.')
    CFGFILE = args.config_json
    DOHCONN=DOHConnection()
    SPEEDTEST=SpeedTest()
    run_server(args)
