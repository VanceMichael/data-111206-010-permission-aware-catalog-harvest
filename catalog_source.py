import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen

FIXTURE_PATH = Path(__file__).resolve().parent / 'fixtures' / 'catalog.json'

LISTING_KINDS = {'/namespaces': 'namespace-list', '/datasets': 'dataset-list'}


def endpoint_kind(resource):
    '''把 URL 路径映射为稳定的端点类别，供采集计划与证据说明使用。'''
    if resource in LISTING_KINDS:
        return LISTING_KINDS[resource]
    pieces = resource.strip('/').split('/')
    if len(pieces) == 3 and pieces[0] == 'datasets' and pieces[2] in ('fields', 'dependencies'):
        return 'field-list' if pieces[2] == 'fields' else 'dependency-list'
    return 'unknown'


class Catalog:
    def __init__(self, data_path=None):
        self.data = json.loads(Path(data_path or FIXTURE_PATH).read_text())
        self.generation = 'g1'
        self.scope = 'wide'
        self.requests = 0
        self.transitions = {}
        # before_query(catalog, resource) 在每条响应生成前执行，可模拟
        # 一次扫描中目录代际或账号可见范围发生变化。
        self.before_query = None

    def query(self, resource, cursor=0):
        self.requests += 1
        if self.before_query is not None:
            self.before_query(self, resource)
        transition = self.transitions.get(self.requests)
        if callable(transition):
            transition(self)
        elif isinstance(transition, dict):
            for key, value in transition.items():
                setattr(self, key, value)

        kind = endpoint_kind(resource)
        version = self.data[self.generation]
        policy = self.data['scopes'][self.scope]
        meta = {
            'generation': self.generation,
            'scope_version': policy['version'],
            'visible_objects': policy['objects'],
            'listing_complete': policy['listing_complete'],
            'kind': kind,
        }
        if resource == '/namespaces':
            rows = version['namespaces']
        elif resource == '/datasets':
            rows = [row for row in version['objects'] if row['id'] in policy['objects']]
        else:
            pieces = resource.strip('/').split('/')
            if len(pieces) != 3 or pieces[0] != 'datasets' or pieces[2] not in ('fields', 'dependencies'):
                return 404, {**meta, 'error': '资源不存在'}
            identity = pieces[1]
            if identity not in policy['objects']:
                return 403, {**meta, 'error': '当前账号不可见'}
            if identity not in version[pieces[2]]:
                return 404, {**meta, 'error': '目录代际中不存在'}
            rows = version[pieces[2]][identity]
        if cursor < 0 or cursor > len(rows):
            return 400, {**meta, 'error': '无效游标'}
        end = min(cursor + 2, len(rows))
        return 200, {
            **meta,
            'items': rows[cursor:end],
            'next_cursor': end if end < len(rows) else None,
            'terminal': end == len(rows),
        }


def dispatch(catalog, raw_path):
    '''HTTP 处理器与本地采集器共用的路由，保证两者看到同一响应语义。'''
    parsed = urlsplit(raw_path)
    try:
        cursor = int(parse_qs(parsed.query).get('cursor', ['0'])[0])
    except ValueError:
        return 400, {'error': '无效游标'}
    return catalog.query(parsed.path, cursor)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        with self.server.catalog_lock:
            status, result = dispatch(self.server.catalog, self.path)
        body = json.dumps(result, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def serve(catalog=None):
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.catalog = catalog or Catalog()
    server.catalog_lock = threading.Lock()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}'
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def fetch_page(base, path):
    try:
        response = urlopen(base + path, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read()
        return response.status, raw, json.loads(raw)


class HttpTransport:
    '''真实本地 HTTP 读取；保留 403/404 等非成功响应。'''

    def __init__(self, base):
        self.base = base

    def fetch(self, path):
        return fetch_page(self.base, path)


class LocalTransport:
    '''进程内读取同一目录服务，不做网络往返，响应仍按原文保存。'''

    def __init__(self, catalog):
        self.catalog = catalog

    def fetch(self, path):
        status, page = dispatch(self.catalog, path)
        raw = json.dumps(page, ensure_ascii=False).encode()
        return status, raw, page
