import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen


class Catalog:
    def __init__(self):
        self.data=json.loads(Path('fixtures/catalog.json').read_text())
        self.generation='g1'
        self.scope='wide'
        self.requests=0
        self.transitions={}

    def query(self,resource,cursor=0):
        self.requests+=1
        if self.requests in self.transitions:
            for key,value in self.transitions[self.requests].items():
                setattr(self,key,value)
        version=self.data[self.generation]
        policy=self.data['scopes'][self.scope]
        meta={'generation':self.generation,'scope_version':policy['version'],'visible_objects':policy['objects'],'listing_complete':policy['listing_complete']}
        if resource=='/namespaces':
            rows=version['namespaces']
        elif resource=='/datasets':
            rows=[row for row in version['objects'] if row['id'] in policy['objects']]
        else:
            pieces=resource.strip('/').split('/')
            if len(pieces)!=3 or pieces[0]!='datasets' or pieces[2] not in ('fields','dependencies'):
                return 404,{**meta,'error':'资源不存在'}
            identity=pieces[1]
            if identity not in policy['objects']:
                return 403,{**meta,'error':'当前账号不可见'}
            if identity not in version[pieces[2]]:
                return 404,{**meta,'error':'目录代际中不存在'}
            rows=version[pieces[2]][identity]
        if cursor<0 or cursor>len(rows):
            return 400,{**meta,'error':'无效游标'}
        end=min(cursor+2,len(rows))
        return 200,{**meta,'items':rows[cursor:end],'next_cursor':end if end<len(rows) else None,'terminal':end==len(rows)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):
        pass

    def do_GET(self):
        parsed=urlsplit(self.path)
        try:
            cursor=int(parse_qs(parsed.query).get('cursor',['0'])[0])
        except ValueError:
            self.send_error(400)
            return
        with self.server.catalog_lock:
            status,result=self.server.catalog.query(parsed.path,cursor)
        body=json.dumps(result,ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def serve(catalog=None):
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    server.catalog=catalog or Catalog()
    server.catalog_lock=threading.Lock()
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}'
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def fetch_page(base,path):
    try:
        response=urlopen(base+path,timeout=5)
    except HTTPError as error:
        response=error
    with response:
        raw=response.read()
        return response.status,raw,json.loads(raw)
