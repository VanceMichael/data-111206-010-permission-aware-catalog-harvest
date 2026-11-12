import argparse
import json
from datetime import datetime, timezone

from cli import cmd_demo_border
from raw_store import RawStore


def demo(store):
    """原有独立单页读取：只观察一页，不推断删除或完整依赖图。"""
    from catalog_source import Catalog, fetch_page, serve

    observed_at = datetime.now(timezone.utc).isoformat()
    catalog = Catalog()
    with serve(catalog) as base:
        status, raw, page = fetch_page(base, '/datasets')
        digest = store.save('catalog:/datasets', raw, {'status': status}, observed_at)
    return {
        '状态码': status,
        '目录代际': page['generation'],
        '权限范围': page['scope_version'],
        '本页对象': page['items'],
        '下一页': page['next_cursor'],
        '原文摘要': digest,
        '说明': '仅单页，不推断删除或完整依赖图',
    }


def main():
    parser = argparse.ArgumentParser(description='本地原文采集演示')
    parser.add_argument('command', choices=['demo', 'demo-border'])
    parser.add_argument('--output', default='output/raw.sqlite3')
    parser.add_argument('--catalog', default='output/catalog.sqlite3')
    args = parser.parse_args()
    if args.command == 'demo-border':
        cmd_demo_border(args)
        return
    store = RawStore(args.output)
    try:
        result = demo(store)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        store.close()


if __name__ == '__main__':
    main()
