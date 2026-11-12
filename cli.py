"""本地目录服务的命令行入口。

保留独立的单页读取（demo-border 与 demo 中的单页摘要），并增加权限感知
扫描、快照、分类与解释查询。所有状态写入本地输出目录，可直接复查。
"""

import argparse
import json
from datetime import datetime, timezone

from capture import CatalogCapture
from catalog_source import Catalog, LocalTransport, fetch_page, serve
from catalog_store import CatalogStore
from raw_store import RawStore


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def open_runtime(raw_path='output/raw.sqlite3', catalog_path='output/catalog.sqlite3'):
    raw = RawStore(raw_path)
    catalog = CatalogStore(catalog_path)
    return raw, catalog


def classify(capture):
    """按证据含义分类，避免用一张成功状态覆盖所有情况。"""
    latest_events = {}
    for event in capture.timeline:
        latest_events[event['object_id']] = event
    deleted = {entry['object_id']: entry for entry in capture.deletion_records()}
    accepted = capture.catalog.get('status') == 'accepted'
    catalog_ids = set(capture.catalog.get('objects', {}))
    references = set(capture.catalog.get('references', []))
    observed_ids = set(latest_events) | set(deleted) | set(capture.catalog.get('objects', {}))
    observed_ids |= references

    hidden = []
    absent = []
    observed_not_in_catalog = []
    for identity, event in latest_events.items():
        if event['observation'] == 'forbidden':
            hidden.append({
                'object_id': identity,
                'generation': event['generation'],
                'scope_version': event['scope_version'],
                'retained_in_catalog': identity in catalog_ids,
                'evidence': event.get('evidence'),
            })
        elif event['observation'] == 'absent':
            absent.append({
                'object_id': identity,
                'generation': event['generation'],
                'scope_version': event['scope_version'],
                'evidence': event.get('evidence'),
            })
        # 中断的扫描也会留下可见事件；只有实际接受了快照，可见才算正式结论。
        elif (event['observation'] == 'visible' and identity not in catalog_ids
                and not accepted):
            observed_not_in_catalog.append({
                'object_id': identity,
                'generation': event['generation'],
                'scope_version': event['scope_version'],
                'meaning': '已观察到，但正式目录未接受该观察：证据或可见范围不足',
                'evidence': event.get('evidence'),
            })

    latest_scan = capture.recent_scans(1)[0] if capture.recent_scans(1) else None
    unresolved_endpoints = []
    if latest_scan is not None:
        for subject, kinds in latest_scan['items'].items():
            for kind, entry in kinds.items():
                if entry.get('result') != 'complete':
                    unresolved_endpoints.append({
                        'object_id': subject,
                        'endpoint': kind,
                        'result': entry.get('result'),
                        'scan': latest_scan['label'],
                        'evidence': entry.get('evidence'),
                    })
        for subject, entry in latest_scan['probes'].items():
            if entry.get('result') not in ('absent', 'hidden'):
                unresolved_endpoints.append({
                    'object_id': subject,
                    'endpoint': 'probe',
                    'result': entry.get('result'),
                    'scan': latest_scan['label'],
                    'evidence': entry.get('evidence'),
                })

    return {
        'catalog_status': capture.catalog.get('status'),
        'generation': capture.catalog.get('generation'),
        'scope_version': capture.catalog.get('scope_version'),
        'observed': sorted(observed_ids),
        'formally_visible': sorted(catalog_ids),
        'observed_hidden': hidden,
        'observed_absent': absent,
        'observed_not_in_catalog': observed_not_in_catalog,
        'confirmed_deleted': [
            {
                'object_id': identity,
                'generation': entry['generation'],
                'scope_version': entry['scope_version'],
                'probe_result': entry['probe_result'],
                'evidence': entry['evidence'],
            }
            for identity, entry in deleted.items()
        ],
        'external_references': sorted(references),
        'unresolved_endpoints': unresolved_endpoints,
        'notes': [] if accepted else [
            '正式目录尚未因证据充分而更新；观察结果仍保留在原文库与观察清单中'],
    }


def scan_summary(scan):
    return {
        'scan': scan['label'],
        'generation': scan['generation'],
        'scope_version': scan['scope_version'],
        'requests': scan['requests'],
        'reused_evidence': len(scan['reused']),
        'stopped': scan['broken'],
        'decision': scan['decision'],
        'probes': {
            key: value.get('result') for key, value in scan['probes'].items()
        },
        'notes': scan['notes'],
    }


def capture_once(raw, catalog_store, label=None, transport=None, reuse=True):
    catalog = Catalog()
    capture = CatalogCapture(raw, transport or LocalTransport(catalog),
                             catalog_store=catalog_store)
    scan = capture.scan(label=label, reuse=reuse)
    return catalog, capture, scan


def cmd_demo(args):
    raw, catalog_store = open_runtime(args.output, args.catalog)
    catalog = Catalog()
    capture = CatalogCapture(raw, LocalTransport(catalog), catalog_store=catalog_store,
                             clock=_utc_now)
    steps = []

    scan1 = capture.scan(label='wide-g1')
    steps.append({'step': 'wide-g1', **scan_summary(scan1)})
    steps.append({
        'step': 'wide-g1-graph',
        'cycles': capture.catalog.get('cycles'),
        'external_references': capture.catalog.get('references'),
        'view_market_dependencies': [
            {'to': edge['to'], 'state': edge['state']}
            for edge in capture.catalog.get('edges', [])
            if edge['from'] == 'view-market'
        ],
        'view_network_in_cycle': capture.answer('view-network')['in_cycles'],
    })

    catalog.scope = 'limited'
    scan2 = capture.scan(label='limited-g1')
    steps.append({'step': 'limited-g1', **scan_summary(scan2)})
    steps.append({
        'step': 'limited-g1-catalog-unchanged',
        'catalog_generation': capture.catalog.get('generation'),
        'catalog_scope_version': capture.catalog.get('scope_version'),
        'visible_objects': sorted(capture.catalog.get('objects', {})),
        'view_network_state': capture.answer('view-network')['state'],
    })

    catalog.scope = 'wide'
    scan3 = capture.scan(label='wide-g1-reopened')
    steps.append({'step': 'wide-g1-reopened', **scan_summary(scan3)})
    steps.append({
        'step': 'wide-g1-reopened-answers',
        'view_network': capture.answer('view-network')['state'],
        'resolved_items': {
            identity: [entry.get('result') for entry in kinds.values()]
            for identity, kinds in scan3['items'].items()
        },
    })

    hook_state = {'count': 0}

    def change_generation_mid_scan(source, resource):
        hook_state['count'] += 1
        if hook_state['count'] == 3:
            source.generation = 'g2'

    catalog.before_query = change_generation_mid_scan
    scan4 = capture.scan(label='mid-scan-generation-change', reuse=False)
    catalog.before_query = None
    steps.append({'step': 'mid-scan-generation-change', **scan_summary(scan4)})
    steps.append({
        'step': 'after-interrupted-scan',
        'catalog_generation': capture.catalog.get('generation'),
        'catalog_scope_version': capture.catalog.get('scope_version'),
    })

    scan5 = capture.scan(label='wide-g2')
    steps.append({'step': 'wide-g2', **scan_summary(scan5)})
    steps.append({
        'step': 'wide-g2-answers',
        'ds_company_fields': capture.answer('ds-company')['fields'],
        'view_network': capture.answer('view-network'),
        'outside_secret': capture.answer('outside-secret'),
        'cycles': capture.catalog.get('cycles'),
    })
    steps.append({
        'step': 'classification',
        'result': classify(capture),
    })

    result = {
        '说明': '同一目录服务上的权限收缩与恢复、字段更名、依赖环和扫描中换代',
        'steps': steps,
        'single_page_reader': single_page_reader(),
        'outputs': {'raw': args.output, 'catalog': args.catalog},
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raw.close()
    catalog_store.close()


def single_page_reader():
    """原有单页读取接口：只观察一页，不推断删除或完整依赖图。"""
    from catalog_source import Catalog as Source

    source = Source()
    with serve(source) as base:
        status, raw, page = fetch_page(base, '/datasets')
    return {
        '状态码': status,
        '目录代际': page['generation'],
        '权限范围': page['scope_version'],
        '本页对象': page['items'],
        '下一页': page['next_cursor'],
        '说明': '仅单页，不推断删除或完整依赖图',
    }


def cmd_capture(args):
    raw, catalog_store = open_runtime(args.output, args.catalog)
    _, capture, scan = capture_once(raw, catalog_store, label=args.label,
                                    reuse=not args.no_reuse)
    print(json.dumps(scan_summary(scan), ensure_ascii=False, indent=2))
    raw.close()
    catalog_store.close()


def cmd_snapshot(args):
    raw, catalog_store = open_runtime(args.output, args.catalog)
    capture = CatalogCapture(raw, LocalTransport(Catalog()), catalog_store=catalog_store)
    print(json.dumps(capture.snapshot(), ensure_ascii=False, indent=2))
    raw.close()
    catalog_store.close()


def cmd_explain(args):
    raw, catalog_store = open_runtime(args.output, args.catalog)
    capture = CatalogCapture(raw, LocalTransport(Catalog()), catalog_store=catalog_store)
    print(json.dumps(capture.answer(args.object_id), ensure_ascii=False, indent=2))
    raw.close()
    catalog_store.close()


def cmd_list(args):
    raw, catalog_store = open_runtime(args.output, args.catalog)
    capture = CatalogCapture(raw, LocalTransport(Catalog()), catalog_store=catalog_store)
    result = classify(capture)
    result['scans'] = [
        {
            'scan': record['label'],
            'generation': record['generation'],
            'scope_version': record['scope_version'],
            'broken': record['broken'],
            'decision': record['decision'],
        }
        for record in capture.recent_scans(args.scans)
    ]
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raw.close()
    catalog_store.close()


def cmd_observations(args):
    raw, catalog_store = open_runtime(args.output, args.catalog)
    capture = CatalogCapture(raw, LocalTransport(Catalog()), catalog_store=catalog_store)
    rows = capture.observations()
    if args.raw:
        rows = capture.raw_observations()
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    raw.close()
    catalog_store.close()


def cmd_demo_border(args):
    """原有单页演示：读取并保存一个响应，不扩展为完整目录结论。"""
    raw, catalog_store = open_runtime(args.output, args.catalog)
    observed_at = _utc_now()
    result = single_page_reader()
    with serve(Catalog()) as base:
        status, body, page = fetch_page(base, '/datasets')
    digest = raw.save('catalog:/datasets', body, {'status': status}, observed_at)
    result['原文摘要'] = digest
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raw.close()
    catalog_store.close()


def main():
    parser = argparse.ArgumentParser(description='本地目录服务演示')
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--output', default='output/raw.sqlite3')
    common.add_argument('--catalog', default='output/catalog.sqlite3')

    commands = parser.add_subparsers(dest='command', required=True)

    demo = commands.add_parser('demo', parents=[common],
                               help='权限收缩恢复、字段更名、依赖环与换代演示')
    demo.set_defaults(func=cmd_demo)

    border = commands.add_parser('demo-border', parents=[common],
                                 help='原有的独立单页读取演示')
    border.set_defaults(func=cmd_demo_border)

    capture = commands.add_parser('capture', parents=[common],
                                  help='扫描一轮并尝试更新正式目录')
    capture.add_argument('--label', default=None)
    capture.add_argument('--no-reuse', action='store_true',
                         help='不重用同代际同权限范围的完整证据')
    capture.set_defaults(func=cmd_capture)

    snapshot = commands.add_parser('snapshot', parents=[common],
                                   help='输出当前正式目录快照')
    snapshot.set_defaults(func=cmd_snapshot)

    explain = commands.add_parser('explain', parents=[common],
                                  help='解释对象为何可见、隐藏或确认消失')
    explain.add_argument('object_id')
    explain.set_defaults(func=cmd_explain)

    listing = commands.add_parser('list', parents=[common],
                                  help='按证据含义分类对象与未查清端点')
    listing.add_argument('--scans', type=int, default=5)
    listing.set_defaults(func=cmd_list)

    observations = commands.add_parser('observations', parents=[common],
                                       help='列出已观察端点和状态')
    observations.add_argument('--raw', action='store_true',
                              help='从原文库读取并包含观察时间')
    observations.set_defaults(func=cmd_observations)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
