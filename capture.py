"""来源目录的权限感知元数据采集。

三类独立判断贯穿全程：

* 观察状态：某个端点在这条响应里返回了什么（200/403/404/部分分页）。
* 证据充分性：目录代际与权限范围版本是否贯穿整次扫描，清单是否完整。
* 形式目录：只有代际与可见范围都足以支持结论时才接受新的图快照。

403 表示“当前账号不可见”，404 表示“该代际中不存在”，空列表是完整
清单的一部分而不是删除证据；三者在证据里分开保留。
"""

import json
from datetime import datetime, timezone

INCOMPLETE = 'incomplete'
INTERRUPTED = 'interrupted'

FIELD = 'field-list'
DEPENDENCY = 'dependency-list'
NAMESPACE = 'namespace-list'
DATASET = 'dataset-list'
PROBE = 'probe'

KINDS = (NAMESPACE, DATASET, FIELD, DEPENDENCY, PROBE)


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


class Evidence:
    """一个端点的全部 HTTP 响应，连同原文摘要。

    分页响应作为一个证据对象保存；任何一页失败都让 complete 保持
    False，失败页本身仍保留在 parts 中。
    """

    def __init__(self, kind, subject, group, generation, scope_version):
        self.kind = kind
        self.subject = subject
        self.group = group
        self.generation = generation
        self.scope_version = scope_version
        self.parts = []
        self.items = []
        self.policy = {}
        self.complete = False
        self.error = None
        self.resource = None

    @property
    def digests(self):
        return [part['digest'] for part in self.parts]

    @property
    def statuses(self):
        return [part['status'] for part in self.parts]

    def summary(self):
        return {
            'kind': self.kind,
            'subject': self.subject,
            'generation': self.generation,
            'scope_version': self.scope_version,
            'complete': self.complete,
            'error': self.error,
            'policy': self.policy,
            'items': self.items,
            'pages': [
                {
                    'resource': part['resource'],
                    'source': part['source'],
                    'cursor': part['cursor'],
                    'status': part['status'],
                    'digest': part['digest'],
                    'terminal': part.get('terminal'),
                    'next_cursor': part.get('next_cursor'),
                }
                for part in self.parts
            ],
        }

    @classmethod
    def from_summary(cls, summary):
        evidence = cls(summary['kind'], summary.get('subject'), None,
                       summary.get('generation'), summary.get('scope_version'))
        evidence.complete = bool(summary.get('complete'))
        evidence.error = summary.get('error')
        evidence.policy = summary.get('policy') or {}
        evidence.items = summary.get('items') or []
        evidence.resource = (summary.get('pages') or [{}])[0].get('resource')
        evidence.parts = [
            {
                'resource': page.get('resource'),
                'source': page.get('source'),
                'cursor': page.get('cursor', 0),
                'status': page.get('status'),
                'digest': page.get('digest'),
                'terminal': page.get('terminal'),
                'next_cursor': page.get('next_cursor'),
            }
            for page in summary.get('pages') or []
        ]
        return evidence

    def ref(self):
        """形式目录引用的精简证据：摘要可直接用 RawStore.read 复查。"""
        return {
            'kind': self.kind,
            'subject': self.subject,
            'generation': self.generation,
            'scope_version': self.scope_version,
            'complete': self.complete,
            'sources': [
                {
                    'source': part['source'],
                    'status': part['status'],
                    'digest': part['digest'],
                }
                for part in self.parts
            ],
        }


class CatalogCapture:
    def __init__(self, raw_store, transport=None, catalog_store=None,
                 clock=_utc_now, max_requests=200):
        self.raw = raw_store
        self.transport = transport
        self.catalog_store = catalog_store
        self.clock = clock
        self.max_requests = max_requests
        self._evidence = {kind: [] for kind in KINDS}
        self.snapshots = []
        self.deletions = []
        self.timeline = []
        self.scan_records = []
        self.scan_count = 0
        self.last_accept_signature = None
        self.last_accept_seq = -1
        self.catalog = {
            'status': 'unestablished',
            'reason': '尚未在完整的目录代际与可见范围内完成扫描',
            'objects': {},
            'namespaces': [],
            'edges': [],
            'references': [],
            'cycles': [],
            'evidence': {},
        }
        if catalog_store is not None:
            self._load()

    # ------------------------------------------------------------------
    # 读取与证据登记
    # ------------------------------------------------------------------
    def scan(self, transport=None, reuse=True, label=None):
        """扫描一轮来源目录并尝试接受快照。

        reuse=True 时，同一目录代际和权限范围版本下已经完整取得的清单、
        字段或依赖证据会直接复用；扫描失败后换用新的传输继续，即续采。
        """
        if transport is not None:
            self.transport = transport
        if self.transport is None:
            raise ValueError('扫描需要来源传输')
        self.scan_count += 1
        scan = {
            'number': self.scan_count,
            'label': label or f'scan-{self.scan_count}',
            'group': f'scan-{self.scan_count}',
            'generation': None,
            'scope_version': None,
            'requests': 0,
            'reuse': bool(reuse),
            'reused': [],
            'items': {},
            'probes': {},
            'notes': [],
            'broken': None,
            'decision': {},
        }

        namespaces = self._collect_or_reuse(scan, '/namespaces', NAMESPACE)
        datasets = self._collect_or_reuse(scan, '/datasets', DATASET)
        scan['namespaces_evidence'] = namespaces
        scan['datasets_evidence'] = datasets

        if not scan['broken'] and datasets is not None:
            visible = [row['id'] for row in datasets.items]
            scan['visible_ids'] = visible
            for row in datasets.items:
                self._event(scan, row['id'], 'visible', datasets.ref())
            for identity in visible:
                self._resolve_item(scan, FIELD, identity,
                                   f'/datasets/{identity}/fields')
                if scan['broken']:
                    break
                self._resolve_item(scan, DEPENDENCY, identity,
                                   f'/datasets/{identity}/dependencies')
                if scan['broken']:
                    break
            if scan['broken']:
                # 中断后尚未走到解析的可见对象应显式标记，不能默认为完整。
                for identity in visible:
                    entry = scan['items'].setdefault(identity, {})
                    for kind in (FIELD, DEPENDENCY):
                        entry.setdefault(kind, {'result': INTERRUPTED, 'evidence': None})
            # 上次正式目录已确认、这次清单里看不见的对象：只做端点探针，
            # 绝不由“看不见”直接推断删除。403 是隐藏，404 才是该代际不存在。
            if not scan['broken']:
                for identity in sorted(self._previous_confirmed_ids() - set(visible)):
                    self._probe(scan, identity)
                    if scan['broken']:
                        break

        self._decide(scan)
        self._finish_scan(scan)
        return scan

    def _fetch(self, scan, resource, cursor=0):
        if scan['broken']:
            return None
        if scan['requests'] >= self.max_requests:
            scan['broken'] = {
                'kind': INCOMPLETE,
                'detail': f'本轮请求数达到上限 {self.max_requests}，仍缺少证据',
            }
            return None
        scan['requests'] += 1
        source = f'GET {resource}' + (f'?cursor={cursor}' if cursor else '')
        path = resource + (f'?cursor={cursor}' if cursor else '')
        try:
            status, raw, page = self.transport.fetch(path)
        except Exception as error:  # 保留已取得的响应，后续扫描可续采
            scan['broken'] = {
                'kind': INCOMPLETE,
                'detail': f'{type(error).__name__}: {error}',
            }
            return None
        observed_at = self.clock()
        if isinstance(page, dict):
            metadata = {
                'group': scan['group'],
                'status': status,
                'generation': page.get('generation'),
                'scope_version': page.get('scope_version'),
                'terminal': page.get('terminal'),
                'next_cursor': page.get('next_cursor'),
                'kind': page.get('kind'),
            }
        else:
            metadata = {'group': scan['group'], 'status': status, 'malformed': True}
        digest = self.raw.save(source, raw, metadata, observed_at)
        if not isinstance(page, dict):
            scan['broken'] = {
                'kind': 'invalid_evidence',
                'detail': f'{source} 的响应不是 JSON 对象',
            }
            return None

        generation = page.get('generation')
        scope_version = page.get('scope_version')
        if not generation or not scope_version:
            scan['broken'] = {
                'kind': 'invalid_evidence',
                'detail': f'{source} 缺少目录代际或权限范围版本',
            }
            return None

        if scan['generation'] is None:
            scan['generation'] = generation
            scan['scope_version'] = scope_version
        elif generation != scan['generation']:
            scan['broken'] = {
                'kind': 'generation_changed',
                'detail': f'{source} 返回代际 {generation}，本轮锚定为 {scan["generation"]}',
            }
        elif scope_version != scan['scope_version']:
            scan['broken'] = {
                'kind': 'scope_changed',
                'detail': f'{source} 返回权限范围 {scope_version}，本轮锚定为 {scan["scope_version"]}',
            }

        return {
            'resource': resource,
            'cursor': cursor,
            'source': source,
            'status': status,
            'digest': digest,
            'page': page,
            'terminal': page.get('terminal'),
            'next_cursor': page.get('next_cursor'),
        }

    def _collect(self, scan, resource, kind, subject=None):
        evidence = Evidence(kind, subject, scan['group'],
                            scan['generation'], scan['scope_version'])
        evidence.resource = resource
        cursor = 0
        while True:
            part = self._fetch(scan, resource, cursor)
            if part is None:
                break
            evidence.parts.append(part)
            if part.get('generation') and part['generation'] != scan['generation']:
                evidence.generation = part['generation']
            if scan['broken']:
                break
            page = part['page']
            if kind in (NAMESPACE, DATASET, FIELD, DEPENDENCY):
                evidence.policy = {
                    'visible_objects': page.get('visible_objects'),
                    'listing_complete': page.get('listing_complete'),
                }
            if part['status'] != 200:
                evidence.error = f'HTTP {part["status"]}'
                break
            items = page.get('items')
            if not isinstance(items, list):
                scan['broken'] = {
                    'kind': 'invalid_evidence',
                    'detail': f'{part["source"]} 缺少 items 列表',
                }
                evidence.error = 'invalid_items'
                break
            if not self._valid_items(kind, items):
                scan['broken'] = {
                    'kind': 'invalid_evidence',
                    'detail': f'{part["source"]} 的 items 结构不符合端点契约',
                }
                evidence.error = 'invalid_items'
                break
            evidence.items.extend(items)
            if page.get('terminal') is True and page.get('next_cursor') is None:
                evidence.complete = True
                break
            next_cursor = page.get('next_cursor')
            if not isinstance(next_cursor, int) or next_cursor <= cursor:
                scan['broken'] = {
                    'kind': INCOMPLETE,
                    'detail': f'{part["source"]} 未给出可前进的游标',
                }
                break
            cursor = next_cursor
        self._store_evidence(evidence)
        self._evidence[kind].append(evidence)
        return evidence

    @staticmethod
    def _valid_items(kind, items):
        if kind == DEPENDENCY:
            return all(isinstance(row, str) and row for row in items)
        return all(isinstance(row, dict) and row.get('id') for row in items)

    def _store_evidence(self, evidence):
        if self.catalog_store is not None and evidence.parts:
            self.catalog_store.add_evidence(evidence.summary())

    def _find_complete(self, kind, subject, generation, scope_version):
        if not generation or not scope_version:
            return None
        for evidence in reversed(self._evidence[kind]):
            if (evidence.complete
                    and evidence.generation == generation
                    and evidence.scope_version == scope_version
                    and evidence.subject == subject):
                return evidence
        return None

    def _find_probe(self, subject, generation, scope_version):
        for evidence in reversed(self._evidence[PROBE]):
            if (evidence.parts
                    and evidence.generation == generation
                    and evidence.scope_version == scope_version
                    and evidence.subject == subject):
                return evidence
        return None

    def _collect_or_reuse(self, scan, resource, kind, subject=None):
        if scan['broken']:
            return None
        if scan['reuse']:
            existing = self._find_complete(kind, subject,
                                           scan['generation'], scan['scope_version'])
            if existing is not None:
                scan['reused'].append(existing.ref())
                return existing
        return self._collect(scan, resource, kind, subject)

    def _resolve_item(self, scan, kind, subject, resource):
        scan['items'].setdefault(subject, {})
        if scan['broken']:
            scan['items'][subject][kind] = {'result': INTERRUPTED, 'evidence': None}
            return
        if scan['reuse']:
            existing = self._find_complete(kind, subject,
                                           scan['generation'], scan['scope_version'])
            if existing is not None:
                scan['reused'].append(existing.ref())
                scan['items'][subject][kind] = {'result': 'complete', 'evidence': existing.ref()}
                return
        evidence = self._collect(scan, resource, kind, subject)
        if evidence is None or scan['broken']:
            result = INTERRUPTED
        elif evidence.complete:
            result = 'complete'
        elif evidence.statuses and 403 in evidence.statuses:
            result = 'inaccessible'
        elif evidence.statuses and 404 in evidence.statuses:
            result = 'absent_in_generation'
        elif evidence.error == 'HTTP 400':
            result = 'invalid_request'
        else:
            result = INCOMPLETE
        scan['items'][subject][kind] = {'result': result, 'evidence': evidence.ref()}

    def _probe(self, scan, subject):
        evidence = None
        if scan['reuse']:
            evidence = self._find_probe(subject, scan['generation'], scan['scope_version'])
            if evidence is not None:
                scan['reused'].append(evidence.ref())
        if evidence is None:
            evidence = self._collect(
                scan, f'/datasets/{subject}/dependencies', PROBE, subject)
        if evidence is None or scan['broken']:
            result = INTERRUPTED
        elif 403 in evidence.statuses:
            result = 'hidden'
            self._event(scan, subject, 'forbidden', evidence.ref())
        elif 404 in evidence.statuses:
            result = 'absent'
            self._event(scan, subject, 'absent', evidence.ref())
        elif evidence.complete:
            result = 'present_but_unlisted'
            self._event(scan, subject, 'visible', evidence.ref())
        else:
            result = INCOMPLETE
        scan['probes'][subject] = {'result': result, 'evidence': evidence.ref()}

    # ------------------------------------------------------------------
    # 快照接受
    # ------------------------------------------------------------------
    def _previous_confirmed_ids(self):
        if self.catalog.get('status') != 'accepted':
            return set()
        return set(self.catalog.get('objects', {}))

    def _decide(self, scan):
        decision = {'accepted': False, 'reason': None, 'detail': None}
        scan['decision'] = decision
        if scan['broken']:
            decision['reason'] = scan['broken']['kind']
            decision['detail'] = scan['broken']['detail']
            decision['meaning'] = '本轮证据未贯穿同一代际与可见范围，不更新正式目录'
            self._note(scan, '扫描在变化或不完整证据处停止，未接受快照')
            return

        namespaces = scan.get('namespaces_evidence')
        datasets = scan.get('datasets_evidence')
        if namespaces is None or not namespaces.complete:
            decision['reason'] = 'namespace_listing_incomplete'
            decision['detail'] = '命名空间清单没有完整终页证据'
            self._note(scan, decision['detail'])
            return
        if datasets is None or not datasets.complete:
            decision['reason'] = 'dataset_listing_incomplete'
            decision['detail'] = '数据集清单没有完整终页证据'
            self._note(scan, decision['detail'])
            return

        policy = datasets.policy or {}
        visible_ids = [row['id'] for row in datasets.items]
        if not policy.get('listing_complete'):
            decision['reason'] = 'visibility_scope_incomplete'
            decision['detail'] = (
                f'权限范围 {scan["scope_version"]} 自述清单不完整；'
                '可见范围不足以支持“看不见即删除”的结论')
            self._summarize_candidates(scan, decision, visible_ids)
            self._note(scan, decision['detail'])
            return

        missing_items = [
            identity for identity in visible_ids
            if scan['items'].get(identity, {}).get(FIELD, {}).get('result') != 'complete'
            or scan['items'].get(identity, {}).get(DEPENDENCY, {}).get('result') != 'complete'
        ]
        if missing_items:
            decision['reason'] = 'object_evidence_incomplete'
            decision['detail'] = '以下可见对象的字段或依赖没有完整证据：' + ','.join(missing_items)
            self._note(scan, decision['detail'])
            return

        previous = self._previous_confirmed_ids()
        disappearing = sorted(previous - set(visible_ids))
        candidates = []
        for identity in disappearing:
            result = scan['probes'].get(identity, {}).get('result')
            if result == 'absent':
                candidates.append(identity)
            else:
                decision['reason'] = 'visibility_limited_removal'
                decision['detail'] = (
                    f'对象 {identity} 在此前的正式目录中已确认存在，本轮清单未见；'
                    f'端点探针结果为 {result}；没有 404 证据就不能推断删除')
                decision['probes'] = {
                    key: entry.get('result') for key, entry in scan['probes'].items()
                }
                self._note(scan, decision['detail'])
                return

        used = self._evidence_used(scan, visible_ids, candidates)
        signature = (
            scan['generation'],
            scan['scope_version'],
            tuple(sorted(digest for evidence in used for digest in evidence.digests)),
        )
        if signature == self.last_accept_signature:
            decision['accepted'] = True
            decision['revalidated'] = True
            decision['reason'] = 'no_new_evidence'
            decision['detail'] = '代际、权限范围与证据摘要均与上次接受相同，正式目录保持不变'
            self._note(scan, decision['detail'])
            return

        snapshot = self._build_snapshot(scan, namespaces, datasets, visible_ids)
        self._record_deletions(scan, candidates)
        self.snapshots.append(snapshot)
        if self.catalog_store is not None:
            self.catalog_store.add_snapshot(snapshot, signature)
        self.last_accept_signature = signature
        self.last_accept_seq = scan['number']
        if self.catalog_store is not None:
            self.catalog_store.set_state('last_accept_signature', json.dumps(signature))
            self.catalog_store.set_state('last_accept_seq', str(scan['number']))
        self.catalog = {
            'status': 'accepted',
            'generation': snapshot['generation'],
            'scope_version': snapshot['scope_version'],
            'objects': snapshot['datasets'],
            'namespaces': snapshot['namespaces'],
            'edges': snapshot['edges'],
            'references': snapshot['references'],
            'cycles': snapshot['cycles'],
            'evidence': snapshot['evidence'],
            'accepted_at': snapshot['accepted_at'],
            'snapshot_index': len(self.snapshots) - 1,
        }
        decision['accepted'] = True
        decision['snapshot_index'] = len(self.snapshots) - 1
        decision['deletions'] = candidates
        self._note(scan, f'接受快照：{scan["generation"]} / {scan["scope_version"]}')

    def _evidence_used(self, scan, visible_ids, deletions):
        used = []
        for key in ('namespaces_evidence', 'datasets_evidence'):
            evidence = scan.get(key)
            if evidence is not None:
                used.append(evidence)
        for identity in visible_ids:
            item = scan['items'].get(identity, {})
            for kind in (FIELD, DEPENDENCY):
                evidence = self._find_evidence_by_ref(item.get(kind, {}).get('evidence'))
                if evidence is not None:
                    used.append(evidence)
        for identity in deletions:
            evidence = self._find_evidence_by_ref(
                scan['probes'].get(identity, {}).get('evidence'))
            if evidence is not None:
                used.append(evidence)
        return used

    def _find_evidence_by_ref(self, ref):
        if not ref:
            return None
        wanted = [source['digest'] for source in ref['sources']]
        for items in self._evidence.values():
            for evidence in items:
                if (evidence.kind == ref['kind']
                        and evidence.generation == ref['generation']
                        and evidence.scope_version == ref['scope_version']
                        and evidence.subject == ref['subject']
                        and evidence.digests == wanted):
                    return evidence
        return None

    def _build_snapshot(self, scan, namespaces, datasets, visible_ids):
        fields = {}
        edges = []
        object_evidence = {}
        for identity in visible_ids:
            field_evidence = self._find_complete(
                FIELD, identity, scan['generation'], scan['scope_version'])
            fields[identity] = [
                {'id': row['id'], 'name': row.get('name'), 'type': row.get('type')}
                for row in (field_evidence.items if field_evidence else [])
            ]
            dependency_evidence = self._find_complete(
                DEPENDENCY, identity, scan['generation'], scan['scope_version'])
            targets = []
            for row in (dependency_evidence.items if dependency_evidence else []):
                if row not in targets:
                    targets.append(row)
            for target in targets:
                state = 'resolved' if target in visible_ids else 'unresolved_reference'
                edges.append({
                    'from': identity,
                    'to': target,
                    'state': state,
                    'evidence': dependency_evidence.ref(),
                })
            object_evidence[identity] = {
                'fields': field_evidence.ref() if field_evidence else None,
                'dependencies': dependency_evidence.ref() if dependency_evidence else None,
            }
        references = sorted({
            edge['to'] for edge in edges if edge['state'] == 'unresolved_reference'
        })
        cycles = self._cycle_nodes(edges)
        return {
            'generation': scan['generation'],
            'scope_version': scan['scope_version'],
            'scope': {
                'visible_objects': sorted(visible_ids),
                'listing_complete': bool((datasets.policy or {}).get('listing_complete')),
            },
            'namespaces': [
                {'id': row['id'], 'name': row.get('name')}
                for row in namespaces.items
            ],
            'datasets': {
                identity: {
                    'name': next(
                        (row.get('name') for row in datasets.items if row['id'] == identity),
                        None),
                    'fields': fields.get(identity, []),
                }
                for identity in visible_ids
            },
            'edges': edges,
            'references': references,
            'cycles': sorted(cycles),
            'evidence': {
                'namespaces': namespaces.ref(),
                'datasets': datasets.ref(),
                'objects': object_evidence,
            },
            'accepted_at': self.clock(),
            'accepted_scan': scan['label'],
        }

    @staticmethod
    def _cycle_nodes(edges):
        adjacency = {}
        for edge in edges:
            if edge['state'] == 'resolved':
                adjacency.setdefault(edge['from'], []).append(edge['to'])
        cyclic = set()
        for start in adjacency:
            stack = list(adjacency.get(start, []))
            seen = set()
            while stack:  # 显式栈：依赖环不会导致递归失控
                node = stack.pop()
                if node == start:
                    cyclic.add(start)
                    break
                if node in seen:
                    continue
                seen.add(node)
                stack.extend(adjacency.get(node, []))
        return cyclic

    def _record_deletions(self, scan, candidates):
        previous_snapshot = self.snapshots[-1] if self.snapshots else None
        for identity in candidates:
            probe = scan['probes'][identity]
            previous_edges = []
            previous_fields = []
            if previous_snapshot is not None:
                previous_edges = [
                    edge for edge in previous_snapshot['edges']
                    if edge['from'] == identity or edge['to'] == identity
                ]
                previous_fields = (
                    previous_snapshot['datasets'].get(identity, {}).get('fields', []))
            entry = {
                'object_id': identity,
                'state': 'confirmed_deleted',
                'generation': scan['generation'],
                'scope_version': scan['scope_version'],
                'meaning': (
                    '对象端点在该代际与权限范围下返回 404；'
                    '403 只表示当前账号不可见，因此这不是权限造成的缺页'),
                'probe_result': probe['result'],
                'evidence': probe['evidence'],
                'previous_edges': previous_edges,
                'previous_fields': previous_fields,
                'detected_scan': scan['label'],
            }
            self.deletions.append(entry)
            if self.catalog_store is not None:
                self.catalog_store.add_deletion(entry)

    def _event(self, scan, object_id, observation, evidence_ref=None):
        if scan['broken']:
            return
        entry = {
            'scan': scan['number'],
            'scan_label': scan['label'],
            'generation': scan['generation'],
            'scope_version': scan['scope_version'],
            'object_id': object_id,
            'observation': observation,
            'evidence': evidence_ref,
            'timeline_seq': len(self.timeline),
        }
        self.timeline.append(entry)
        if self.catalog_store is not None:
            self.catalog_store.add_timeline(entry)

    def _note(self, scan, message):
        scan['notes'].append(message)

    def _summarize_candidates(self, scan, decision, visible_ids):
        previous = self._previous_confirmed_ids()
        candidates = sorted(previous - set(visible_ids)) if previous else []
        if candidates:
            decision['detail'] += (
                '；旧权限下已确认但本轮不可见的对象：' + ','.join(candidates)
                + '（未推断为删除）')
        decision['probes'] = {
            key: entry.get('result') for key, entry in scan['probes'].items()
        }

    def _finish_scan(self, scan):
        for key in ('namespaces_evidence', 'datasets_evidence'):
            evidence = scan.pop(key, None)
            if evidence is not None:
                scan.setdefault('listing_evidence', {})[key] = evidence.ref()
        record = {
            'number': scan['number'],
            'label': scan['label'],
            'generation': scan['generation'],
            'scope_version': scan['scope_version'],
            'requests': scan['requests'],
            'broken': scan['broken'],
            'decision': scan['decision'],
            'visible_ids': scan.get('visible_ids', []),
            'items': {
                subject: {
                    kind: {'result': entry.get('result'), 'evidence': entry.get('evidence')}
                    for kind, entry in entries.items()
                }
                for subject, entries in scan['items'].items()
            },
            'probes': scan['probes'],
            'reused': scan['reused'],
            'notes': scan['notes'],
            'listing_evidence': scan.get('listing_evidence', {}),
        }
        self.scan_records.append(record)
        if self.catalog_store is not None:
            self.catalog_store.add_scan(record)
            self.catalog_store.set_state('scan_count', str(self.scan_count))

    # ------------------------------------------------------------------
    # 查询接口
    # ------------------------------------------------------------------
    def snapshot(self):
        if not self.snapshots:
            return {
                'status': self.catalog.get('status'),
                'reason': self.catalog.get('reason'),
                'objects': [],
                'edges': [],
            }
        return dict(self.snapshots[-1])

    def answer(self, object_id):
        """解释某对象为什么仍在、为什么被隐藏、为什么确认消失。"""
        in_catalog = object_id in self.catalog.get('objects', {})
        event = self._latest_event(object_id)
        deletion = self._latest_deletion(object_id)
        evidence = []
        explanation = []
        state = 'unobserved'

        if event is not None and event['observation'] == 'forbidden':
            state = 'hidden'
            explanation.append(
                f'{event["generation"]} / {event["scope_version"]} 下该对象端点返回 403，'
                '只说明当前账号可见范围不包含它')
            if in_catalog:
                explanation.append(
                    '正式目录仍保留上一次证据充分时接受的记录，未因看不见而删除')
            else:
                explanation.append('正式目录没有该对象；可见范围不足以确认其后新增')
            evidence.append(event.get('evidence'))
        elif event is not None and event['observation'] == 'absent':
            if deletion is not None:
                state = 'confirmed_deleted'
                explanation.append(deletion['meaning'])
                explanation.append(
                    f'删除结论依据 {deletion["generation"]} / {deletion["scope_version"]} '
                    '下返回 404 的对象端点响应，而非清单缺页')
                evidence.append(deletion.get('evidence'))
            else:
                state = 'absent_in_generation'
                explanation.append(
                    f'{event["generation"]} / {event["scope_version"]} 下端点返回 404，'
                    '该对象在此代际不存在')
                if in_catalog:
                    explanation.append(
                        '本轮扫描未满足更新正式目录的条件，因此正式目录保留此前快照')
                evidence.append(event.get('evidence'))
        elif event is not None and event['observation'] == 'visible':
            if in_catalog:
                state = 'visible'
                snapshot = self.snapshots[-1]
                entry = self.catalog['objects'][object_id]
                explanation.append(
                    f'对象在 {snapshot["generation"]} / {snapshot["scope_version"]} '
                    '的正式目录快照中可见')
                explanation.append(
                    '字段以字段 ID 对齐，更名或重排不会被当成删除再新增')
                object_evidence = snapshot['evidence']['objects'].get(object_id, {})
                for kind in ('fields', 'dependencies'):
                    if object_evidence.get(kind):
                        evidence.append(object_evidence[kind])
                evidence.append(snapshot['evidence']['datasets'])
            else:
                state = 'observed_not_in_catalog'
                explanation.append(
                    f'{event["generation"]} / {event["scope_version"]} 的清单中可见该对象，'
                    '但正式目录尚未接受快照：可见范围或证据完整性不足以支持结论')
                evidence.append(event.get('evidence'))
        elif in_catalog:
            state = 'visible'
            snapshot = self.snapshots[-1]
            explanation.append('正式目录快照中可见该对象，尚无更新的端点观察')
            object_evidence = snapshot['evidence']['objects'].get(object_id, {})
            for kind in ('fields', 'dependencies'):
                if object_evidence.get(kind):
                    evidence.append(object_evidence[kind])

        if state in ('visible', 'hidden', 'absent_in_generation') and not explanation:
            state = 'unobserved'

        if state == 'unobserved' and object_id in self.catalog.get('objects', {}):
            snapshot = self.snapshots[-1] if self.snapshots else None
            if snapshot is not None:
                state = 'visible'
                explanation.append('正式目录快照中可见该对象，尚无更新的端点观察')

        if state == 'unobserved' and object_id in self.catalog.get('references', []):
            state = 'external_reference'
            explanation.append(
                '该标识只作为依赖目标出现，当前可见范围内没有对应数据集；'
                '保留为未解析的外部引用，不假定断边')
            evidence.extend(
                edge['evidence'] for edge in self.catalog.get('edges', [])
                if (edge['to'] == object_id or edge['from'] == object_id)
                and edge.get('evidence'))

        if state == 'unobserved':
            return {
                'object_id': object_id,
                'state': state,
                'summary': '没有足够证据解释该对象；它可能尚未被采集覆盖',
                'dependencies': [],
                'in_cycles': False,
                'evidence': [],
            }

        snapshot = self.snapshots[-1] if self.snapshots else None
        dependencies = []
        in_cycles = False
        if snapshot is not None and state in ('visible', 'external_reference'):
            dependencies = [
                edge for edge in snapshot['edges']
                if edge['from'] == object_id or edge['to'] == object_id
            ]
            in_cycles = object_id in snapshot['cycles']
        if state == 'confirmed_deleted' and deletion is not None:
            dependencies = deletion.get('previous_edges', [])

        result = {
            'object_id': object_id,
            'state': state,
            'summary': '；'.join(explanation),
            'dependencies': dependencies,
            'in_cycles': in_cycles,
            'evidence': [ref for ref in evidence if ref],
        }
        unresolved = self._unresolved_for(object_id)
        if unresolved:
            result['unresolved_endpoints'] = unresolved
            if state == 'visible':
                result['summary'] += (
                    '；仍有端点未查清：' + '、'.join(
                        f'{entry["endpoint"]}={entry["result"]}' for entry in unresolved))
        if state == 'visible':
            result['fields'] = self.catalog['objects'][object_id].get('fields', [])
        if state == 'confirmed_deleted':
            result['fields_last_seen'] = (
                deletion.get('previous_fields', []) if deletion else [])
        if snapshot is not None and state in (
                'visible', 'confirmed_deleted', 'external_reference', 'hidden'):
            result['snapshot_generation'] = snapshot['generation']
            result['snapshot_scope_version'] = snapshot['scope_version']
        return result

    def _latest_event(self, object_id):
        matches = [entry for entry in self.timeline if entry.get('object_id') == object_id]
        return matches[-1] if matches else None

    def _unresolved_for(self, object_id):
        if not self.scan_records:
            return []
        latest = self.scan_records[-1]
        unresolved = []
        for kind, entry in latest['items'].get(object_id, {}).items():
            if entry.get('result') != 'complete':
                unresolved.append({
                    'endpoint': kind,
                    'result': entry.get('result'),
                    'scan': latest['label'],
                    'evidence': entry.get('evidence'),
                })
        probe = latest.get('probes', {}).get(object_id)
        if probe and probe.get('result') not in ('absent', 'hidden'):
            unresolved.append({
                'endpoint': 'probe',
                'result': probe.get('result'),
                'scan': latest['label'],
                'evidence': probe.get('evidence'),
            })
        return unresolved

    def _latest_deletion(self, object_id):
        matches = [entry for entry in self.deletions if entry.get('object_id') == object_id]
        return matches[-1] if matches else None

    def observations(self):
        """列出所有已观察到的端点与状态，不把它们压成一个成功标记。"""
        rows = []
        for evidence in self._all_evidence():
            covered = bool(evidence.subject) and any(
                entry['object_id'] == evidence.subject
                and entry['observation'] in ('visible', 'forbidden', 'absent')
                for entry in self.timeline)
            rows.append({
                'kind': evidence.kind,
                'subject': evidence.subject,
                'generation': evidence.generation,
                'scope_version': evidence.scope_version,
                'complete': evidence.complete,
                'statuses': evidence.statuses,
                'error': evidence.error,
                'explained': covered,
                'evidence': evidence.ref(),
            })
        return rows

    def _all_evidence(self):
        seen = set()
        for items in self._evidence.values():
            for evidence in items:
                if id(evidence) in seen:
                    continue
                seen.add(id(evidence))
                yield evidence

    def raw_observations(self):
        """直接从原文库重建观察清单，进程重启后仍可复查。"""
        rows = []
        for observation in self.raw.observations():
            rows.append({
                'source': observation['source'],
                'digest': observation['digest'],
                'first_seen': observation['first_seen'],
                'last_seen': observation['last_seen'],
                'metadata': json.loads(observation['metadata']),
            })
        return rows

    # ------------------------------------------------------------------
    # 持久状态恢复
    # ------------------------------------------------------------------
    def _load(self):
        store = self.catalog_store
        for summary in store.evidence():
            evidence = Evidence.from_summary(summary)
            self._evidence[evidence.kind].append(evidence)
        stored_snapshots = store.snapshots()
        for payload, signature in stored_snapshots:
            self.snapshots.append(payload)
        if self.snapshots:
            snapshot = self.snapshots[-1]
            self.last_accept_signature = _thaw_signature(stored_snapshots[-1][1])
            self.last_accept_seq = int(store.get_state('last_accept_seq') or '0')
            self.catalog = {
                'status': 'accepted',
                'generation': snapshot['generation'],
                'scope_version': snapshot['scope_version'],
                'objects': snapshot['datasets'],
                'namespaces': snapshot['namespaces'],
                'edges': snapshot['edges'],
                'references': snapshot['references'],
                'cycles': snapshot['cycles'],
                'evidence': snapshot['evidence'],
                'accepted_at': snapshot['accepted_at'],
                'snapshot_index': len(self.snapshots) - 1,
            }
        self.deletions.extend(store.deletions())
        self.timeline.extend(store.timeline())
        self.scan_records.extend(store.scans())
        self.scan_count = int(store.get_state('scan_count') or '0')

    def recent_scans(self, limit=5):
        limit = max(1, limit)
        return self.scan_records[-limit:]

    def deletion_records(self):
        return list(self.deletions)

    def snapshot_history(self):
        return list(self.snapshots)


def _thaw_signature(value):
    return (value[0], value[1], tuple(value[2]))


def fixed_clock(value):
    return lambda: value
