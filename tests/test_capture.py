"""权限感知采集的行为测试。

测试使用本地合成目录和真实 HTTP/本地传输，不访问外部网络。每条断言
都对应一个证据含义：403 不是删除、404 才是该代际不存在、空列表不是
删除、分页未到终页不是完整证据、换代或权限变化不能拼接成一次结论。
"""

import tempfile
import unittest
from pathlib import Path

from capture import CatalogCapture
from catalog_source import Catalog, HttpTransport, LocalTransport, serve
from catalog_store import CatalogStore
from raw_store import RawStore


class CaptureTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        base = Path(self.directory.name)
        self.raw = RawStore(base / 'raw.sqlite3')
        self.catalog_store = CatalogStore(base / 'catalog.sqlite3')
        self.catalog = Catalog()
        self.capture = CatalogCapture(
            self.raw, LocalTransport(self.catalog), catalog_store=self.catalog_store)

    def tearDown(self):
        self.capture = None
        self.raw.close()
        self.catalog_store.close()
        self.directory.cleanup()

    def scan(self, label, transport=None, reuse=True):
        return self.capture.scan(transport=transport, label=label, reuse=reuse)


class WideScanTests(CaptureTestCase):
    def test_full_scan_accepts_complete_graph(self):
        scan = self.scan('wide-g1')
        self.assertTrue(scan['decision']['accepted'], scan)
        snapshot = self.capture.snapshot()
        self.assertEqual(snapshot['generation'], 'g1')
        self.assertEqual(snapshot['scope_version'], 'scope-1')
        self.assertEqual(set(snapshot['datasets']), {'ds-company', 'view-market', 'view-network'})
        self.assertEqual(snapshot['scope']['visible_objects'],
                         ['ds-company', 'view-market', 'view-network'])
        self.assertEqual(len(self.capture.snapshots), 1)

    def test_each_dependency_keeps_its_source_response(self):
        self.scan('wide-g1')
        edges = self.capture.catalog['edges']
        self.assertTrue(edges)
        for edge in edges:
            self.assertTrue(edge['evidence']['sources'], edge)
            self.assertEqual(edge['evidence']['sources'][0]['status'], 200)
            self.assertEqual(edge['evidence']['generation'], 'g1')
            for source in edge['evidence']['sources']:
                self.assertTrue(self.raw.read(source['digest']))

    def test_cycles_are_preserved_and_terminate(self):
        self.scan('wide-g1')
        snapshot = self.capture.snapshot()
        self.assertIn('view-market', snapshot['cycles'])
        self.assertIn('view-network', snapshot['cycles'])
        edge_set = {(edge['from'], edge['to']) for edge in snapshot['edges']}
        self.assertIn(('view-market', 'view-network'), edge_set)
        self.assertIn(('view-network', 'view-market'), edge_set)
        self.assertTrue(self.capture.answer('view-market')['in_cycles'])

    def test_external_reference_stays_unresolved(self):
        self.scan('wide-g1')
        snapshot = self.capture.snapshot()
        self.assertIn('outside-secret', snapshot['references'])
        edge = next(edge for edge in snapshot['edges']
                    if edge['to'] == 'outside-secret')
        self.assertEqual(edge['state'], 'unresolved_reference')
        answer = self.capture.answer('outside-secret')
        self.assertEqual(answer['state'], 'external_reference')
        self.assertTrue(all(edge['to'] != 'outside-secret'
                            for edge in snapshot['edges']
                            if edge['from'] == 'outside-secret'))

    def test_field_identity_survives_rename_and_reorder(self):
        self.scan('wide-g1')
        before = self.capture.answer('ds-company')['fields']
        self.catalog.generation = 'g2'
        scan = self.scan('wide-g2-fields', reuse=False)
        self.assertTrue(scan['decision']['accepted'])
        after = self.capture.answer('ds-company')['fields']
        self.assertEqual({field['id'] for field in before},
                         {field['id'] for field in after})
        self.assertEqual([field['id'] for field in after], ['f-name', 'f-identity'])
        self.assertEqual(
            {field['id']: field['name'] for field in after},
            {'f-name': '注册名称', 'f-identity': '企业编号'})
        self.assertEqual(len(self.capture.deletions), 1)
        self.assertEqual(self.capture.deletions[0]['object_id'], 'view-network')


class PermissionTests(CaptureTestCase):
    def test_limited_scope_is_not_used_for_deletion(self):
        self.scan('wide-g1')
        self.catalog.scope = 'limited'
        scan = self.scan('limited-g1')
        self.assertFalse(scan['decision']['accepted'])
        self.assertEqual(scan['decision']['reason'], 'visibility_scope_incomplete')
        self.assertEqual(scan['probes']['ds-company']['result'], 'hidden')
        self.assertEqual(scan['probes']['view-network']['result'], 'hidden')
        self.assertEqual(self.capture.deletions, [])
        self.assertEqual(set(self.capture.catalog['objects']), {
            'ds-company', 'view-market', 'view-network'})

    def test_403_is_hidden_not_deleted(self):
        self.scan('wide-g1')
        self.catalog.scope = 'limited'
        self.scan('limited-g1')
        answer = self.capture.answer('ds-company')
        self.assertEqual(answer['state'], 'hidden')
        self.assertIn('403', answer['summary'])
        self.assertEqual(answer['evidence'][0]['sources'][0]['status'], 403)
        self.assertEqual(answer['snapshot_generation'], 'g1')

    def test_reopening_retains_and_re_resolves(self):
        self.scan('wide-g1')
        self.catalog.scope = 'limited'
        limited = self.scan('limited-g1')
        self.assertEqual(limited['items']['view-market']['field-list']['result'], 'complete')
        self.catalog.scope = 'wide'
        reopened = self.scan('wide-g1-reopened')
        self.assertTrue(reopened['decision']['accepted'])
        self.assertEqual(reopened['decision']['reason'], 'no_new_evidence')
        self.assertEqual(limited['items']['view-market']['field-list']['result'], 'complete')
        self.assertEqual(reopened['items']['view-network']['dependency-list']['result'],
                         'complete')
        self.assertEqual(self.capture.answer('view-network')['state'], 'visible')
        self.assertEqual(len(self.capture.snapshots), 1)

    def test_no_new_evidence_does_not_rewrite_catalog(self):
        self.scan('wide-g1')
        scan = self.scan('wide-g1-repeat')
        self.assertTrue(scan['decision']['accepted'])
        self.assertTrue(scan['decision']['revalidated'])
        self.assertEqual(len(self.capture.snapshots), 1)


class InterruptionTests(CaptureTestCase):
    def test_mid_scan_generation_change_rejects_snapshot(self):
        self.scan('wide-g1')
        seen = {'count': 0}

        def change(source, resource):
            seen['count'] += 1
            if seen['count'] == 3:
                source.generation = 'g2'

        self.catalog.before_query = change
        scan = self.scan('mid-scan', reuse=False)
        self.catalog.before_query = None
        self.assertEqual(scan['decision']['reason'], 'generation_changed')
        self.assertFalse(scan['decision']['accepted'])
        self.assertEqual(self.capture.catalog['generation'], 'g1')
        self.assertEqual(len(self.capture.snapshots), 1)

    def test_scope_change_mid_scan_is_anchored(self):
        self.scan('wide-g1')
        seen = {'count': 0}

        def change(source, resource):
            seen['count'] += 1
            if seen['count'] == 3:
                source.scope = 'limited'

        self.catalog.before_query = change
        scan = self.scan('scope-mid', reuse=False)
        self.catalog.before_query = None
        self.assertEqual(scan['decision']['reason'], 'scope_changed')
        self.assertFalse(scan['decision']['accepted'])
        self.assertEqual(self.capture.catalog['scope_version'], 'scope-1')

    def test_interrupted_scan_marks_unreached_endpoints(self):
        self.scan('wide-g1')

        class FailAfter:
            def __init__(self, inner, limit):
                self.inner = inner
                self.limit = limit
                self.calls = 0

            def fetch(self, path):
                self.calls += 1
                if self.calls > self.limit:
                    raise OSError('中断')
                return self.inner.fetch(path)

        scan = self.scan('partial', transport=FailAfter(
            LocalTransport(self.catalog), 4), reuse=False)
        self.assertEqual(scan['decision']['reason'], 'incomplete')
        from cli import classify
        unresolved = classify(self.capture)['unresolved_endpoints']
        self.assertTrue(unresolved)
        self.assertIn('dependency-list', {entry['endpoint'] for entry in unresolved})
        self.assertEqual(len(self.capture.snapshots), 1)

    def test_partial_scan_reports_unresolved_endpoints(self):
        self.scan('wide-g1')

        class FailAfter:
            def __init__(self, inner, limit):
                self.inner = inner
                self.limit = limit
                self.calls = 0

            def fetch(self, path):
                self.calls += 1
                if self.calls > self.limit:
                    raise OSError('中断')
                return self.inner.fetch(path)

        scan = self.scan('partial-visible', transport=FailAfter(
            LocalTransport(self.catalog), 3), reuse=False)
        self.assertEqual(scan['decision']['reason'], 'incomplete')
        unresolved = scan['items']['ds-company']['dependency-list']
        self.assertEqual(unresolved['result'], 'interrupted')
        from cli import classify
        self.assertTrue(classify(self.capture)['unresolved_endpoints'])

    def test_failed_transport_can_resume(self):
        self.scan('wide-g1')

        class FlakyTransport:
            def __init__(self, inner):
                self.inner = inner
                self.calls = 0

            def fetch(self, path):
                self.calls += 1
                if self.calls == 3:
                    raise OSError('连接中断')
                return self.inner.fetch(path)

        scan = self.scan('flaky', transport=FlakyTransport(LocalTransport(self.catalog)),
                         reuse=False)
        self.assertFalse(scan['decision']['accepted'])
        self.assertEqual(scan['decision']['reason'], 'incomplete')
        self.assertIn('连接中断', scan['decision']['detail'])
        self.assertEqual(self.capture.catalog['generation'], 'g1')

        resumed = self.scan('resume', transport=LocalTransport(self.catalog))
        self.assertTrue(resumed['decision']['accepted'])
        self.assertGreaterEqual(len(resumed['reused']), 1)
        self.assertEqual(self.capture.catalog['generation'], 'g1')

    def test_generation_and_scope_survive_new_process(self):
        self.scan('wide-g1')
        self.catalog.scope = 'limited'
        self.scan('limited-g1')
        self.raw.close()
        self.catalog_store.close()
        base = Path(self.directory.name)
        self.raw = RawStore(base / 'raw.sqlite3')
        self.catalog_store = CatalogStore(base / 'catalog.sqlite3')
        restored = CatalogCapture(
            self.raw, LocalTransport(self.catalog), catalog_store=self.catalog_store)
        self.assertEqual(restored.catalog['generation'], 'g1')
        self.assertEqual(restored.catalog['scope_version'], 'scope-1')
        self.assertEqual(restored.answer('ds-company')['state'], 'hidden')
        self.catalog.scope = 'wide'
        scan = restored.scan(label='reopened-in-new-process')
        self.assertTrue(scan['decision']['accepted'])
        self.assertEqual(scan['decision']['reason'], 'no_new_evidence')
        self.assertEqual(restored.answer('ds-company')['state'], 'visible')
        self.capture = restored


class EvidenceMeaningTests(CaptureTestCase):
    def test_probe_404_is_confirmed_deleted_only_for_previous_id(self):
        self.scan('wide-g1')
        self.catalog.generation = 'g2'
        scan = self.scan('wide-g2')
        self.assertTrue(scan['decision']['accepted'])
        self.assertEqual(self.capture.deletions[0]['probe_result'], 'absent')
        self.assertEqual(
            self.capture.deletions[0]['evidence']['sources'][0]['status'], 404)
        self.assertIn('view-network', [entry['object_id'] for entry in self.capture.deletions])

    def test_complete_empty_listing_cannot_remove_known_objects(self):
        self.scan('wide-g1')
        self.catalog.data['scopes']['wide']['objects'] = []
        self.catalog.data['scopes']['wide']['version'] = 'scope-empty'
        try:
            scan = self.scan('empty-listing')
        finally:
            self.catalog.data['scopes']['wide']['objects'] = [
                'ds-company', 'view-market', 'view-network']
            self.catalog.data['scopes']['wide']['version'] = 'scope-1'
        self.assertFalse(scan['decision']['accepted'])
        self.assertEqual(scan['decision']['reason'], 'visibility_limited_removal')
        self.assertEqual(self.capture.deletions, [])
        self.assertEqual(self.capture.catalog['generation'], 'g1')
        self.assertEqual(scan['probes']['ds-company']['result'], 'hidden')

    def test_object_endpoint_404_is_not_a_deletion_record(self):
        self.catalog.data['g1']['fields'].pop('view-network')
        self.catalog.data['g1']['dependencies'].pop('view-network')
        scan = self.scan('missing-object-endpoint')
        self.assertFalse(scan['decision']['accepted'])
        self.assertEqual(scan['decision']['reason'], 'object_evidence_incomplete')
        self.assertEqual(self.capture.deletions, [])

    def test_classification_separates_states(self):
        from cli import classify

        self.scan('wide-g1')
        self.catalog.scope = 'limited'
        self.scan('limited-g1')
        result = classify(self.capture)
        self.assertIn('ds-company', result['formally_visible'])
        hidden = {entry['object_id'] for entry in result['observed_hidden']}
        self.assertEqual(hidden, {'ds-company', 'view-network'})
        self.assertEqual(result['confirmed_deleted'], [])
        self.assertIn('view-market', result['observed'])

    def test_observations_keep_partial_pages_and_raw_readability(self):
        self.scan('wide-g1')
        rows = self.capture.observations()
        dataset_rows = [row for row in rows if row['kind'] == 'dataset-list']
        self.assertTrue(dataset_rows[0]['complete'])
        self.assertEqual(len(dataset_rows[0]['evidence']['sources']), 2)
        raw_rows = self.capture.raw_observations()
        self.assertTrue(raw_rows)
        for row in raw_rows:
            self.assertTrue(self.raw.read(row['digest']))
            self.assertIn('status', row['metadata'])
        statuses = {row['metadata']['status'] for row in raw_rows}
        self.assertEqual(statuses, {200})


class HttpTransportTests(unittest.TestCase):
    def test_real_http_scan_preserves_statuses(self):
        catalog = Catalog()
        with tempfile.TemporaryDirectory() as directory:
            raw = RawStore(Path(directory) / 'raw.sqlite3')
            store = CatalogStore(Path(directory) / 'catalog.sqlite3')
            try:
                with serve(catalog) as base:
                    capture = CatalogCapture(raw, HttpTransport(base), catalog_store=store)
                    scan = capture.scan(label='http-wide')
                    self.assertTrue(scan['decision']['accepted'])
                    self.assertEqual(scan['generation'], 'g1')
                    catalog.scope = 'limited'
                    limited = capture.scan(label='http-limited')
                self.assertEqual(limited['probes']['ds-company']['result'], 'hidden')
                self.assertEqual(
                    limited['probes']['ds-company']['evidence']['sources'][0]['status'], 403)
                self.assertEqual(capture.answer('ds-company')['state'], 'hidden')
            finally:
                raw.close()
                store.close()


if __name__ == '__main__':
    unittest.main()
