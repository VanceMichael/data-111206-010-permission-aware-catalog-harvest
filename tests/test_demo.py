import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class DemoTests(unittest.TestCase):
    def run_cli(self, *args, output, catalog):
        return subprocess.run(
            [sys.executable, 'cli.py', *args,
             '--output', str(output), '--catalog', str(catalog)],
            capture_output=True, text=True, timeout=60)

    def test_real_demo(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'capture.sqlite3'
            process = subprocess.run(
                [sys.executable, 'app.py', 'demo', '--output', str(output)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIsInstance(json.loads(process.stdout), dict)
            self.assertTrue(output.is_file())

    def test_full_demo_scenario(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'raw.sqlite3'
            catalog = Path(directory) / 'catalog.sqlite3'
            process = self.run_cli('demo', output=output, catalog=catalog)
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            steps = {step['step']: step for step in result['steps']}

            wide = steps['wide-g1-graph']
            self.assertEqual(set(wide['cycles']), {'view-market', 'view-network'})
            self.assertEqual(wide['external_references'], ['outside-secret'])

            self.assertFalse(steps['limited-g1']['decision']['accepted'])
            self.assertEqual(
                steps['limited-g1']['decision']['reason'], 'visibility_scope_incomplete')
            self.assertEqual(
                steps['limited-g1-catalog-unchanged']['visible_objects'],
                ['ds-company', 'view-market', 'view-network'])
            self.assertEqual(
                steps['limited-g1-catalog-unchanged']['view_network_state'], 'hidden')
            self.assertEqual(
                steps['wide-g1-reopened-answers']['view_network'], 'visible')

            self.assertEqual(
                steps['mid-scan-generation-change']['stopped']['kind'],
                'generation_changed')
            self.assertEqual(
                steps['after-interrupted-scan']['catalog_generation'], 'g1')

            deleted = steps['wide-g2-answers']['view_network']
            self.assertEqual(deleted['state'], 'confirmed_deleted')
            self.assertEqual(deleted['evidence'][0]['sources'][0]['status'], 404)
            self.assertEqual(
                [field['id'] for field in steps['wide-g2-answers']['ds_company_fields']],
                ['f-name', 'f-identity'])

            classified = steps['classification']['result']
            self.assertEqual(classified['confirmed_deleted'][0]['object_id'], 'view-network')
            self.assertEqual(classified['external_references'], ['outside-secret'])
            self.assertEqual(classified['observed_hidden'], [])

            for path in (output, catalog):
                self.assertTrue(path.is_file())


class QueryTests(unittest.TestCase):
    def test_persisted_queries_after_demo(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'raw.sqlite3'
            catalog = Path(directory) / 'catalog.sqlite3'
            demo = subprocess.run(
                [sys.executable, 'cli.py', 'demo',
                 '--output', str(output), '--catalog', str(catalog)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(demo.returncode, 0, demo.stderr)

            explain = subprocess.run(
                [sys.executable, 'cli.py', 'explain', 'view-network',
                 '--output', str(output), '--catalog', str(catalog)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(explain.returncode, 0, explain.stderr)
            answer = json.loads(explain.stdout)
            self.assertEqual(answer['state'], 'confirmed_deleted')
            self.assertTrue(answer['evidence'])

            listing = subprocess.run(
                [sys.executable, 'cli.py', 'list',
                 '--output', str(output), '--catalog', str(catalog)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(listing.returncode, 0, listing.stderr)
            summary = json.loads(listing.stdout)
            self.assertEqual(summary['catalog_status'], 'accepted')
            self.assertEqual(summary['generation'], 'g2')
            self.assertEqual(summary['external_references'], ['outside-secret'])

            observations = subprocess.run(
                [sys.executable, 'cli.py', 'observations', '--raw',
                 '--output', str(output), '--catalog', str(catalog)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(observations.returncode, 0, observations.stderr)
            rows = json.loads(observations.stdout)
            self.assertTrue(any(row['metadata']['status'] == 200 for row in rows))

            snapshot = subprocess.run(
                [sys.executable, 'cli.py', 'snapshot',
                 '--output', str(output), '--catalog', str(catalog)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(snapshot.returncode, 0, snapshot.stderr)
            accepted = json.loads(snapshot.stdout)
            self.assertEqual(accepted['generation'], 'g2')
            self.assertEqual(set(accepted['datasets']), {'ds-company', 'view-market'})


class SinglePageTests(unittest.TestCase):
    def test_single_page_interface_is_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'raw.sqlite3'
            catalog = Path(directory) / 'catalog.sqlite3'
            process = subprocess.run(
                [sys.executable, 'cli.py', 'demo-border',
                 '--output', str(output), '--catalog', str(catalog)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stderr)
            page = json.loads(process.stdout)
            self.assertEqual(page['状态码'], 200)
            self.assertEqual(page['目录代际'], 'g1')
            self.assertEqual(page['下一页'], 2)
            self.assertIn('不推断删除', page['说明'])
