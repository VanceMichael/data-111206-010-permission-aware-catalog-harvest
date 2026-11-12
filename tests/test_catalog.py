import unittest
from catalog_source import Catalog, fetch_page, serve


class CatalogTests(unittest.TestCase):
    def test_page_boundary(self):
        catalog=Catalog()
        status,page=catalog.query('/datasets')
        self.assertEqual(status,200)
        self.assertEqual(page['next_cursor'],2)
        self.assertFalse(page['terminal'])
        self.assertTrue(catalog.query('/datasets',2)[1]['terminal'])

    def test_permission_and_missing_are_different(self):
        catalog=Catalog()
        catalog.scope='limited'
        self.assertEqual(catalog.query('/datasets/ds-company/fields')[0],403)
        catalog.scope='wide'
        catalog.generation='g2'
        self.assertEqual(catalog.query('/datasets/view-network/fields')[0],404)

    def test_permission_transition(self):
        catalog=Catalog()
        catalog.transitions={2:{'scope':'limited'}}
        self.assertEqual(catalog.query('/datasets')[1]['scope_version'],'scope-1')
        self.assertEqual(catalog.query('/datasets')[1]['scope_version'],'scope-2')

    def test_field_identity_survives_rename(self):
        catalog=Catalog()
        previous=catalog.query('/datasets/ds-company/fields')[1]['items']
        catalog.generation='g2'
        current=catalog.query('/datasets/ds-company/fields')[1]['items']
        self.assertEqual({row['id'] for row in previous},{row['id'] for row in current})
        self.assertNotEqual(previous,current)

    def test_actual_http_preserves_forbidden(self):
        catalog=Catalog()
        catalog.scope='limited'
        with serve(catalog) as base:
            status,raw,page=fetch_page(base,'/datasets/ds-company/fields')
        self.assertEqual(status,403)
        self.assertEqual(page['scope_version'],'scope-2')
        self.assertTrue(raw)
