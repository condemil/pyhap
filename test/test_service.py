from unittest import TestCase

from pyhap.service import (
    AccessoryInformationService,
    Service,
)


class TestService(TestCase):
    def test_json(self):
        service = AccessoryInformationService()
        service.instance_id = 5
        self.assertEqual(service.__json__(), {
            'type': '3E',
            'iid': 5,
            'characteristics': []
        })

    def test_abstract(self):
        with self.assertRaises(NotImplementedError):
            service = Service()
            service.service_uuid  # pylint: disable=pointless-statement
