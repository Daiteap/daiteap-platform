import base64
import json

from json.decoder import JSONDecodeError

from ..environment_providers import check_controlplane_nodes
from mock import MagicMock, patch
from django.test import TestCase
import logging

class CheckControlplaneNodes(TestCase):
    def setUp(self):
        logger = logging.getLogger()
        logger.disabled = True

    def test_check_controlplane_nodes_even_number_controlplane_nodes_returns_false(self):
        resources = {
            'aws': {
                'region': 'eu-central-1',
                'nodes': [
                    {
                        'is_control_plane': True,
                        'zone': 'eu-central-1b',
                    }
                ],
            }, 
            'google': {
                'region': 'europe-west3', 
                'nodes': [
                    {
                        'is_control_plane': True, 
                        'zone': 'europe-west3-a', 
                    }
                ], 
            }, 
        }

        return_value = check_controlplane_nodes(resources)

        self.assertEqual(return_value, False)

    def test_check_controlplane_nodes_non_even_number_controlplane_nodes_returns_true(self):
        resources = {
            'aws': {
                'region': 'eu-central-1',
                'nodes': [
                    {
                        'is_control_plane': True,
                        'zone': 'eu-central-1b',
                    }
                ],
            }
        }

        return_value = check_controlplane_nodes(resources)

        self.assertEqual(return_value, True)
