# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import functools

from keystone.common import json_home
from keystone.common import wsgi
from keystone.contrib import federation
from keystone.contrib.federation import controllers


build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-FEDERATION', extension_version='1.0')

build_parameter_relation = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='OS-FEDERATION', extension_version='1.0')

IDP_ID_PARAMETER_RELATION = build_parameter_relation(parameter_name='idp_id')
PROTOCOL_ID_PARAMETER_RELATION = build_parameter_relation(
    parameter_name='protocol_id')


class FederationExtension(wsgi.V3ExtensionRouter):
    """API Endpoints for the Federation extension.

    The API looks like::

        PUT /OS-FEDERATION/identity_providers/$identity_provider
        GET /OS-FEDERATION/identity_providers
        GET /OS-FEDERATION/identity_providers/$identity_provider
        DELETE /OS-FEDERATION/identity_providers/$identity_provider
        PATCH /OS-FEDERATION/identity_providers/$identity_provider

        PUT /OS-FEDERATION/identity_providers/
            $identity_provider/protocols/$protocol
        GET /OS-FEDERATION/identity_providers/
            $identity_provider/protocols
        GET /OS-FEDERATION/identity_providers/
            $identity_provider/protocols/$protocol
        PATCH /OS-FEDERATION/identity_providers/
            $identity_provider/protocols/$protocol
        DELETE /OS-FEDERATION/identity_providers/
            $identity_provider/protocols/$protocol

        PUT /OS-FEDERATION/mappings
        GET /OS-FEDERATION/mappings
        PATCH /OS-FEDERATION/mappings/$mapping_id
        GET /OS-FEDERATION/mappings/$mapping_id
        DELETE /OS-FEDERATION/mappings/$mapping_id

        GET /OS-FEDERATION/projects
        GET /OS-FEDERATION/domains

        GET /OS-FEDERATION/identity_providers/$identity_provider/
            protocols/$protocol/auth
        POST /OS-FEDERATION/identity_providers/$identity_provider/
            protocols/$protocol/auth


        POST /auth/OS-FEDERATION/saml2

        GET /OS-FEDERATION/saml2/metadata


    """
    def _construct_url(self, suffix):
        return "/OS-FEDERATION/%s" % suffix

    def add_routes(self, mapper):
        # This is needed for dependency injection
        # it loads the Federation driver which registers it as a dependency.
        federation.Manager()
        auth_controller = controllers.Auth()
        idp_controller = controllers.IdentityProvider()
        protocol_controller = controllers.FederationProtocol()
        mapping_controller = controllers.MappingController()
        project_controller = controllers.ProjectV3()
        domain_controller = controllers.DomainV3()
        saml_metadata_controller = controllers.SAMLMetadataV3()

        # Identity Provider CRUD operations

        self._add_resource(
            mapper, idp_controller,
            path=self._construct_url('identity_providers/{idp_id}'),
            get_action='get_identity_provider',
            put_action='create_identity_provider',
            patch_action='update_identity_provider',
            delete_action='delete_identity_provider',
            rel=build_resource_relation(resource_name='identity_provider'),
            path_vars={
                'idp_id': IDP_ID_PARAMETER_RELATION,
            })
        self._add_resource(
            mapper, idp_controller,
            path=self._construct_url('identity_providers'),
            get_action='list_identity_providers',
            rel=build_resource_relation(resource_name='identity_providers'))

        # Protocol CRUD operations

        self._add_resource(
            mapper, protocol_controller,
            path=self._construct_url('identity_providers/{idp_id}/protocols/'
                                     '{protocol_id}'),
            get_action='get_protocol',
            put_action='create_protocol',
            patch_action='update_protocol',
            delete_action='delete_protocol',
            rel=build_resource_relation(
                resource_name='identity_provider_protocol'),
            path_vars={
                'idp_id': IDP_ID_PARAMETER_RELATION,
                'protocol_id': PROTOCOL_ID_PARAMETER_RELATION,
            })
        self._add_resource(
            mapper, protocol_controller,
            path=self._construct_url('identity_providers/{idp_id}/protocols'),
            get_action='list_protocols',
            rel=build_resource_relation(
                resource_name='identity_provider_protocols'),
            path_vars={
                'idp_id': IDP_ID_PARAMETER_RELATION,
            })

        # Mapping CRUD operations

        self._add_resource(
            mapper, mapping_controller,
            path=self._construct_url('mappings/{mapping_id}'),
            get_action='get_mapping',
            put_action='create_mapping',
            patch_action='update_mapping',
            delete_action='delete_mapping',
            rel=build_resource_relation(resource_name='mapping'),
            path_vars={
                'mapping_id': build_parameter_relation(
                    parameter_name='mapping_id'),
            })
        self._add_resource(
            mapper, mapping_controller,
            path=self._construct_url('mappings'),
            get_action='list_mappings',
            rel=build_resource_relation(resource_name='mappings'))
        self._add_resource(
            mapper, domain_controller,
            path=self._construct_url('domains'),
            get_action='list_domains_for_groups',
            rel=build_resource_relation(resource_name='domains'))
        self._add_resource(
            mapper, project_controller,
            path=self._construct_url('projects'),
            get_action='list_projects_for_groups',
            rel=build_resource_relation(resource_name='projects'))
        self._add_resource(
            mapper, auth_controller,
            path=self._construct_url('identity_providers/{identity_provider}/'
                                     'protocols/{protocol}/auth'),
            get_post_action='federated_authentication',
            rel=build_resource_relation(
                resource_name='identity_provider_protocol_auth'),
            path_vars={
                'identity_provider': IDP_ID_PARAMETER_RELATION,
                'protocol': PROTOCOL_ID_PARAMETER_RELATION,
            })

        # Auth operations
        self._add_resource(
            mapper, auth_controller,
            path='/auth' + self._construct_url('saml2'),
            post_action='create_saml_assertion',
            rel=build_resource_relation(resource_name='saml2'))

        # Keystone-Identity-Provider metadata endpoint
        self._add_resource(
            mapper, saml_metadata_controller,
            path=self._construct_url('saml2/metadata'),
            get_action='get_metadata',
            rel=build_resource_relation(resource_name='metadata'))
