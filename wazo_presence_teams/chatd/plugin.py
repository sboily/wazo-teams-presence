# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from flask import request, Response
from flask_restful import Resource

from wazo_chatd_client import Client as ChatdClient
from wazo_confd_client import Client as ConfdClient


logger = logging.getLogger(__name__)


PRESENCE_STATE_MAP = {
    'Available': 'available',
    'Busy': 'unavailable',
    'Away': 'away',
    'BeRightBack': 'away',
    'DoNotDisturb': 'dnd'
}

class TeamsChatdService:
    def __init__(self, chatd_client, confd_client):
        self._chatd = chatd_client
        self._confd = confd_client

    def update_presence(self, data, user_uuid):
        state = data['value'][0]['resourceData']['availability']
        status = data['value'][0]['resourceData']['activity']
        state = PRESENCE_STATE_MAP.get(state, 'available')
        if state == 'dnd':
            self._confd.users(user_uuid).update_service("dnd", {"enabled": True})
            state = 'unavailable'
        else:
            self._confd.users(user_uuid).update_service("dnd", {"enabled": False})
        presence = {
            "uuid": user_uuid,
            "state": state,
            "status": f"Teams: {status}"
        }
        logger.debug(
            f"Updating user {user_uuid} state to {state}"
        )
        return self._chatd.user_presences.update(presence)


class TeamsChatdResource(Resource):
    def __init__(self, chatd_service):
        self.chatd_service = chatd_service

    def post(self, user_uuid):
        validationToken = request.args.get('validationToken')
        if validationToken:
            return Response(validationToken, mimetype='text/plain')

        self.chatd_service.update_presence(request.get_json(), user_uuid)
        return '', 200


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']
        config = dependencies['config']
        token_changed_subscribe = dependencies['token_changed_subscribe']

        chatd_client = ChatdClient('localhost', verify_certificate=False)
        confd_client = ConfdClient(**config['confd'])
        token_changed_subscribe(chatd_client.set_token)
        token_changed_subscribe(confd_client.set_token)
        services = TeamsChatdService(chatd_client, confd_client)

        api.add_resource(
            TeamsChatdResource,
            '/users/<user_uuid>/teams/presence',
            resource_class_args=[services],
        )
