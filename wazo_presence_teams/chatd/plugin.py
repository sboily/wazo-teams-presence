# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from flask import request, Response
from flask_restful import Resource
from wazo_chatd_client import Client as ChatdClient


class TeamsChatdService:
    def __init__(self, chatd_client):
        self._chatd = chatd_client

    def update_presence(self, data, user_uuid):
        state = data['value'][0]['resourceData']['availability']
        status = data['value'][0]['resourceData']['activity']
        if state == 'Available':
            state = 'available'
        elif state == 'Busy':
            state = 'unavailable'
        elif state == 'Away':
            state = 'away'
        else:
            state = 'available'
            status = 'State from teams are not supported'
        presence = {
            "uuid": user_uuid,
            "state": state,
            "status": status
        }
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
        token_changed_subscribe = dependencies['token_changed_subscribe']

        chatd_client = ChatdClient('localhost', verify_certificate=False)
        token_changed_subscribe(chatd_client.set_token)
        services = TeamsChatdService(chatd_client)

        api.add_resource(
            TeamsChatdResource,
            '/users/<user_uuid>/teams/presence',
            resource_class_args=[services],
        )
