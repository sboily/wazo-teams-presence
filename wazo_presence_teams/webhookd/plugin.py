# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import iso8601
import requests
import logging
import uuid
import json

from time import gmtime, strftime
from datetime import datetime
from pymemcache.client.base import Client as Memcached

from wazo_auth_client import Client as AuthClient
from wazo_confd_client import Client as ConfdClient
from wazo_webhookd.plugins.subscription.service import SubscriptionService
from wazo_webhookd.services.helpers import HookExpectedError


logger = logging.getLogger(__name__)


class Service:
    def load(self, dependencies):
        bus_consumer = dependencies['bus_consumer']
        self._config = dependencies['config']
        self.subscription_service = SubscriptionService(dependencies['config'])

        bus_consumer.subscribe_to_event_names(
            uuid=str(uuid.uuid4()),
            event_names=['auth_user_external_auth_added'],
            user_uuid=None,
            wazo_uuid=None,
            callback=self.on_external_auth_added,
        )

        bus_consumer.subscribe_to_event_names(
            uuid=str(uuid.uuid4()),
            event_names=['auth_user_external_auth_deleted'],
            user_uuid=None,
            wazo_uuid=None,
            callback=self.on_external_auth_deleted,
        )

        logger.info("[microsoft teams presence] Plugin started")

    def on_external_auth_added(self, body, event):
        if body['data'].get('external_auth_name') == 'microsoft':
            user_uuid = body['data']['user_uuid']
            tenant_uuid = self.get_tenant_uuid(user_uuid)

            external_tokens, external_config = self.get_external_data(
                self._config,
                user_uuid,
                tenant_uuid,
            )
            teams = TeamsPresence(self._config, external_tokens, external_config)
            teams.set_subscription(teams.get_user())
            logger.info(
                "[microsoft teams presence] User registered: %s/%s",
                tenant_uuid,
                user_uuid,
            )

            user_external_config_cache = UserExternalConfigCache(
                get_memcached(self._config['memcached'])
            )
            user_external_config_cache.add(user_uuid, external_config)

    def on_external_auth_deleted(self, body, event):
        if body['data'].get('external_auth_name') == 'microsoft':
            user_uuid = body['data']['user_uuid']
            tenant_uuid = self.get_tenant_uuid(user_uuid)

            subscriptions = []

            for subscription in subscriptions:
                self.subscription_service.delete(subscription.uuid)
                logger.info(
                    '[microsoft teams presence] User unregistered: %s/%s',
                    tenant_uuid,
                    user_uuid,
                )

            user_external_config_cache = UserExternalConfigCache(
                get_memcached(self._config['memcached'])
            )
            user_external_config_cache.delete(user_uuid)

    def get_tenant_uuid(self, user_uuid):
        auth = self.get_auth(self._config)
        return auth.users.get(user_uuid)["tenant_uuid"]

    @classmethod
    def get_auth(cls, config):
        auth_config = dict(config['auth'])
        auth_config['verify_certificate'] = False
        auth = AuthClient(**auth_config)
        token = auth.token.new('wazo_user', expiration=60)
        auth.set_token(token["token"])
        return auth

    @classmethod
    def get_confd(cls, config):
        auth = cls.get_auth(config)
        token = auth.token.new('wazo_user', expiration=60)
        if 'confd' not in config:
            raise Exception("[microsoft teams presence] Confd is not configured properly")
        confd_config = dict(config['confd'])
        confd = ConfdClient(**confd_config)
        confd.set_token(token["token"])
        return confd

    @classmethod
    def get_external_data(cls, config, user_uuid, tenant_uuid):
        auth = cls.get_auth(config)
        external_tokens = cls.get_external_token(config, user_uuid)
        external_config = auth.external.get_config('microsoft', tenant_uuid)
        external_config['user_uuid'] = user_uuid

        confd_client = cls.get_confd(config)
        domain = confd_client.ingress_http.list(tenant_uuid=tenant_uuid)

        for item in domain['items']:
            if 'uri' in item:
                external_config['domain'] = item['uri']

        return (external_tokens, external_config)

    @classmethod
    def get_external_token(cls, config, user_uuid):
        auth = cls.get_auth(config)
        try:
            return auth.external.get('microsoft', user_uuid)
        except requests.exceptions.HTTPError:
            raise HookExpectedError(
                "[microsoft teams presence] No existing external token for this user"
            )

    # Not used for the moment
    @classmethod
    def run(cls, task, config, subscription, event):
        user_uuid = subscription['events_user_uuid']
        if not user_uuid:
            raise HookExpectedError(
                "[microsoft team presence] subscription doesn't have events_user_uuid set"
            )

        user_external_config_cache = UserExternalConfigCache(
            get_memcached(config['memcached'])
        )
        external_config = user_external_config_cache.get(user_uuid)
        external_token = cls.get_external_token(config, user_uuid)
        teams = TeamsPresence(config, external_token, external_config)

        data = event.get('data')
        notification_type = event.get('name')

        if notification_type:
            return getattr(teams, notification_type)(data)


def get_memcached(config):
    host, port = config['uri'].split(':')
    return Memcached(
        (str(host), int(port)), serializer=serialize, deserializer=deserialize
    )


def serialize(key, value):
    if isinstance(value, str):
        return value.encode('utf-8'), 1
    return json.dumps(value).encode('utf-8'), 2


def deserialize(key, value, flags):
    if flags == 1:
        return value.decode('utf-8')
    if flags == 2:
        return json.loads(value.decode('utf-8'))
    raise Exception("[microsoft teams presence] Unknown serialization format")


class UserExternalConfigCache:
    def __init__(self, client_memcached):
        self.mem = client_memcached

    def add(self, user_uuid, data):
        self.mem.add(user_uuid, data)

    def get(self, user_uuid):
        return self.mem.get(user_uuid)

    def delete(self, user_uuid):
        self.mem.delete(user_uuid)


class TeamsPresence:
    def __init__(self, config, external_tokens, external_config):
        self.sessionId = "f82a3e59-8e7a-4c40-86df-05ef17fdc7aa"
        self.graph = "https://graph.microsoft.com/v1.0"
        self.domain = external_config['domain']
        self.user_uuid = external_config['user_uuid']
        self.access_token = external_tokens['access_token']

    def get_user(self):
        r = requests.get(f"{self.graph}/me", headers=self._headers())
        return r.json()['id']

    def get_presence(self):
        r = requests.get(f"{self.graph}/me/presence", headers=self._headers())
        if r.status_code == 200:
            return(r.json()['availability'], r.json()['activity'])
        return ()

    def clear_presence(self):
        data = {
            "sessionId": self.sessionId,
        }
        r = requests.post(f"{self.graph}/users/{userId}/presence/clearPresence", json=data, headers=self._headers())
        if r.status_code != 200:
            print(r.text)

    def set_presence(self, userId, availability, activity, expiration="PT1H"):
        # Available/Available
        # Busy/InACall
        # Busy/InAConferenceCall
        # Away/Away
        data = {
            "sessionId": self.sessionId,
            "availability": availability,
            "activity": activity,
            "expirationDuration": expiration
        }
        r = requests.post(f"{self.graph}/users/{userId}/presence/setPresence", json=data, headers=self._headers())
        if r.status_code != 200:
            print(r.text)

    def set_subscription(self, userId):
        date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=+60)
        expiration = date.isoformat().replace("+00:00", "Z")
        data = {
            "changeType": "updated",
            "notificationUrl": f"https://{self.domain}/api/chatd/1.0/users/{self.user_uuid}/teams/presence",
            "resource": f"/communications/presences/{userId}",
            "expirationDateTime": expiration,
            "clientState": "SecretClientState"
        }
        r = requests.post(f"{self.graph}/subscriptions", json=data, headers=self._headers())
        if r.status_code == 409:
            print("A subscripton already exists.")
        elif r.status_code == 201:
            print(f"Subscription {r.json()['id']} created")
        elif r.status_code != 200:
            print(r.status_code)
            print(r.json())

    def renew_subscription(self, subscriptionId):
        date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=+60)
        expiration = date.isoformat().replace("+00:00", "Z")
        data = {
            "expirationDateTime": expiration
        }
        r = requests.patch(f"{self.graph}/subscriptions/{subscriptionId}", json=data, headers=self._headers())
        if r.status_code != 200:
            print(r.status_code)
            print(r.text)

    def delete_subscription(self, subscriptionId):
        r = requests.delete(f"{self.graph}/subscriptions/{subscriptionId}", headers=self._headers())
        if r.status_code != 204:
            print(r.text)

    def list_subscriptions(self):
        r = requests.get(f"{self.graph}/subscriptions", headers=self._headers())
        if r.status_code != 200:
            print(r.text)
        return r.json()['value']

    def _headers(self):
        return {
            'Content-Type':'application/json',
            'Authorization': 'Bearer {0}'.format(self.access_token),
            'Accept': 'application/json'
        }
