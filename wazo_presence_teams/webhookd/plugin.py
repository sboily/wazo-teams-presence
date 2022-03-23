# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import requests
import logging
import uuid
import json
import threading
import time
import iso8601

from datetime import datetime, timezone, timedelta
from pymemcache.client.base import Client as Memcached

from wazo_auth_client import Client as AuthClient
from wazo_confd_client import Client as ConfdClient
from wazo_webhookd.plugins.subscription.service import SubscriptionService
from wazo_webhookd.services.helpers import HookExpectedError


logger = logging.getLogger(__name__)


EXPIRATION = 3600


class UserCache:
    def __init__(self, user_cache):
        self.subscriptionId = user_cache['subscriptionId']
        self.expiration = user_cache['expiration']
        self.access_token = user_cache['access_token']
        self.config = user_cache['config']
        self.tenant_uuid = user_cache['tenant_uuid']
        self.userId = user_cache['userId']


class SubscriptionRenewer:
    def __init__(self, config, cache):
        self._cache = cache
        self._config = config
        self._tombstone = threading.Event()
        self._thread = threading.Thread(target=self._loop)
        self._thread.daemon = True
        self.users = self._users() or []

    def start(self):
        self._thread.start()

    def stop(self):
        self._tombstone.set()
        self._thread.join()
        self._tombstone.clear()

    def _users(self):
        return self._cache.get_users()

    def add_user(self, user_uuid):
        self.users.append(user_uuid)
        self._cache.update_users(self.users)

    def delete_user(self, user_uuid):
        self.users.remove(user_uuid)
        self._cache.update_users(self.users)

    def _loop(self):
        while not self._tombstone.is_set():
            for user in self.users:
                u = self._cache.get(user)
                if not u:
                    self.delete_user(user)
                    continue

                user_cache = UserCache(u)
                if self._is_expired(user_cache.expiration):
                    teams = TeamsPresence(self._config, user_cache.access_token, user_cache.config)
                    renew, expiration = teams.renew_subscription(user_cache.subscriptionId)
                    if renew.status_code == 200:
                        user_cache.expiration = expiration
                    elif renew.status_code == 401:
                        _cache = self._renew_external_token(user_cache, user)
                        continue
                    elif renew.status_code == 404:
                        subscriptionId, expiration = teams.create_subscription(user_cache.userId)
                        user_cache.subscriptionId = subscriptionId
                        user_cache.expiration = expiration
                    self._cache.update(user, user_cache.__dict__)
            time.sleep(1)

    def _renew_external_token(self, user_cache, user_uuid):
        logger.info(f"[microsoft teams presence] Update cache access token for: {user_uuid}")
        token_data, _ = Service.get_external_data(
            self._config,
            user_uuid,
            user_cache.tenant_uuid,
        )
        user_cache.access_token = token_data['access_token']
        self._cache.update(user_uuid, user_cache.__dict__)
        return user_cache

    def _is_expired(self, expiration):
        if expiration == None:
            return True
        if expiration:
            now = datetime.now(timezone.utc)
            duration = int((iso8601.parse_date(expiration) - now).total_seconds())
            if duration - 5 < 0:
                logger.info("[microsoft teams presence] Subscription for presence is expired.")
                return True
        return False


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

        self.subcription_renewer = SubscriptionRenewer(
            self._config,
            UserExternalConfigCache(
                get_memcached(self._config['memcached'])
            )
        )
        self.subcription_renewer.start()

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
            teams = TeamsPresence(self._config, external_tokens['access_token'], external_config)
            userId = teams.get_user()
            subscriptionId, expiration = teams.create_subscription(userId)

            logger.info(f"[microsoft teams presence] User registered: {tenant_uuid}/{user_uuid}")

            self.subcription_renewer.add_user(user_uuid)
            user_external_config_cache = UserExternalConfigCache(
                get_memcached(self._config['memcached'])
            )
            cache = UserCache({
                "subscriptionId": subscriptionId,
                "expiration": expiration,
                "access_token": external_tokens['access_token'],
                "config": external_config,
                "tenant_uuid": tenant_uuid,
                "userId": userId
            })
            user_external_config_cache.add(user_uuid, cache.__dict__)

    def on_external_auth_deleted(self, body, event):
        if body['data'].get('external_auth_name') == 'microsoft':
            user_uuid = body['data']['user_uuid']
            tenant_uuid = self.get_tenant_uuid(user_uuid)

            logger.info(f"[microsoft teams presence] User unregistered: {tenant_uuid}/{user_uuid}")

            user_external_config_cache = UserExternalConfigCache(
                get_memcached(self._config['memcached'])
            )

            user_cache = user_external_config_cache.get(user_uuid)
            if user_cache:
                subscriptionId = user_cache['subscriptionId']
                access_token = user_cache['access_token']
                external_config = user_cache['config']
                teams = TeamsPresence(self._config, access_token, external_config)
                teams.delete_subscription(subscriptionId)
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
        external_config = user_external_config_cache.get(user_uuid)['config']
        external_token = cls.get_external_token(config, user_uuid)
        teams = TeamsPresence(config, external_token['access_token'], external_config)

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

    def update(self, user_uuid, data):
        self.mem.set(user_uuid, data)

    def get(self, user_uuid):
        return self.mem.get(user_uuid)

    def delete(self, user_uuid):
        self.mem.delete(user_uuid)

    def get_users(self):
        return self.mem.get('users')

    def update_users(self, data):
        self.mem.set('users', data)


class TeamsPresence:
    def __init__(self, config, access_tokens, external_config):
        self.sessionId = config['microsoft']['appId']
        self.graph = "https://graph.microsoft.com/v1.0"
        self.domain = external_config['domain']
        self.user_uuid = external_config['user_uuid']
        self.access_token = access_tokens
        self.expiration_time = EXPIRATION

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

    def create_subscription(self, userId):
        data = {
            "changeType": "updated",
            "notificationUrl": f"https://{self.domain}/api/chatd/1.0/users/{self.user_uuid}/teams/presence",
            "resource": f"/communications/presences/{userId}",
            "expirationDateTime": self._expiration(self.expiration_time),
            "clientState": "SecretClientState"
        }
        r = requests.post(f"{self.graph}/subscriptions", json=data, headers=self._headers())
        if r.status_code == 409:
            logger.info(f"[microsoft teams presence] A subscription already exists.")
            subscriptionId, expiration = self.list_subscriptions()
            return (subscriptionId, expiration)
        elif r.status_code == 201:
            logger.info(f"[microsoft teams presence] Subscription {r.json()['id']} created")
            return (r.json()['id'], r.json()['expirationDateTime'])
        elif r.status_code != 200:
            print(r.status_code)
            print(r.json())

    def renew_subscription(self, subscriptionId):
        expiration = self._expiration(self.expiration_time)
        data = {
            "expirationDateTime": expiration
        }
        r = requests.patch(f"{self.graph}/subscriptions/{subscriptionId}", json=data, headers=self._headers())
        if r.status_code != 200:
            print(r.status_code)
            print(r.text)
        elif r.status_code == 200:
            logger.info(f"[microsoft teams presence] A subscription has been renewed.")
        return (r, expiration)

    def delete_subscription(self, subscriptionId):
        r = requests.delete(f"{self.graph}/subscriptions/{subscriptionId}", headers=self._headers())
        if r.status_code != 204:
            print(r.text)
        else:
            logger.info(f"[microsoft teams presence] A subscription has been removed.")

    def list_subscriptions(self):
        r = requests.get(f"{self.graph}/subscriptions", headers=self._headers())
        if r.status_code != 200:
            print(r.text)
        elif r.status_code == 200:
            data = r.json()['value'][0]
            return (data['id'], data['expirationDateTime'])
        return (None, None)

    def _headers(self):
        return {
            'Content-Type':'application/json',
            'Authorization': 'Bearer {0}'.format(self.access_token),
            'Accept': 'application/json'
        }

    def _expiration(self, seconds):
        date = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        return date.isoformat().replace("+00:00", "Z")
