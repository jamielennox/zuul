# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
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

import collections
import datetime
import logging
import hmac
import hashlib
import platform

import iso8601
import jwt
import requests
from six.moves import urllib
import webob
import webob.dec
import voluptuous as v
import github3
from github3.exceptions import MethodNotAllowed

from zuul.connection import BaseConnection
from zuul.exceptions import MergeFailure
from zuul.model import GithubTriggerEvent
from zuul import version

ACCESS_TOKEN_URL = 'https://api.github.com/installations/%s/access_tokens'
PREVIEW_JSON_ACCEPT = 'application/vnd.github.machine-man-preview+json'

USER_AGENT = 'zuul/%s %s %s/%s' % (
    version.version_info.version_string(),
    requests.utils.default_user_agent(),
    platform.python_implementation(), platform.python_version())


class UTC(datetime.tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return datetime.timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return datetime.timedelta(0)


utc = UTC()


class GithubBaseAuth(object):

    def __init__(self, host=None):
        self.host = host or 'github.com'

    def get_headers(self, api, project, fallback_auth=False):
        return {}

    def get_params(self, api, project, fallback_auth=False):
        return {}

    @property
    def api_url(self):
        return "https://%s/api" % self.host

    def event_hook(self, api, event_type, json_body):
        pass


class GithubTokenAuth(GithubBaseAuth):

    def __init__(self, api_token, host=None):
        super(GithubTokenAuth, self).__init__(host=host)
        self.api_token = api_token

    def get_headers(self, api, project, fallback_auth=False):
        return {'Authorization': 'token %s' % self.api_token}


class UnexpectedHTTPResponse(Exception):

    def __init__(self, response):
        self.response = response

    @property
    def status_code(self):
        return self.response.status_code

    @property
    def reason(self):
        return self.response.reason


class GithubIntegrationAuth(GithubBaseAuth):

    log = logging.getLogger("zuul.GithubIntegrationAuth")

    def __init__(self,
                 integration_id,
                 integration_key,
                 fallback_token=None,
                 host=None):
        super(GithubIntegrationAuth, self).__init__(host=host)

        self.integration_id = integration_id
        self.integration_key = integration_key

        # there are some things integrations can't do yet so do them with a
        # standard token. No one will notice.
        self.fallback_token = fallback_token

        self._integration_token = None
        self._integration_token_expiry = None

        self.installation_map = {}
        self.token_cache = {}

    def event_hook(self, api, event_type, json_body):
        super(GithubIntegrationAuth, self).event_hook(event_type, json_body)

        # If there's any installation mapping information in the body then
        # update the project mapping before any requests are made.
        installation_id = json_body.get('installation', {}).get('id')
        project_name = json_body.get('repository', {}).get('full_name')

        if installation_id and project_name:
            old_id = self.installation_map.get(project_name)

            if old_id and old_id != installation_id:
                msg = "Unexpected installation_id change for %s. %d -> %d."
                self.log.warning(msg, project_name, old_id, installation_id)

            self.installation_map[project_name] = installation_id

    @property
    def integration_token(self):
        now = datetime.datetime.now(utc)

        if ((not self._integration_token) or
                (not self._integration_token_expiry) or
                (now >= self._integration_token_expiry)):
            # 10 minutes is the maximum amount of time you can request
            expiry = now + datetime.timedelta(minutes=10)
            data = {'iat': now, 'exp': expiry, 'iss': self.integration_id}

            self.integration_token = jwt.encode(data,
                                                self.integration_key,
                                                algorithm='RS256')

            expiry -= datetime.timedelta(minutes=2)
            self._integration_token_expiry = expiry

        return self._integration_token

    def get_headers(self, api, project, fallback_auth=False):
        if fallback_auth:
            return {'Authorization': 'token %s' % self.fallback_token}

        elif project:
            token = self._get_installation_token(project)
            return {'Authorization': 'Token %s' % token}

        else:
            return {'Authorization': 'Bearer %s' % self.integration_token}

    def _get_installation_token(self, api, project, user_id=None):
        installation_id = self.installation_map.get(project)

        if not installation_id:
            self.log.error("No installation ID available for project %s",
                           project)
            return ''

        now = datetime.datetime.now(utc)
        token, expiry = self.installation_token_cache.get(installation_id,
                                                          (None, None))

        if ((not expiry) or (not token) or (now >= expiry)):
            url = ACCESS_TOKEN_URL % installation_id

            headers = {'Accept': PREVIEW_JSON_ACCEPT,
                       'Authorization': 'Bearer %s' % self.integration_token}
            json_data = {'user_id': user_id} if user_id else None

            response = api.session.post(url, headers=headers, json=json_data)

            if response.status_code != 200:
                raise UnexpectedHTTPResponse(resp)

            data = response.json()

            expiry = iso8601.parse_date(data['expires_at'])
            expiry -= datetime.timedelta(minutes=2)
            token = data['token']

            self.installation_token_cache[installation_id] = (token, expiry)

        return token


class GithubAPI(object):

    def __init__(self, auth=None):
        self.session = requests.Session()
        self.auth = auth or GithubBaseAuth()

    def event_hook(self, *args, **kwargs):
        return self.auth.event_hook(self, *args, **kwargs)

    def request(self, method, url,
                project=None,
                fallback_auth=False,
                expected_status=200,
                **kwargs):
        params = self.auth.get_params(self,
                                      project,
                                      fallback_auth=fallback_auth)
        headers = self.auth.get_headers(self,
                                        project,
                                        fallback_auth=fallback_auth)

        headers.setdefault('Accept', 'application/vnd.github.v3+json')
        headers.setdefault('User-Agent', USER_AGENT)

        if params:
            kwargs.setdefault('params', {}).update(params)
        if headers:
            kwargs.setdefault('headers', {}).update(headers)

        if urllib.parse.urlparse(url).netloc:
            url = self.auth.api_url + path

        resp = self.session.request(method, url, **kwargs)

        if resp.status_code != expected_status:
            raise UnexpectedHTTPResponse(resp)

        return resp

    def get(self, path, **kwargs):
        return self.request('GET', path, **kwargs)

    def get_iter(self, path, **kwargs):
        while path:
            resp = self.get(path, **kwargs)

            for item in resp.json():
                yield item

            path = resp.links.get('next')

    def post(self, path, **kwargs):
        kwargs.setdefault('expected_status', 201)
        return self.request('POST', path, **kwargs)

    def put(self, path, **kwargs):
        return self.request('PUT', path, **kwargs)

    def delete(self, path, **kwargs):
        kwargs.setdefault('expected_status', 204)
        return self.request('DELETE', path, **kwargs)

    def getPull(self, project, number):
        return self.get('/repos/%s/pulls/%s' % (project, number),
                        project=project).json()

    def labelPull(self, project, pr_number, labels):
        # labels is a list
        return self.post('/repos/%s/issues/%s/labels' % (project, number),
                         data=labels,
                         project=project).json()

    def unlabelPull(self, project, pr_number, label):
        self.delete('/repos/%s/issues/%s/labels/%s' % (project, number, label))

    def getPullReviews(self, project, pr_number):
        headers = {'Accept': 'application/vnd.github.black-cat-preview+json'}
        return self.get_iter('/repos/%s/pulls/%s/reviews',
                             project=project,
                             headers=headers)

    def getPullFileNames(self, project, pr_number):
        data = self.get_iter('/repos/%s/pulls/%s/files' % (project, pr_number),
                             project=project)

        return [f['filename'] for f in data]

    def getRepoPermission(self, project, username):
        url = '/repos/%s/collaborators/%s/permission' % (project, username)

        try:
            return self.get(url, project=project).json()['permission']
        except requests.exceptions.NotFound:
            # no known user, maybe deleted since review?
            return 'none'

    def commentPull(self, project, pr_number, message):
        self.post('/repos/%s/issues/%s/comments' % (project, pr_number),
                  json={'body': message},
                  project=project)

    def mergePull(self, project, pr_number, commit_message='', sha=None):
        headers = {'Accept': 'application/vnd.github.polaris-preview+json'}

        data = {}

        if commit_message:
            data['commit_message'] = commit_message
        if sha:
            data['sha'] = sha

        self.put('/repos/%s/pulls/%s/merge' % (project, pr_number),
                 json=data,
                 project=project)

    def getCommitStatuses(self, project, sha):
        return self.get_iter('/repos/%s/commits/%s/statuses' % (project, sha),
                             project=project)

    def setCommitStatus(self,
                        project,
                        sha,
                        state,
                        url='',
                        description='',
                        context=''):
        params = {'state': state}

        if url:
            params['target_url'] = url
        if description:
            params['description'] = description
        if context:
            params['context'] = context

        self.post('/repos/%s/statuses/%s' % (project, sha),
                  project=project)

    def getPullBySha(self, project, sha):
        query = '%s repo:%s type:pr is:open' % (sha, project)

        pulls = {}
        search_reults = self.get_iter('/search/issues', params={'q': query})

        for issue in search_results.get('items', []):
            pr = self.getPull(project, issue['id'])

            if pr['head']['sha'] != sha:
                continue

            pulls[issue['id']] = pr

        if len(pulls) > 1:
            raise Exception('Multiple pulls found with head sha %s' % sha)

        if len(pulls) == 0:
            return None

        return pulls.keys()[0]


class GithubWebhookListener():

    log = logging.getLogger("zuul.GithubWebhookListener")

    def __init__(self, connection):
        self.connection = connection

    def handle_request(self, request):
        if request.method != 'POST':
            self.log.debug("Only POST method is allowed.")
            raise webob.exc.HTTPMethodNotAllowed(
                'Only POST method is allowed.')

        self.log.debug("Github Webhook Received.")

        self._validate_signature(request)

        self.__dispatch_event(request)

    def __dispatch_event(self, request):
        try:
            event = request.headers['X-Github-Event']
            self.log.debug("X-Github-Event: " + event)
        except KeyError:
            self.log.debug("Request headers missing the X-Github-Event.")
            raise webob.exc.HTTPBadRequest('Please specify a X-Github-Event '
                                           'header.')

        try:
            method = getattr(self, '_event_' + event)
        except AttributeError:
            message = "Unhandled X-Github-Event: {0}".format(event)
            self.log.debug(message)
            raise webob.exc.HTTPBadRequest(message)

        try:
            json_body = request.json_body
        except:
            message = 'Exception deserializing JSON body'
            self.log.exception(message)
            raise webob.exc.HTTPBadRequest(message)

        self.connection.api.event_hook(event, json_body)

        try:
            event = method(json_body)
        except:
            self.log.exception('Exception when handling event:')
            event = None

        if event:
            self.log.debug('Scheduling github event: {0}'.format(event.type))
            self.connection.sched.addEvent(event)

    def _event_push(self, body):
        base_repo = body.get('repository')

        event = GithubTriggerEvent()
        event.connection_name = self.connection.connection_name
        event.trigger_name = 'github'
        event.project_name = base_repo.get('full_name')

        event.ref = body.get('ref')
        event.oldrev = body.get('before')
        event.newrev = body.get('after')

        ref_parts = event.ref.split('/')  # ie, ['refs', 'heads', 'master']

        if ref_parts[1] == "heads":
            event.type = 'push'
        elif ref_parts[1] == "tags":
            event.type = 'tag'
        else:
            return None

        # necessary for the scheduler to match against particular branches
        event.branch = ref_parts[2]

        return event

    def _event_pull_request(self, body):
        action = body.get('action')
        pr_body = body.get('pull_request')

        event = self._pull_request_to_event(pr_body)
        event.account = self._get_sender(body)

        if action == 'opened':
            event.type = 'pr-open'
        elif action == 'synchronize':
            event.type = 'pr-change'
        elif action == 'closed':
            event.type = 'pr-close'
        elif action == 'reopened':
            event.type = 'pr-reopen'
        elif action == 'labeled':
            event.type = 'pr-label'
            event.label = body['label']['name']
        elif action == 'unlabeled':
            event.type = 'pr-label'
            event.label = '-' + body['label']['name']
        else:
            return None

        return event

    def _event_issue_comment(self, body):
        """Handles pull request comments"""
        action = body.get('action')
        if action != 'created':
            return
        pr_body = self._issue_to_pull_request(body)
        if pr_body is None:
            return

        event = self._pull_request_to_event(pr_body)
        event.account = self._get_sender(body)
        event.comment = body.get('comment').get('body')
        event.type = 'pr-comment'
        return event

    def _event_pull_request_review(self, body):
        """Handles pull request reviews"""
        action = body.get('action')
        if action != 'submitted':
            return
        pr_body = body.get('pull_request')
        if pr_body is None:
            return

        review = body.get('review')
        if review is None:
            return

        event = self._pull_request_to_event(pr_body)
        event.state = review.get('state')
        event.account = self._get_sender(body)
        event.type = 'pr-review'
        return event

    def _event_status(self, body):
        action = body.get('action')
        if action == 'pending':
            return
        pr_body = self.connection.getPullBySha(body['name'], body['sha'])
        if pr_body is None:
            return

        event = self._pull_request_to_event(pr_body)
        event.account = self._get_sender(body)
        event.type = 'status'
        return event

    def _issue_to_pull_request(self, body):
        number = body.get('issue').get('number')
        project_name = body.get('repository').get('full_name')
        pr_body = self.connection.getPull(project_name, number)
        if pr_body is None:
            self.log.debug('Pull request #%s not found in project %s' %
                           (number, project_name))
        return pr_body

    def _validate_signature(self, request):
        secret = self.connection.connection_config.get('webhook_token', None)
        if secret is None:
            return True

        body = request.body
        try:
            request_signature = request.headers['X-Hub-Signature']
        except KeyError:
            raise webob.exc.HTTPUnauthorized(
                'Please specify a X-Hub-Signature header with secret.')

        payload_signature = 'sha1=' + hmac.new(secret,
                                               body,
                                               hashlib.sha1).hexdigest()

        self.log.debug("Payload Signature: {0}".format(str(payload_signature)))
        self.log.debug("Request Signature: {0}".format(str(request_signature)))
        if str(payload_signature) != str(request_signature):
            raise webob.exc.HTTPUnauthorized(
                'Request signature does not match calculated payload '
                'signature. Check that secret is correct.')

        return True

    def _pull_request_to_event(self, pr_body):
        event = GithubTriggerEvent()
        event.connection_name = self.connection.connection_name
        event.trigger_name = 'github'

        base = pr_body.get('base')
        base_repo = base.get('repo')
        head = pr_body.get('head')

        event.project_name = base_repo.get('full_name')
        event.change_number = pr_body.get('number')
        event.change_url = self.connection.getPullUrl(event.project_name,
                                                      event.change_number)
        event.updated_at = pr_body.get('updated_at')
        event.branch = base.get('ref')
        event.refspec = "refs/pull/" + str(pr_body.get('number')) + "/head"
        event.patch_number = head.get('sha')

        event.title = pr_body.get('title')

        # get the statuses
        event.statuses = self._get_statuses(event.project_name,
                                            event.patch_number)

        return event

    def _get_statuses(self, project, sha):
        # A ref can have more than one status from each context,
        # however the API returns them in order, newest first.
        # So we can keep track of which contexts we've already seen
        # and throw out the rest. Our unique key is based on
        # the user and the context, since context is free form and anybody
        # can put whatever they want there. We want to ensure we track it
        # by user, so that we can require/trigger by user too.
        seen = []
        statuses = []
        for status in self.connection.getCommitStatuses(project, sha):
            # creator can be None if the user has been removed.
            creator = status.get('creator')
            if not creator:
                continue
            user = creator.get('login')
            context = status.get('context')
            state = status.get('state')
            if "%s:%s" % (user, context) not in seen:
                statuses.append("%s:%s:%s" % (user, context, state))
                seen.append("%s:%s" % (user, context))

        return statuses

    def _get_sender(self, body):
        login = body.get('sender').get('login')
        if login:
            return self.connection.getUser(login)


class GithubUser(collections.Mapping):
    log = logging.getLogger('zuul.GithubUser')

    def __init__(self, github, username):
        self._github = github
        self._username = username
        self._data = None

    def __getitem__(self, key):
        if self._data is None:
            self._data = self._init_data()
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def _init_data(self):
        user = self._github.user(self._username)
        log_rate_limit(self.log, self._github)
        data = {
            'username': user.login,
            'name': user.name,
            'email': user.email
        }
        return data


class GithubConnection(BaseConnection):
    driver_name = 'github'
    log = logging.getLogger("zuul.GithubConnection")
    payload_path = 'payload'

    def __init__(self, connection_name, connection_config):
        super(GithubConnection, self).__init__(
            connection_name, connection_config)
        self._change_cache = {}

        self.git_ssh_key = self.connection_config.get('sshkey')
        self.git_host = self.connection_config.get('git_host', 'github.com')

    def onLoad(self):
        webhook_listener = GithubWebhookListener(self)
        self.registerHttpHandler(self.payload_path,
                                 webhook_listener.handle_request)
        self._authenticateGithubAPI()

    def onStop(self):
        self.unregisterHttpHandler(self.payload_path)

    def _authenticateGithubAPI(self):
        config = self.connection_config

        api_token = config.get('api_token')

        integration_id = config.get('integration_id')
        integration_key = None
        integration_key_file = config.get('integration_key')

        if api_token:
            self._github.login(token=api_token)

        self.api = GithubAPI(GithubTokenAuth(api_token))

        if integration_key_file:
            try:
                with open(integration_key_file, 'r') as f:
                    integration_key = f.read()
            except IOError:
                m = "Failed to open integration key file for reading: %s"
                self.log.error(m, integration_key_file)

        if (integration_id or integration_key) and \
                not (integration_id and integration_key):
            self.log.warning("You must provide an integration_id and "
                             "integration_key to use installation based "
                             "authentication")

            return

        if integration_id:
            self.integration_id = int(integration_id)
        if integration_key:
            self.integration_key = integration_key

    def getGitUrl(self, project):
        if self.git_ssh_key:
            return 'ssh://git@%s/%s.git' % (self.git_host, project)

        if self.integration_id:
            installation_key = self._get_installation_key(project)
            return 'https://x-access-token:%s@%s/%s' % (installation_key,
                                                        self.git_host,
                                                        project)

        return 'https://%s/%s' % (self.git_host, project)

    def getGitwebUrl(self, project, sha=None):
        url = 'https://%s/%s' % (self.git_host, project)
        if sha is not None:
            url += '/commit/%s' % sha
        return url

    def getPullUrl(self, project, number):
        return '%s/pull/%s' % (self.getGitwebUrl(project), number)

    def __getattr__(self, name):
        names = ['getPull',
                 'getPullBySha',
                 'getPullFileNames',
                 'getPullReviews',
                 'getRepoPermission',
                 'commentPull',
                 'mergePull',
                 'getCommitStatuses',
                 'setCommitStatus',
                 'labelPull',
                 'unlabelPull']

        if name in names:
            def f(*args, **kwargs):
                return getattr(self.api, name)(*args, **kwargs)

            return f

        raise AttributeError(name)

    def getUser(self, login):
        return GithubUser(self.getGithubClient(), login)

    def getUserUri(self, login):
        return 'https://%s/%s' % (self.git_host, login)


def log_rate_limit(log, github):
    try:
        rate_limit = github.rate_limit()
        remaining = rate_limit['resources']['core']['remaining']
        reset = rate_limit['resources']['core']['reset']
    except:
        return
    log.debug('GitHub API rate limit remaining: %s reset: %s' %
              (remaining, reset))


def getSchema():
    github_connection = v.Any(str, v.Schema({}, extra=True))
    return github_connection
