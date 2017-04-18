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

import cachecontrol
from cachecontrol.cache import DictCache
import iso8601
import jwt
import requests
import webob
import webob.dec
import voluptuous as v
import github3
from github3.exceptions import MethodNotAllowed
from tenacity import retry, retry_if_exception_type, stop_after_attempt

from zuul.connection import BaseConnection
from zuul.exceptions import MergeFailure
from zuul.model import GithubTriggerEvent

ACCESS_TOKEN_URL = 'https://api.github.com/installations/%s/access_tokens'
PREVIEW_JSON_ACCEPT = 'application/vnd.github.machine-man-preview+json'
RETRY_LIMIT = 3


class UTC(datetime.tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return datetime.timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return datetime.timedelta(0)


utc = UTC()


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

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
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

        # If there's any installation mapping information in the body then
        # update the project mapping before any requests are made.
        installation_id = json_body.get('installation', {}).get('id')
        project_name = json_body.get('repository', {}).get('full_name')

        if installation_id and project_name:
            old_id = self.connection.installation_map.get(project_name)

            if old_id and old_id != installation_id:
                msg = "Unexpected installation_id change for %s. %d -> %d."
                self.log.warning(msg, project_name, old_id, installation_id)

            self.connection.installation_map[project_name] = installation_id

        try:
            event = method(json_body)
        except:
            self.log.exception('Exception when handling event:')
            event = None

        if event:
            self.log.debug('Scheduling github event: {0}'.format(event.type))
            self.connection.sched.addEvent(event)

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
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

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
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

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
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

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
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

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def _event_status(self, body):
        action = body.get('action')
        if action == 'pending':
            return
        pr_body = self.connection.getPullBySha(body['sha'])
        if pr_body is None:
            return

        event = self._pull_request_to_event(pr_body)
        event.account = self._get_sender(body)
        event.type = 'status'
        # Github API is silly. Webhook blob sets author data in
        # 'sender', but API call to get status puts it in 'creator'.
        # Duplicate the data so our code can look in one place
        body['creator'] = body['sender']
        event.event_status = "%s:%s:%s" % self._status_as_tuple(body)
        return event

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def _issue_to_pull_request(self, body):
        number = body.get('issue').get('number')
        project_name = body.get('repository').get('full_name')
        owner, project = project_name.split('/')
        pr_body = self.connection.getPull(owner, project, number)
        if pr_body is None:
            self.log.debug('Pull request #%s not found in project %s' %
                           (number, project_name))
        return pr_body

    @retry(stop=stop_after_attempt(RETRY_LIMIT),
           retry=retry_if_exception_type(KeyError))
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

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
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
        owner, project = event.project_name.split('/')
        event.statuses = self._get_statuses(owner, project, event.patch_number)

        return event

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def _get_statuses(self, owner, project, sha):
        # A ref can have more than one status from each context,
        # however the API returns them in order, newest first.
        # So we can keep track of which contexts we've already seen
        # and throw out the rest. Our unique key is based on
        # the user and the context, since context is free form and anybody
        # can put whatever they want there. We want to ensure we track it
        # by user, so that we can require/trigger by user too.
        seen = []
        statuses = []
        for status in self.connection.getCommitStatuses(owner, project, sha):
            stuple = self._status_as_tuple(status)
            if "%s:%s" % (stuple[0], stuple[1]) not in seen:
                statuses.append("%s:%s:%s" % stuple)
                seen.append("%s:%s" % (stuple[0], stuple[1]))

        return statuses

    def _status_as_tuple(self, status):
        """Translate a status into a tuple of user, context, state"""

        creator = status.get('creator')
        if not creator:
            user = "Unknown"
        else:
            user = creator.get('login')
        context = status.get('context')
        state = status.get('state')
        return (user, context, state)

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
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

        self._github = None

        # NOTE(jamielennox): Better here would be to cache to memcache or file
        # or something external - but zuul already sucks at restarting so in
        # memory probably doesn't make this much worse.
        self.cache_adapter = cachecontrol.CacheControlAdapter(
            DictCache(),
            cache_etags=True)

        self.integration_id = None
        self.integration_key = None

        self.installation_map = {}
        self.installation_token_cache = {}

    def onLoad(self):
        webhook_listener = GithubWebhookListener(self)
        self.registerHttpHandler(self.payload_path,
                                 webhook_listener.handle_request)
        self._authenticateGithubAPI()

    def onStop(self):
        self.unregisterHttpHandler(self.payload_path)

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def _createGithubClient(self):
        if self.git_host != 'github.com':
            url = 'https://%s/' % self.git_host
            github = github3.GitHubEnterprise(url)
        else:
            github = github3.GitHub()

        # anything going through requests to http/s goes through cache
        github.session.mount('http://', self.cache_adapter)
        github.session.mount('https://', self.cache_adapter)

        return github

    @retry(stop=stop_after_attempt(RETRY_LIMIT),
           retry=retry_if_exception_type(IOError))
    def _authenticateGithubAPI(self):
        config = self.connection_config

        api_token = config.get('api_token')

        integration_id = config.get('integration_id')
        integration_key = None
        integration_key_file = config.get('integration_key')

        self._github = self._createGithubClient()

        if api_token:
            self._github.login(token=api_token)

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

    def _get_installation_key(self, project, user_id=None):
        installation_id = self.installation_map.get(project)

        if not installation_id:
            self.log.debug("No installation ID available for project %s",
                           project)
            return None

        now = datetime.datetime.now(utc)
        token, expiry = self.installation_token_cache.get(installation_id,
                                                          (None, None))

        if ((not expiry) or (not token) or (now >= expiry)):
            expiry = now + datetime.timedelta(minutes=5)

            data = {'iat': now, 'exp': expiry, 'iss': self.integration_id}
            integration_token = jwt.encode(data,
                                           self.integration_key,
                                           algorithm='RS256')

            url = ACCESS_TOKEN_URL % installation_id
            headers = {'Accept': PREVIEW_JSON_ACCEPT,
                       'Authorization': 'Bearer %s' % integration_token}
            json_data = {'user_id': user_id} if user_id else None

            response = requests.post(url, headers=headers, json=json_data)
            response.raise_for_status()

            data = response.json()

            expiry = iso8601.parse_date(data['expires_at'])
            expiry -= datetime.timedelta(minutes=2)
            token = data['token']

            self.installation_token_cache[installation_id] = (token, expiry)

        return token

    def getGithubClient(self,
                        project=None,
                        user_id=None,
                        use_integration=True):
        # if you're authenticating for a project and you're an integration then
        # you need to use the installation specific token. There are some
        # operations that are not yet supported by integrations so
        # use_integration lets you use api_key auth.
        if use_integration and project and self.integration_id:
            token = self._get_installation_key(project, user_id)

            if token:
                github = self._createGithubClient()
                github.login(token=token)
                return github

        # if we're using api_key authentication then this is already token
        # authenticated, if not then anonymous is the best we have.
        return self._github

    def maintainCache(self, relevant):
        for key, change in self._change_cache.items():
            if change not in relevant:
                del self._change_cache[key]

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def getGitUrl(self, project):
        if self.integration_id:
            installation_key = self._get_installation_key(project)
            if installation_key:
                return 'https://x-access-token:%s@%s/%s' % (installation_key,
                                                            self.git_host,
                                                            project)

        if self.git_ssh_key:
            return 'ssh://git@%s/%s.git' % (self.git_host, project)

        return 'https://%s/%s' % (self.git_host, project)

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def getGitwebUrl(self, project, sha=None):
        url = 'https://%s/%s' % (self.git_host, project)
        if sha is not None:
            url += '/commit/%s' % sha
        return url

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def getPullUrl(self, project, number):
        return '%s/pull/%s' % (self.getGitwebUrl(project), number)

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def getPull(self, owner, project, number):
        github = self.getGithubClient("%s/%s" % (owner, project))
        pr = github.pull_request(owner, project, number)
        log_rate_limit(self.log, github)
        if not pr:
            return None
        return pr.as_dict()

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def getPullBySha(self, sha):
        query = '%s type:pr is:open' % sha
        pulls = []
        github = self.getGithubClient()
        for issue in github.search_issues(query=query):
            pr_url = issue.issue.pull_request().as_dict().get('url')
            if not pr_url:
                continue
            # the issue provides no good description of the project :\
            owner, project, _, number = pr_url.split('/')[4:]
            github = self.getGithubClient("%s/%s" % (owner, project))
            pr = github.pull_request(owner, project, number)
            if pr.head.sha != sha:
                continue
            if pr.as_dict() in pulls:
                continue
            pulls.append(pr.as_dict())

        if len(pulls) > 1:
            raise Exception('Multiple pulls found with head sha %s' % sha)

        log_rate_limit(self.log, github)
        if len(pulls) == 0:
            return None
        return pulls.pop()

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def getPullFileNames(self, owner, project, number):
        github = self.getGithubClient("%s/%s" % (owner, project))
        filenames = [f.filename for f in
                     github.pull_request(owner, project, number).files()]
        log_rate_limit(self.log, github)
        return filenames

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def getPullReviews(self, owner, project, number):
        # make a list out of the reviews so that we complete our
        # API transaction
        # reviews are not yet supported by integrations, use api_key:
        # https://platform.github.community/t/api-endpoint-for-pr-reviews/409
        github = self.getGithubClient("%s/%s" % (owner, project),
                                      use_integration=False)
        reviews = [review.as_dict() for review in
                   github.pull_request(owner, project, number).reviews()]
        log_rate_limit(self.log, github)
        return reviews

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def getUser(self, login):
        return GithubUser(self.getGithubClient(), login)

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def getUserUri(self, login):
        return 'https://%s/%s' % (self.git_host, login)

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def getRepoPermission(self, owner, project, login):
        # This gets around a missing API call
        # need preview header
        github = self.getGithubClient("%s/%s" % (owner, project))
        headers = {'Accept': 'application/vnd.github.korra-preview'}

        # Create a repo object
        repository = github.repository(owner, project)
        # Build up a URL
        url = repository._build_url('collaborators', login, 'permission',
                                    base_url=repository._api)
        # Get the data
        perms = repository._get(url, headers=headers)

        log_rate_limit(self.log, github)

        # no known user, maybe deleted since review?
        if perms.status_code == 404:
            return 'none'

        # get permissions from the data
        return perms.json()['permission']

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def commentPull(self, owner, project, pr_number, message):
        github = self.getGithubClient("%s/%s" % (owner, project))
        pull_request = github.issue(owner, project, pr_number)
        pull_request.create_comment(message)
        log_rate_limit(self.log, github)

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def mergePull(self, owner, project, pr_number, commit_message='',
                  sha=None):
        github = self.getGithubClient("%s/%s" % (owner, project))
        pull_request = github.pull_request(owner, project, pr_number)
        try:
            result = pull_request.merge(commit_message=commit_message, sha=sha)
        except MethodNotAllowed as e:
            raise MergeFailure('Merge was not successful due to mergeability'
                               ' conflict, original error is %s' % e)
        log_rate_limit(self.log, github)
        if not result:
            raise Exception('Pull request was not merged')

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def getCommitStatuses(self, owner, project, sha):
        github = self.getGithubClient("%s/%s" % (owner, project))
        repository = github.repository(owner, project)
        commit = repository.commit(sha)
        # make a list out of the statuses so that we complete our
        # API transaction
        statuses = [status.as_dict() for status in commit.statuses()]

        log_rate_limit(self.log, github)
        return statuses

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def setCommitStatus(self, owner, project, sha, state,
                        url='', description='', context=''):
        github = self.getGithubClient("%s/%s" % (owner, project))
        self.log.debug('Setting commit status: %s', state)
        repository = github.repository(owner, project)
        self.log.debug('Calling create_status: sha: %s, state: %s, url: %s,'
                       ' description: %s, context: %s', sha, state, url,
                       description, context)
        repository.create_status(sha, state, url, description, context)
        log_rate_limit(self.log, github)

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def labelPull(self, owner, project, pr_number, label):
        github = self.getGithubClient("%s/%s" % (owner, project))
        pull_request = github.issue(owner, project, pr_number)
        pull_request.add_labels(label)
        log_rate_limit(self.log, github)

    @retry(stop=stop_after_attempt(RETRY_LIMIT))
    def unlabelPull(self, owner, project, pr_number, label):
        github = self.getGithubClient("%s/%s" % (owner, project))
        pull_request = github.issue(owner, project, pr_number)
        pull_request.remove_label(label)
        log_rate_limit(self.log, github)


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
