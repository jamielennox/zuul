#!/usr/bin/env python

# Copyright 2012 Hewlett-Packard Development Company, L.P.
# Copyright 2016 Red Hat, Inc.
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

from six.moves import configparser as ConfigParser
import gc
import hashlib
import json
import logging
import os
from six.moves import queue as Queue
from six.moves import urllib
import random
import re
import select
import shutil
from six.moves import reload_module
try:
    from cStringIO import StringIO
except Exception:
    from six import StringIO
import socket
import string
import subprocess
import sys
import tempfile
import threading
import traceback
import time
import uuid


import git
import gear
import fixtures
import kazoo.client
import kazoo.exceptions
import pymysql
import statsd
import testtools
import testtools.content
import testtools.content_type
from git.exc import NoSuchPathError
import yaml

import zuul.driver.gerrit.gerritsource as gerritsource
import zuul.driver.gerrit.gerritconnection as gerritconnection
import zuul.scheduler
import zuul.webapp
import zuul.rpclistener
import zuul.executor.server
import zuul.executor.client
import zuul.lib.connections
import zuul.merger.client
import zuul.merger.merger
import zuul.merger.server
import zuul.nodepool
import zuul.zk

FIXTURE_DIR = os.path.join(os.path.dirname(__file__),
                           'fixtures')

KEEP_TEMPDIRS = bool(os.environ.get('KEEP_TEMPDIRS', False))


def repack_repo(path):
    cmd = ['git', '--git-dir=%s/.git' % path, 'repack', '-afd']
    output = subprocess.Popen(cmd, close_fds=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    out = output.communicate()
    if output.returncode:
        raise Exception("git repack returned %d" % output.returncode)
    return out


def random_sha1():
    return hashlib.sha1(str(random.random())).hexdigest()


def iterate_timeout(max_seconds, purpose):
    start = time.time()
    count = 0
    while (time.time() < start + max_seconds):
        count += 1
        yield count
        time.sleep(0)
    raise Exception("Timeout waiting for %s" % purpose)


def simple_layout(path, driver='gerrit'):
    """Specify a layout file for use by a test method.

    :arg str path: The path to the layout file.
    :arg str driver: The source driver to use, defaults to gerrit.

    Some tests require only a very simple configuration.  For those,
    establishing a complete config directory hierachy is too much
    work.  In those cases, you can add a simple zuul.yaml file to the
    test fixtures directory (in fixtures/layouts/foo.yaml) and use
    this decorator to indicate the test method should use that rather
    than the tenant config file specified by the test class.

    The decorator will cause that layout file to be added to a
    config-project called "common-config" and each "project" instance
    referenced in the layout file will have a git repo automatically
    initialized.
    """

    def decorator(test):
        test.__simple_layout__ = (path, driver)
        return test
    return decorator


class ChangeReference(git.Reference):
    _common_path_default = "refs/changes"
    _points_to_commits_only = True


class FakeChange(object):
    categories = {'approved': ('Approved', -1, 1),
                  'code-review': ('Code-Review', -2, 2),
                  'verified': ('Verified', -2, 2)}

    def __init__(self, gerrit, number, project, branch, subject,
                 status='NEW', upstream_root=None, files={}):
        self.gerrit = gerrit
        self.reported = 0
        self.queried = 0
        self.patchsets = []
        self.number = number
        self.project = project
        self.branch = branch
        self.subject = subject
        self.latest_patchset = 0
        self.depends_on_change = None
        self.needed_by_changes = []
        self.fail_merge = False
        self.messages = []
        self.data = {
            'branch': branch,
            'comments': [],
            'commitMessage': subject,
            'createdOn': time.time(),
            'id': 'I' + random_sha1(),
            'lastUpdated': time.time(),
            'number': str(number),
            'open': status == 'NEW',
            'owner': {'email': 'user@example.com',
                      'name': 'User Name',
                      'username': 'username'},
            'patchSets': self.patchsets,
            'project': project,
            'status': status,
            'subject': subject,
            'submitRecords': [],
            'url': 'https://hostname/%s' % number}

        self.upstream_root = upstream_root
        self.addPatchset(files=files)
        self.data['submitRecords'] = self.getSubmitRecords()
        self.open = status == 'NEW'

    def addFakeChangeToRepo(self, msg, files, large):
        path = os.path.join(self.upstream_root, self.project)
        repo = git.Repo(path)
        ref = ChangeReference.create(repo, '1/%s/%s' % (self.number,
                                                        self.latest_patchset),
                                     'refs/tags/init')
        repo.head.reference = ref
        zuul.merger.merger.reset_repo_to_head(repo)
        repo.git.clean('-x', '-f', '-d')

        path = os.path.join(self.upstream_root, self.project)
        if not large:
            for fn, content in files.items():
                fn = os.path.join(path, fn)
                with open(fn, 'w') as f:
                    f.write(content)
                repo.index.add([fn])
        else:
            for fni in range(100):
                fn = os.path.join(path, str(fni))
                f = open(fn, 'w')
                for ci in range(4096):
                    f.write(random.choice(string.printable))
                f.close()
                repo.index.add([fn])

        r = repo.index.commit(msg)
        repo.head.reference = 'master'
        zuul.merger.merger.reset_repo_to_head(repo)
        repo.git.clean('-x', '-f', '-d')
        repo.heads['master'].checkout()
        return r

    def addPatchset(self, files=None, large=False):
        self.latest_patchset += 1
        if not files:
            fn = '%s-%s' % (self.branch.replace('/', '_'), self.number)
            data = ("test %s %s %s\n" %
                    (self.branch, self.number, self.latest_patchset))
            files = {fn: data}
        msg = self.subject + '-' + str(self.latest_patchset)
        c = self.addFakeChangeToRepo(msg, files, large)
        ps_files = [{'file': '/COMMIT_MSG',
                     'type': 'ADDED'},
                    {'file': 'README',
                     'type': 'MODIFIED'}]
        for f in files.keys():
            ps_files.append({'file': f, 'type': 'ADDED'})
        d = {'approvals': [],
             'createdOn': time.time(),
             'files': ps_files,
             'number': str(self.latest_patchset),
             'ref': 'refs/changes/1/%s/%s' % (self.number,
                                              self.latest_patchset),
             'revision': c.hexsha,
             'uploader': {'email': 'user@example.com',
                          'name': 'User name',
                          'username': 'user'}}
        self.data['currentPatchSet'] = d
        self.patchsets.append(d)
        self.data['submitRecords'] = self.getSubmitRecords()

    def getPatchsetCreatedEvent(self, patchset):
        event = {"type": "patchset-created",
                 "change": {"project": self.project,
                            "branch": self.branch,
                            "id": "I5459869c07352a31bfb1e7a8cac379cabfcb25af",
                            "number": str(self.number),
                            "subject": self.subject,
                            "owner": {"name": "User Name"},
                            "url": "https://hostname/3"},
                 "patchSet": self.patchsets[patchset - 1],
                 "uploader": {"name": "User Name"}}
        return event

    def getChangeRestoredEvent(self):
        event = {"type": "change-restored",
                 "change": {"project": self.project,
                            "branch": self.branch,
                            "id": "I5459869c07352a31bfb1e7a8cac379cabfcb25af",
                            "number": str(self.number),
                            "subject": self.subject,
                            "owner": {"name": "User Name"},
                            "url": "https://hostname/3"},
                 "restorer": {"name": "User Name"},
                 "patchSet": self.patchsets[-1],
                 "reason": ""}
        return event

    def getChangeAbandonedEvent(self):
        event = {"type": "change-abandoned",
                 "change": {"project": self.project,
                            "branch": self.branch,
                            "id": "I5459869c07352a31bfb1e7a8cac379cabfcb25af",
                            "number": str(self.number),
                            "subject": self.subject,
                            "owner": {"name": "User Name"},
                            "url": "https://hostname/3"},
                 "abandoner": {"name": "User Name"},
                 "patchSet": self.patchsets[-1],
                 "reason": ""}
        return event

    def getChangeCommentEvent(self, patchset):
        event = {"type": "comment-added",
                 "change": {"project": self.project,
                            "branch": self.branch,
                            "id": "I5459869c07352a31bfb1e7a8cac379cabfcb25af",
                            "number": str(self.number),
                            "subject": self.subject,
                            "owner": {"name": "User Name"},
                            "url": "https://hostname/3"},
                 "patchSet": self.patchsets[patchset - 1],
                 "author": {"name": "User Name"},
                 "approvals": [{"type": "code-review",
                                "description": "Code-Review",
                                "value": "0"}],
                 "comment": "This is a comment"}
        return event

    def getChangeMergedEvent(self):
        event = {"submitter": {"name": "Jenkins",
                               "username": "jenkins"},
                 "newRev": "29ed3b5f8f750a225c5be70235230e3a6ccb04d9",
                 "patchSet": self.patchsets[-1],
                 "change": self.data,
                 "type": "change-merged",
                 "eventCreatedOn": 1487613810}
        return event

    def getRefUpdatedEvent(self):
        path = os.path.join(self.upstream_root, self.project)
        repo = git.Repo(path)
        oldrev = repo.heads[self.branch].commit.hexsha

        event = {
            "type": "ref-updated",
            "submitter": {
                "name": "User Name",
            },
            "refUpdate": {
                "oldRev": oldrev,
                "newRev": self.patchsets[-1]['revision'],
                "refName": self.branch,
                "project": self.project,
            }
        }
        return event

    def addApproval(self, category, value, username='reviewer_john',
                    granted_on=None, message=''):
        if not granted_on:
            granted_on = time.time()
        approval = {
            'description': self.categories[category][0],
            'type': category,
            'value': str(value),
            'by': {
                'username': username,
                'email': username + '@example.com',
            },
            'grantedOn': int(granted_on)
        }
        for i, x in enumerate(self.patchsets[-1]['approvals'][:]):
            if x['by']['username'] == username and x['type'] == category:
                del self.patchsets[-1]['approvals'][i]
        self.patchsets[-1]['approvals'].append(approval)
        event = {'approvals': [approval],
                 'author': {'email': 'author@example.com',
                            'name': 'Patchset Author',
                            'username': 'author_phil'},
                 'change': {'branch': self.branch,
                            'id': 'Iaa69c46accf97d0598111724a38250ae76a22c87',
                            'number': str(self.number),
                            'owner': {'email': 'owner@example.com',
                                      'name': 'Change Owner',
                                      'username': 'owner_jane'},
                            'project': self.project,
                            'subject': self.subject,
                            'topic': 'master',
                            'url': 'https://hostname/459'},
                 'comment': message,
                 'patchSet': self.patchsets[-1],
                 'type': 'comment-added'}
        self.data['submitRecords'] = self.getSubmitRecords()
        return json.loads(json.dumps(event))

    def getSubmitRecords(self):
        status = {}
        for cat in self.categories.keys():
            status[cat] = 0

        for a in self.patchsets[-1]['approvals']:
            cur = status[a['type']]
            cat_min, cat_max = self.categories[a['type']][1:]
            new = int(a['value'])
            if new == cat_min:
                cur = new
            elif abs(new) > abs(cur):
                cur = new
            status[a['type']] = cur

        labels = []
        ok = True
        for typ, cat in self.categories.items():
            cur = status[typ]
            cat_min, cat_max = cat[1:]
            if cur == cat_min:
                value = 'REJECT'
                ok = False
            elif cur == cat_max:
                value = 'OK'
            else:
                value = 'NEED'
                ok = False
            labels.append({'label': cat[0], 'status': value})
        if ok:
            return [{'status': 'OK'}]
        return [{'status': 'NOT_READY',
                 'labels': labels}]

    def setDependsOn(self, other, patchset):
        self.depends_on_change = other
        d = {'id': other.data['id'],
             'number': other.data['number'],
             'ref': other.patchsets[patchset - 1]['ref']
             }
        self.data['dependsOn'] = [d]

        other.needed_by_changes.append(self)
        needed = other.data.get('neededBy', [])
        d = {'id': self.data['id'],
             'number': self.data['number'],
             'ref': self.patchsets[patchset - 1]['ref'],
             'revision': self.patchsets[patchset - 1]['revision']
             }
        needed.append(d)
        other.data['neededBy'] = needed

    def query(self):
        self.queried += 1
        d = self.data.get('dependsOn')
        if d:
            d = d[0]
            if (self.depends_on_change.patchsets[-1]['ref'] == d['ref']):
                d['isCurrentPatchSet'] = True
            else:
                d['isCurrentPatchSet'] = False
        return json.loads(json.dumps(self.data))

    def setMerged(self):
        if (self.depends_on_change and
                self.depends_on_change.data['status'] != 'MERGED'):
            return
        if self.fail_merge:
            return
        self.data['status'] = 'MERGED'
        self.open = False

        path = os.path.join(self.upstream_root, self.project)
        repo = git.Repo(path)
        repo.heads[self.branch].commit = \
            repo.commit(self.patchsets[-1]['revision'])

    def setReported(self):
        self.reported += 1


class FakeGerritConnection(gerritconnection.GerritConnection):
    """A Fake Gerrit connection for use in tests.

    This subclasses
    :py:class:`~zuul.connection.gerrit.GerritConnection` to add the
    ability for tests to add changes to the fake Gerrit it represents.
    """

    log = logging.getLogger("zuul.test.FakeGerritConnection")

    def __init__(self, driver, connection_name, connection_config,
                 changes_db=None, upstream_root=None):
        super(FakeGerritConnection, self).__init__(driver, connection_name,
                                                   connection_config)

        self.event_queue = Queue.Queue()
        self.fixture_dir = os.path.join(FIXTURE_DIR, 'gerrit')
        self.change_number = 0
        self.changes = changes_db
        self.queries = []
        self.upstream_root = upstream_root

    def addFakeChange(self, project, branch, subject, status='NEW',
                      files=None):
        """Add a change to the fake Gerrit."""
        self.change_number += 1
        c = FakeChange(self, self.change_number, project, branch, subject,
                       upstream_root=self.upstream_root,
                       status=status, files=files)
        self.changes[self.change_number] = c
        return c

    def review(self, project, changeid, message, action):
        number, ps = changeid.split(',')
        change = self.changes[int(number)]

        # Add the approval back onto the change (ie simulate what gerrit would
        # do).
        # Usually when zuul leaves a review it'll create a feedback loop where
        # zuul's review enters another gerrit event (which is then picked up by
        # zuul). However, we can't mimic this behaviour (by adding this
        # approval event into the queue) as it stops jobs from checking what
        # happens before this event is triggered. If a job needs to see what
        # happens they can add their own verified event into the queue.
        # Nevertheless, we can update change with the new review in gerrit.

        for cat in action.keys():
            if cat != 'submit':
                change.addApproval(cat, action[cat], username=self.user)

        # TODOv3(jeblair): can this be removed?
        if 'label' in action:
            parts = action['label'].split('=')
            change.addApproval(parts[0], parts[2], username=self.user)

        change.messages.append(message)

        if 'submit' in action:
            change.setMerged()
        if message:
            change.setReported()

    def query(self, number):
        change = self.changes.get(int(number))
        if change:
            return change.query()
        return {}

    def simpleQuery(self, query):
        self.log.debug("simpleQuery: %s" % query)
        self.queries.append(query)
        if query.startswith('change:'):
            # Query a specific changeid
            changeid = query[len('change:'):]
            l = [change.query() for change in self.changes.values()
                 if change.data['id'] == changeid]
        elif query.startswith('message:'):
            # Query the content of a commit message
            msg = query[len('message:'):].strip()
            l = [change.query() for change in self.changes.values()
                 if msg in change.data['commitMessage']]
        else:
            # Query all open changes
            l = [change.query() for change in self.changes.values()]
        return l

    def _start_watcher_thread(self, *args, **kw):
        pass

    def getGitUrl(self, project):
        return os.path.join(self.upstream_root, project.name)


class BuildHistory(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def __repr__(self):
        return ("<Completed build, result: %s name: %s uuid: %s changes: %s>" %
                (self.result, self.name, self.uuid, self.changes))


class FakeURLOpener(object):
    def __init__(self, upstream_root, url):
        self.upstream_root = upstream_root
        self.url = url

    def read(self):
        res = urllib.parse.urlparse(self.url)
        path = res.path
        project = '/'.join(path.split('/')[2:-2])
        ret = '001e# service=git-upload-pack\n'
        ret += ('000000a31270149696713ba7e06f1beb760f20d359c4abed HEAD\x00'
                'multi_ack thin-pack side-band side-band-64k ofs-delta '
                'shallow no-progress include-tag multi_ack_detailed no-done\n')
        path = os.path.join(self.upstream_root, project)
        repo = git.Repo(path)
        for ref in repo.refs:
            r = ref.object.hexsha + ' ' + ref.path + '\n'
            ret += '%04x%s' % (len(r) + 4, r)
        ret += '0000'
        return ret


class FakeStatsd(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', 0))
        self.port = self.sock.getsockname()[1]
        self.wake_read, self.wake_write = os.pipe()
        self.stats = []

    def run(self):
        while True:
            poll = select.poll()
            poll.register(self.sock, select.POLLIN)
            poll.register(self.wake_read, select.POLLIN)
            ret = poll.poll()
            for (fd, event) in ret:
                if fd == self.sock.fileno():
                    data = self.sock.recvfrom(1024)
                    if not data:
                        return
                    self.stats.append(data[0])
                if fd == self.wake_read:
                    return

    def stop(self):
        os.write(self.wake_write, '1\n')


class FakeBuild(object):
    log = logging.getLogger("zuul.test")

    def __init__(self, executor_server, job):
        self.daemon = True
        self.executor_server = executor_server
        self.job = job
        self.jobdir = None
        self.uuid = job.unique
        self.parameters = json.loads(job.arguments)
        # TODOv3(jeblair): self.node is really "the image of the node
        # assigned".  We should rename it (self.node_image?) if we
        # keep using it like this, or we may end up exposing more of
        # the complexity around multi-node jobs here
        # (self.nodes[0].image?)
        self.node = None
        if len(self.parameters.get('nodes')) == 1:
            self.node = self.parameters['nodes'][0]['image']
        self.unique = self.parameters['ZUUL_UUID']
        self.pipeline = self.parameters['ZUUL_PIPELINE']
        self.project = self.parameters['ZUUL_PROJECT']
        self.name = self.parameters['job']
        self.wait_condition = threading.Condition()
        self.waiting = False
        self.aborted = False
        self.requeue = False
        self.created = time.time()
        self.changes = None
        if 'ZUUL_CHANGE_IDS' in self.parameters:
            self.changes = self.parameters['ZUUL_CHANGE_IDS']

    def __repr__(self):
        waiting = ''
        if self.waiting:
            waiting = ' [waiting]'
        return '<FakeBuild %s:%s %s%s>' % (self.pipeline, self.name,
                                           self.changes, waiting)

    def release(self):
        """Release this build."""
        self.wait_condition.acquire()
        self.wait_condition.notify()
        self.waiting = False
        self.log.debug("Build %s released" % self.unique)
        self.wait_condition.release()

    def isWaiting(self):
        """Return whether this build is being held.

        :returns: Whether the build is being held.
        :rtype: bool
        """

        self.wait_condition.acquire()
        if self.waiting:
            ret = True
        else:
            ret = False
        self.wait_condition.release()
        return ret

    def _wait(self):
        self.wait_condition.acquire()
        self.waiting = True
        self.log.debug("Build %s waiting" % self.unique)
        self.wait_condition.wait()
        self.wait_condition.release()

    def run(self):
        self.log.debug('Running build %s' % self.unique)

        if self.executor_server.hold_jobs_in_build:
            self.log.debug('Holding build %s' % self.unique)
            self._wait()
        self.log.debug("Build %s continuing" % self.unique)

        result = (RecordingAnsibleJob.RESULT_NORMAL, 0)  # Success
        if (('ZUUL_REF' in self.parameters) and self.shouldFail()):
            result = (RecordingAnsibleJob.RESULT_NORMAL, 1)  # Failure
        if self.aborted:
            result = (RecordingAnsibleJob.RESULT_ABORTED, None)
        if self.requeue:
            result = (RecordingAnsibleJob.RESULT_UNREACHABLE, None)

        return result

    def shouldFail(self):
        changes = self.executor_server.fail_tests.get(self.name, [])
        for change in changes:
            if self.hasChanges(change):
                return True
        return False

    def hasChanges(self, *changes):
        """Return whether this build has certain changes in its git repos.

        :arg FakeChange changes: One or more changes (varargs) that
            are expected to be present (in order) in the git repository of
            the active project.

        :returns: Whether the build has the indicated changes.
        :rtype: bool

        """
        for change in changes:
            path = os.path.join(self.jobdir.src_root, change.project)
            try:
                repo = git.Repo(path)
            except NoSuchPathError as e:
                self.log.debug('%s' % e)
                return False
            ref = self.parameters['ZUUL_REF']
            repo_messages = [c.message.strip() for c in repo.iter_commits(ref)]
            commit_message = '%s-1' % change.subject
            self.log.debug("Checking if build %s has changes; commit_message "
                           "%s; repo_messages %s" % (self, commit_message,
                                                     repo_messages))
            if commit_message not in repo_messages:
                self.log.debug("  messages do not match")
                return False
        self.log.debug("  OK")
        return True


class RecordingExecutorServer(zuul.executor.server.ExecutorServer):
    """An Ansible executor to be used in tests.

    :ivar bool hold_jobs_in_build: If true, when jobs are executed
        they will report that they have started but then pause until
        released before reporting completion.  This attribute may be
        changed at any time and will take effect for subsequently
        executed builds, but previously held builds will still need to
        be explicitly released.

    """
    def __init__(self, *args, **kw):
        self._run_ansible = kw.pop('_run_ansible', False)
        self._test_root = kw.pop('_test_root', False)
        super(RecordingExecutorServer, self).__init__(*args, **kw)
        self.hold_jobs_in_build = False
        self.lock = threading.Lock()
        self.running_builds = []
        self.build_history = []
        self.fail_tests = {}
        self.job_builds = {}

    def failJob(self, name, change):
        """Instruct the executor to report matching builds as failures.

        :arg str name: The name of the job to fail.
        :arg Change change: The :py:class:`~tests.base.FakeChange`
            instance which should cause the job to fail.  This job
            will also fail for changes depending on this change.

        """
        l = self.fail_tests.get(name, [])
        l.append(change)
        self.fail_tests[name] = l

    def release(self, regex=None):
        """Release a held build.

        :arg str regex: A regular expression which, if supplied, will
            cause only builds with matching names to be released.  If
            not supplied, all builds will be released.

        """
        builds = self.running_builds[:]
        self.log.debug("Releasing build %s (%s)" % (regex,
                                                    len(self.running_builds)))
        for build in builds:
            if not regex or re.match(regex, build.name):
                self.log.debug("Releasing build %s" %
                               (build.parameters['ZUUL_UUID']))
                build.release()
            else:
                self.log.debug("Not releasing build %s" %
                               (build.parameters['ZUUL_UUID']))
        self.log.debug("Done releasing builds %s (%s)" %
                       (regex, len(self.running_builds)))

    def executeJob(self, job):
        build = FakeBuild(self, job)
        job.build = build
        self.running_builds.append(build)
        self.job_builds[job.unique] = build
        args = json.loads(job.arguments)
        args['vars']['zuul']['_test'] = dict(test_root=self._test_root)
        job.arguments = json.dumps(args)
        self.job_workers[job.unique] = RecordingAnsibleJob(self, job)
        self.job_workers[job.unique].run()

    def stopJob(self, job):
        self.log.debug("handle stop")
        parameters = json.loads(job.arguments)
        uuid = parameters['uuid']
        for build in self.running_builds:
            if build.unique == uuid:
                build.aborted = True
                build.release()
        super(RecordingExecutorServer, self).stopJob(job)

    def stop(self):
        for build in self.running_builds:
            build.release()
        super(RecordingExecutorServer, self).stop()


class RecordingAnsibleJob(zuul.executor.server.AnsibleJob):
    def doMergeChanges(self, items):
        # Get a merger in order to update the repos involved in this job.
        commit = super(RecordingAnsibleJob, self).doMergeChanges(items)
        if not commit:  # merge conflict
            self.recordResult('MERGER_FAILURE')
        return commit

    def recordResult(self, result):
        build = self.executor_server.job_builds[self.job.unique]
        self.executor_server.lock.acquire()
        self.executor_server.build_history.append(
            BuildHistory(name=build.name, result=result, changes=build.changes,
                         node=build.node, uuid=build.unique,
                         parameters=build.parameters, jobdir=build.jobdir,
                         pipeline=build.parameters['ZUUL_PIPELINE'])
        )
        self.executor_server.running_builds.remove(build)
        del self.executor_server.job_builds[self.job.unique]
        self.executor_server.lock.release()

    def runPlaybooks(self, args):
        build = self.executor_server.job_builds[self.job.unique]
        build.jobdir = self.jobdir

        result = super(RecordingAnsibleJob, self).runPlaybooks(args)
        self.recordResult(result)
        return result

    def runAnsible(self, cmd, timeout, trusted=False):
        build = self.executor_server.job_builds[self.job.unique]

        if self.executor_server._run_ansible:
            result = super(RecordingAnsibleJob, self).runAnsible(
                cmd, timeout, trusted=trusted)
        else:
            result = build.run()
        return result

    def getHostList(self, args):
        self.log.debug("hostlist")
        hosts = super(RecordingAnsibleJob, self).getHostList(args)
        for host in hosts:
            host['host_vars']['ansible_connection'] = 'local'

        hosts.append(dict(
            name='localhost',
            host_vars=dict(ansible_connection='local'),
            host_keys=[]))
        return hosts


class FakeGearmanServer(gear.Server):
    """A Gearman server for use in tests.

    :ivar bool hold_jobs_in_queue: If true, submitted jobs will be
        added to the queue but will not be distributed to workers
        until released.  This attribute may be changed at any time and
        will take effect for subsequently enqueued jobs, but
        previously held jobs will still need to be explicitly
        released.

    """

    def __init__(self):
        self.hold_jobs_in_queue = False
        super(FakeGearmanServer, self).__init__(0)

    def getJobForConnection(self, connection, peek=False):
        for queue in [self.high_queue, self.normal_queue, self.low_queue]:
            for job in queue:
                if not hasattr(job, 'waiting'):
                    if job.name.startswith('executor:execute'):
                        job.waiting = self.hold_jobs_in_queue
                    else:
                        job.waiting = False
                if job.waiting:
                    continue
                if job.name in connection.functions:
                    if not peek:
                        queue.remove(job)
                        connection.related_jobs[job.handle] = job
                        job.worker_connection = connection
                    job.running = True
                    return job
        return None

    def release(self, regex=None):
        """Release a held job.

        :arg str regex: A regular expression which, if supplied, will
            cause only jobs with matching names to be released.  If
            not supplied, all jobs will be released.
        """
        released = False
        qlen = (len(self.high_queue) + len(self.normal_queue) +
                len(self.low_queue))
        self.log.debug("releasing queued job %s (%s)" % (regex, qlen))
        for job in self.getQueue():
            if job.name != 'executor:execute':
                continue
            parameters = json.loads(job.arguments)
            if not regex or re.match(regex, parameters.get('job')):
                self.log.debug("releasing queued job %s" %
                               job.unique)
                job.waiting = False
                released = True
            else:
                self.log.debug("not releasing queued job %s" %
                               job.unique)
        if released:
            self.wakeConnections()
        qlen = (len(self.high_queue) + len(self.normal_queue) +
                len(self.low_queue))
        self.log.debug("done releasing queued jobs %s (%s)" % (regex, qlen))


class FakeSMTP(object):
    log = logging.getLogger('zuul.FakeSMTP')

    def __init__(self, messages, server, port):
        self.server = server
        self.port = port
        self.messages = messages

    def sendmail(self, from_email, to_email, msg):
        self.log.info("Sending email from %s, to %s, with msg %s" % (
                      from_email, to_email, msg))

        headers = msg.split('\n\n', 1)[0]
        body = msg.split('\n\n', 1)[1]

        self.messages.append(dict(
            from_email=from_email,
            to_email=to_email,
            msg=msg,
            headers=headers,
            body=body,
        ))

        return True

    def quit(self):
        return True


class FakeNodepool(object):
    REQUEST_ROOT = '/nodepool/requests'
    NODE_ROOT = '/nodepool/nodes'

    log = logging.getLogger("zuul.test.FakeNodepool")

    def __init__(self, host, port, chroot):
        self.client = kazoo.client.KazooClient(
            hosts='%s:%s%s' % (host, port, chroot))
        self.client.start()
        self._running = True
        self.paused = False
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()
        self.fail_requests = set()

    def stop(self):
        self._running = False
        self.thread.join()
        self.client.stop()
        self.client.close()

    def run(self):
        while self._running:
            self._run()
            time.sleep(0.1)

    def _run(self):
        if self.paused:
            return
        for req in self.getNodeRequests():
            self.fulfillRequest(req)

    def getNodeRequests(self):
        try:
            reqids = self.client.get_children(self.REQUEST_ROOT)
        except kazoo.exceptions.NoNodeError:
            return []
        reqs = []
        for oid in sorted(reqids):
            path = self.REQUEST_ROOT + '/' + oid
            try:
                data, stat = self.client.get(path)
                data = json.loads(data)
                data['_oid'] = oid
                reqs.append(data)
            except kazoo.exceptions.NoNodeError:
                pass
        return reqs

    def getNodes(self):
        try:
            nodeids = self.client.get_children(self.NODE_ROOT)
        except kazoo.exceptions.NoNodeError:
            return []
        nodes = []
        for oid in sorted(nodeids):
            path = self.NODE_ROOT + '/' + oid
            data, stat = self.client.get(path)
            data = json.loads(data)
            data['_oid'] = oid
            try:
                lockfiles = self.client.get_children(path + '/lock')
            except kazoo.exceptions.NoNodeError:
                lockfiles = []
            if lockfiles:
                data['_lock'] = True
            else:
                data['_lock'] = False
            nodes.append(data)
        return nodes

    def makeNode(self, request_id, node_type):
        now = time.time()
        path = '/nodepool/nodes/'
        data = dict(type=node_type,
                    provider='test-provider',
                    region='test-region',
                    az='test-az',
                    interface_ip='127.0.0.1',
                    public_ipv4='127.0.0.1',
                    private_ipv4=None,
                    public_ipv6=None,
                    allocated_to=request_id,
                    state='ready',
                    state_time=now,
                    created_time=now,
                    updated_time=now,
                    image_id=None,
                    host_keys=["fake-key1", "fake-key2"],
                    executor='fake-nodepool')
        data = json.dumps(data)
        path = self.client.create(path, data,
                                  makepath=True,
                                  sequence=True)
        nodeid = path.split("/")[-1]
        return nodeid

    def addFailRequest(self, request):
        self.fail_requests.add(request['_oid'])

    def fulfillRequest(self, request):
        if request['state'] != 'requested':
            return
        request = request.copy()
        oid = request['_oid']
        del request['_oid']

        if oid in self.fail_requests:
            request['state'] = 'failed'
        else:
            request['state'] = 'fulfilled'
            nodes = []
            for node in request['node_types']:
                nodeid = self.makeNode(oid, node)
                nodes.append(nodeid)
            request['nodes'] = nodes

        request['state_time'] = time.time()
        path = self.REQUEST_ROOT + '/' + oid
        data = json.dumps(request)
        self.log.debug("Fulfilling node request: %s %s" % (oid, data))
        self.client.set(path, data)


class ChrootedKazooFixture(fixtures.Fixture):
    def __init__(self, test_id):
        super(ChrootedKazooFixture, self).__init__()

        zk_host = os.environ.get('NODEPOOL_ZK_HOST', 'localhost')
        if ':' in zk_host:
            host, port = zk_host.split(':')
        else:
            host = zk_host
            port = None

        self.zookeeper_host = host

        if not port:
            self.zookeeper_port = 2181
        else:
            self.zookeeper_port = int(port)

        self.test_id = test_id

    def _setUp(self):
        # Make sure the test chroot paths do not conflict
        random_bits = ''.join(random.choice(string.ascii_lowercase +
                                            string.ascii_uppercase)
                              for x in range(8))

        rand_test_path = '%s_%s_%s' % (random_bits, os.getpid(), self.test_id)
        self.zookeeper_chroot = "/nodepool_test/%s" % rand_test_path

        self.addCleanup(self._cleanup)

        # Ensure the chroot path exists and clean up any pre-existing znodes.
        _tmp_client = kazoo.client.KazooClient(
            hosts='%s:%s' % (self.zookeeper_host, self.zookeeper_port))
        _tmp_client.start()

        if _tmp_client.exists(self.zookeeper_chroot):
            _tmp_client.delete(self.zookeeper_chroot, recursive=True)

        _tmp_client.ensure_path(self.zookeeper_chroot)
        _tmp_client.stop()
        _tmp_client.close()

    def _cleanup(self):
        '''Remove the chroot path.'''
        # Need a non-chroot'ed client to remove the chroot path
        _tmp_client = kazoo.client.KazooClient(
            hosts='%s:%s' % (self.zookeeper_host, self.zookeeper_port))
        _tmp_client.start()
        _tmp_client.delete(self.zookeeper_chroot, recursive=True)
        _tmp_client.stop()
        _tmp_client.close()


class MySQLSchemaFixture(fixtures.Fixture):

    def setUp(self):
        super(MySQLSchemaFixture, self).setUp()

        random_bits = ''.join(random.choice(string.ascii_lowercase +
                                            string.ascii_uppercase)
                              for x in range(8))
        self.name = '%s_%s' % (random_bits, os.getpid())
        self.passwd = uuid.uuid4().hex
        self.db_host = os.environ.get('ZUUL_MYSQL_HOST', 'localhost')
        db = pymysql.connect(host=self.db_host,
                             user="openstack_citest",
                             passwd="openstack_citest",
                             db="openstack_citest")
        cur = db.cursor()
        cur.execute("create database %s" % self.name)
        cur.execute(
            "grant all on %s.* to '%s'@'%%' identified by '%s'" %
            (self.name, self.name, self.passwd))
        cur.execute("flush privileges")

        self.dburi = 'mysql+pymysql://%s:%s@%s/%s' % (self.name,
                                                      self.passwd,
                                                      self.db_host,
                                                      self.name)
        self.addDetail('dburi', testtools.content.text_content(self.dburi))
        self.addCleanup(self.cleanup)

    def cleanup(self):
        db = pymysql.connect(host=self.db_host,
                             user="openstack_citest",
                             passwd="openstack_citest",
                             db="openstack_citest")
        cur = db.cursor()
        cur.execute("drop database %s" % self.name)
        cur.execute("drop user '%s'@'%%'" % self.name)
        cur.execute("flush privileges")


class BaseTestCase(testtools.TestCase):
    log = logging.getLogger("zuul.test")
    wait_timeout = 30

    def attachLogs(self, *args):
        def reader():
            self._log_stream.seek(0)
            while True:
                x = self._log_stream.read(4096)
                if not x:
                    break
                yield x.encode('utf8')
        content = testtools.content.content_from_reader(
            reader,
            testtools.content_type.UTF8_TEXT,
            False)
        self.addDetail('logging', content)

    def setUp(self):
        super(BaseTestCase, self).setUp()
        test_timeout = os.environ.get('OS_TEST_TIMEOUT', 0)
        try:
            test_timeout = int(test_timeout)
        except ValueError:
            # If timeout value is invalid do not set a timeout.
            test_timeout = 0
        if test_timeout > 0:
            self.useFixture(fixtures.Timeout(test_timeout, gentle=False))

        if (os.environ.get('OS_STDOUT_CAPTURE') == 'True' or
            os.environ.get('OS_STDOUT_CAPTURE') == '1'):
            stdout = self.useFixture(fixtures.StringStream('stdout')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stdout', stdout))
        if (os.environ.get('OS_STDERR_CAPTURE') == 'True' or
            os.environ.get('OS_STDERR_CAPTURE') == '1'):
            stderr = self.useFixture(fixtures.StringStream('stderr')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stderr', stderr))
        if (os.environ.get('OS_LOG_CAPTURE') == 'True' or
            os.environ.get('OS_LOG_CAPTURE') == '1'):
            self._log_stream = StringIO()
            self.addOnException(self.attachLogs)
        else:
            self._log_stream = sys.stdout

        handler = logging.StreamHandler(self._log_stream)
        formatter = logging.Formatter('%(asctime)s %(name)-32s '
                                      '%(levelname)-8s %(message)s')
        handler.setFormatter(formatter)

        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)

        # Make sure we don't carry old handlers around in process state
        # which slows down test runs
        self.addCleanup(logger.removeHandler, handler)
        self.addCleanup(handler.close)
        self.addCleanup(handler.flush)

        # NOTE(notmorgan): Extract logging overrides for specific
        # libraries from the OS_LOG_DEFAULTS env and create loggers
        # for each. This is used to limit the output during test runs
        # from libraries that zuul depends on such as gear.
        log_defaults_from_env = os.environ.get(
            'OS_LOG_DEFAULTS',
            'git.cmd=INFO,kazoo.client=WARNING,gear=INFO')

        if log_defaults_from_env:
            for default in log_defaults_from_env.split(','):
                try:
                    name, level_str = default.split('=', 1)
                    level = getattr(logging, level_str, logging.DEBUG)
                    logger = logging.getLogger(name)
                    logger.setLevel(level)
                    logger.addHandler(handler)
                    logger.propagate = False
                except ValueError:
                    # NOTE(notmorgan): Invalid format of the log default,
                    # skip and don't try and apply a logger for the
                    # specified module
                    pass


class ZuulTestCase(BaseTestCase):
    """A test case with a functioning Zuul.

    The following class variables are used during test setup and can
    be overidden by subclasses but are effectively read-only once a
    test method starts running:

    :cvar str config_file: This points to the main zuul config file
        within the fixtures directory.  Subclasses may override this
        to obtain a different behavior.

    :cvar str tenant_config_file: This is the tenant config file
        (which specifies from what git repos the configuration should
        be loaded).  It defaults to the value specified in
        `config_file` but can be overidden by subclasses to obtain a
        different tenant/project layout while using the standard main
        configuration.  See also the :py:func:`simple_layout`
        decorator.

    :cvar bool create_project_keys: Indicates whether Zuul should
        auto-generate keys for each project, or whether the test
        infrastructure should insert dummy keys to save time during
        startup.  Defaults to False.

    The following are instance variables that are useful within test
    methods:

    :ivar FakeGerritConnection fake_<connection>:
        A :py:class:`~tests.base.FakeGerritConnection` will be
        instantiated for each connection present in the config file
        and stored here.  For instance, `fake_gerrit` will hold the
        FakeGerritConnection object for a connection named `gerrit`.

    :ivar FakeGearmanServer gearman_server: An instance of
        :py:class:`~tests.base.FakeGearmanServer` which is the Gearman
        server that all of the Zuul components in this test use to
        communicate with each other.

    :ivar RecordingExecutorServer executor_server: An instance of
        :py:class:`~tests.base.RecordingExecutorServer` which is the
        Ansible execute server used to run jobs for this test.

    :ivar list builds: A list of :py:class:`~tests.base.FakeBuild` objects
        representing currently running builds.  They are appended to
        the list in the order they are executed, and removed from this
        list upon completion.

    :ivar list history: A list of :py:class:`~tests.base.BuildHistory`
        objects representing completed builds.  They are appended to
        the list in the order they complete.

    """

    config_file = 'zuul.conf'
    run_ansible = False
    create_project_keys = False

    def _startMerger(self):
        self.merge_server = zuul.merger.server.MergeServer(self.config,
                                                           self.connections)
        self.merge_server.start()

    def setUp(self):
        super(ZuulTestCase, self).setUp()

        self.setupZK()

        if not KEEP_TEMPDIRS:
            tmp_root = self.useFixture(fixtures.TempDir(
                rootdir=os.environ.get("ZUUL_TEST_ROOT"))
            ).path
        else:
            tmp_root = tempfile.mkdtemp(
                dir=os.environ.get("ZUUL_TEST_ROOT", None))
        self.test_root = os.path.join(tmp_root, "zuul-test")
        self.upstream_root = os.path.join(self.test_root, "upstream")
        self.merger_src_root = os.path.join(self.test_root, "merger-git")
        self.executor_src_root = os.path.join(self.test_root, "executor-git")
        self.state_root = os.path.join(self.test_root, "lib")

        if os.path.exists(self.test_root):
            shutil.rmtree(self.test_root)
        os.makedirs(self.test_root)
        os.makedirs(self.upstream_root)
        os.makedirs(self.state_root)

        # Make per test copy of Configuration.
        self.setup_config()
        self.config.set('zuul', 'tenant_config',
                        os.path.join(FIXTURE_DIR,
                                     self.config.get('zuul', 'tenant_config')))
        self.config.set('merger', 'git_dir', self.merger_src_root)
        self.config.set('executor', 'git_dir', self.executor_src_root)
        self.config.set('zuul', 'state_dir', self.state_root)

        self.statsd = FakeStatsd()
        # note, use 127.0.0.1 rather than localhost to avoid getting ipv6
        # see: https://github.com/jsocol/pystatsd/issues/61
        os.environ['STATSD_HOST'] = '127.0.0.1'
        os.environ['STATSD_PORT'] = str(self.statsd.port)
        self.statsd.start()
        # the statsd client object is configured in the statsd module import
        reload_module(statsd)
        reload_module(zuul.scheduler)

        self.gearman_server = FakeGearmanServer()

        self.config.set('gearman', 'port', str(self.gearman_server.port))
        self.log.info("Gearman server on port %s" %
                      (self.gearman_server.port,))

        gerritsource.GerritSource.replication_timeout = 1.5
        gerritsource.GerritSource.replication_retry_interval = 0.5
        gerritconnection.GerritEventConnector.delay = 0.0

        self.sched = zuul.scheduler.Scheduler(self.config)

        self.webapp = zuul.webapp.WebApp(
            self.sched, port=0, listen_address='127.0.0.1')

        self.event_queues = [
            self.sched.result_event_queue,
            self.sched.trigger_event_queue,
            self.sched.management_event_queue
        ]

        self.configure_connections()
        self.sched.registerConnections(self.connections, self.webapp)

        def URLOpenerFactory(*args, **kw):
            if isinstance(args[0], urllib.request.Request):
                return old_urlopen(*args, **kw)
            return FakeURLOpener(self.upstream_root, *args, **kw)

        old_urlopen = urllib.request.urlopen
        urllib.request.urlopen = URLOpenerFactory

        self._startMerger()

        self.executor_server = RecordingExecutorServer(
            self.config, self.connections,
            jobdir_root=self.test_root,
            _run_ansible=self.run_ansible,
            _test_root=self.test_root,
            keep_jobdir=KEEP_TEMPDIRS)
        self.executor_server.start()
        self.history = self.executor_server.build_history
        self.builds = self.executor_server.running_builds

        self.executor_client = zuul.executor.client.ExecutorClient(
            self.config, self.sched)
        self.merge_client = zuul.merger.client.MergeClient(
            self.config, self.sched)
        self.nodepool = zuul.nodepool.Nodepool(self.sched)
        self.zk = zuul.zk.ZooKeeper()
        self.zk.connect(self.zk_config)

        self.fake_nodepool = FakeNodepool(
            self.zk_chroot_fixture.zookeeper_host,
            self.zk_chroot_fixture.zookeeper_port,
            self.zk_chroot_fixture.zookeeper_chroot)

        self.sched.setExecutor(self.executor_client)
        self.sched.setMerger(self.merge_client)
        self.sched.setNodepool(self.nodepool)
        self.sched.setZooKeeper(self.zk)

        self.rpc = zuul.rpclistener.RPCListener(self.config, self.sched)

        self.sched.start()
        self.webapp.start()
        self.rpc.start()
        self.executor_client.gearman.waitForServer()
        # Cleanups are run in reverse order
        self.addCleanup(self.assertCleanShutdown)
        self.addCleanup(self.shutdown)
        self.addCleanup(self.assertFinalState)

        self.sched.reconfigure(self.config)
        self.sched.resume()

    def configure_connections(self):
        # Set up gerrit related fakes
        # Set a changes database so multiple FakeGerrit's can report back to
        # a virtual canonical database given by the configured hostname
        self.gerrit_changes_dbs = {}

        def getGerritConnection(driver, name, config):
            db = self.gerrit_changes_dbs.setdefault(config['server'], {})
            con = FakeGerritConnection(driver, name, config,
                                       changes_db=db,
                                       upstream_root=self.upstream_root)
            self.event_queues.append(con.event_queue)
            setattr(self, 'fake_' + name, con)
            return con

        self.useFixture(fixtures.MonkeyPatch(
            'zuul.driver.gerrit.GerritDriver.getConnection',
            getGerritConnection))

        # Set up smtp related fakes
        # TODO(jhesketh): This should come from lib.connections for better
        # coverage
        # Register connections from the config
        self.smtp_messages = []

        def FakeSMTPFactory(*args, **kw):
            args = [self.smtp_messages] + list(args)
            return FakeSMTP(*args, **kw)

        self.useFixture(fixtures.MonkeyPatch('smtplib.SMTP', FakeSMTPFactory))

        # Register connections from the config using fakes
        self.connections = zuul.lib.connections.ConnectionRegistry()
        self.connections.configure(self.config)

    def setup_config(self):
        # This creates the per-test configuration object.  It can be
        # overriden by subclasses, but should not need to be since it
        # obeys the config_file and tenant_config_file attributes.
        self.config = ConfigParser.ConfigParser()
        self.config.read(os.path.join(FIXTURE_DIR, self.config_file))

        if not self.setupSimpleLayout():
            if hasattr(self, 'tenant_config_file'):
                self.config.set('zuul', 'tenant_config',
                                self.tenant_config_file)
                git_path = os.path.join(
                    os.path.dirname(
                        os.path.join(FIXTURE_DIR, self.tenant_config_file)),
                    'git')
                if os.path.exists(git_path):
                    for reponame in os.listdir(git_path):
                        project = reponame.replace('_', '/')
                        self.copyDirToRepo(project,
                                           os.path.join(git_path, reponame))
        self.setupAllProjectKeys()

    def setupSimpleLayout(self):
        # If the test method has been decorated with a simple_layout,
        # use that instead of the class tenant_config_file.  Set up a
        # single config-project with the specified layout, and
        # initialize repos for all of the 'project' entries which
        # appear in the layout.
        test_name = self.id().split('.')[-1]
        test = getattr(self, test_name)
        if hasattr(test, '__simple_layout__'):
            path, driver = getattr(test, '__simple_layout__')
        else:
            return False

        files = {}
        path = os.path.join(FIXTURE_DIR, path)
        with open(path) as f:
            data = f.read()
            layout = yaml.safe_load(data)
            files['zuul.yaml'] = data
        untrusted_projects = []
        for item in layout:
            if 'project' in item:
                name = item['project']['name']
                untrusted_projects.append(name)
                self.init_repo(name)
                self.addCommitToRepo(name, 'initial commit',
                                     files={'README': ''},
                                     branch='master', tag='init')
            if 'job' in item:
                jobname = item['job']['name']
                files['playbooks/%s.yaml' % jobname] = ''

        root = os.path.join(self.test_root, "config")
        if not os.path.exists(root):
            os.makedirs(root)
        f = tempfile.NamedTemporaryFile(dir=root, delete=False)
        config = [{'tenant':
                   {'name': 'tenant-one',
                    'source': {driver:
                               {'config-projects': ['common-config'],
                                'untrusted-projects': untrusted_projects}}}}]
        f.write(yaml.dump(config))
        f.close()
        self.config.set('zuul', 'tenant_config',
                        os.path.join(FIXTURE_DIR, f.name))

        self.init_repo('common-config')
        self.addCommitToRepo('common-config', 'add content from fixture',
                             files, branch='master', tag='init')

        return True

    def setupAllProjectKeys(self):
        if self.create_project_keys:
            return

        path = self.config.get('zuul', 'tenant_config')
        with open(os.path.join(FIXTURE_DIR, path)) as f:
            tenant_config = yaml.safe_load(f.read())
        for tenant in tenant_config:
            sources = tenant['tenant']['source']
            for source, conf in sources.items():
                for project in conf.get('config-projects', []):
                    self.setupProjectKeys(source, project)
                for project in conf.get('untrusted-projects', []):
                    self.setupProjectKeys(source, project)

    def setupProjectKeys(self, source, project):
        # Make sure we set up an RSA key for the project so that we
        # don't spend time generating one:

        key_root = os.path.join(self.state_root, 'keys')
        if not os.path.isdir(key_root):
            os.mkdir(key_root, 0o700)
        private_key_file = os.path.join(key_root, source, project + '.pem')
        private_key_dir = os.path.dirname(private_key_file)
        self.log.debug("Installing test keys for project %s at %s" % (
            project, private_key_file))
        if not os.path.isdir(private_key_dir):
            os.makedirs(private_key_dir)
        with open(os.path.join(FIXTURE_DIR, 'private.pem')) as i:
            with open(private_key_file, 'w') as o:
                o.write(i.read())

    def setupZK(self):
        self.zk_chroot_fixture = self.useFixture(
            ChrootedKazooFixture(self.id()))
        self.zk_config = '%s:%s%s' % (
            self.zk_chroot_fixture.zookeeper_host,
            self.zk_chroot_fixture.zookeeper_port,
            self.zk_chroot_fixture.zookeeper_chroot)

    def copyDirToRepo(self, project, source_path):
        self.init_repo(project)

        files = {}
        for (dirpath, dirnames, filenames) in os.walk(source_path):
            for filename in filenames:
                test_tree_filepath = os.path.join(dirpath, filename)
                common_path = os.path.commonprefix([test_tree_filepath,
                                                    source_path])
                relative_filepath = test_tree_filepath[len(common_path) + 1:]
                with open(test_tree_filepath, 'r') as f:
                    content = f.read()
                files[relative_filepath] = content
        self.addCommitToRepo(project, 'add content from fixture',
                             files, branch='master', tag='init')

    def assertNodepoolState(self):
        # Make sure that there are no pending requests

        requests = self.fake_nodepool.getNodeRequests()
        self.assertEqual(len(requests), 0)

        nodes = self.fake_nodepool.getNodes()
        for node in nodes:
            self.assertFalse(node['_lock'], "Node %s is locked" %
                             (node['_oid'],))

    def assertNoGeneratedKeys(self):
        # Make sure that Zuul did not generate any project keys
        # (unless it was supposed to).

        if self.create_project_keys:
            return

        with open(os.path.join(FIXTURE_DIR, 'private.pem')) as i:
            test_key = i.read()

        key_root = os.path.join(self.state_root, 'keys')
        for root, dirname, files in os.walk(key_root):
            for fn in files:
                with open(os.path.join(root, fn)) as f:
                    self.assertEqual(test_key, f.read())

    def assertFinalState(self):
        self.log.debug("Assert final state")
        # Make sure no jobs are running
        self.assertEqual({}, self.executor_server.job_workers)
        # Make sure that git.Repo objects have been garbage collected.
        repos = []
        gc.collect()
        for obj in gc.get_objects():
            if isinstance(obj, git.Repo):
                self.log.debug("Leaked git repo object: %s" % repr(obj))
                repos.append(obj)
        self.assertEqual(len(repos), 0)
        self.assertEmptyQueues()
        self.assertNodepoolState()
        self.assertNoGeneratedKeys()
        ipm = zuul.manager.independent.IndependentPipelineManager
        for tenant in self.sched.abide.tenants.values():
            for pipeline in tenant.layout.pipelines.values():
                if isinstance(pipeline.manager, ipm):
                    self.assertEqual(len(pipeline.queues), 0)

    def shutdown(self):
        self.log.debug("Shutting down after tests")
        self.executor_client.stop()
        self.merge_server.stop()
        self.merge_server.join()
        self.merge_client.stop()
        self.executor_server.stop()
        self.sched.stop()
        self.sched.join()
        self.statsd.stop()
        self.statsd.join()
        self.webapp.stop()
        self.webapp.join()
        self.rpc.stop()
        self.rpc.join()
        self.gearman_server.shutdown()
        self.fake_nodepool.stop()
        self.zk.disconnect()
        self.printHistory()
        # we whitelist watchdog threads as they have relatively long delays
        # before noticing they should exit, but they should exit on their own.
        threads = [t for t in threading.enumerate()
                   if t.name != 'executor-watchdog']
        if len(threads) > 1:
            log_str = ""
            for thread_id, stack_frame in sys._current_frames().items():
                log_str += "Thread: %s\n" % thread_id
                log_str += "".join(traceback.format_stack(stack_frame))
            self.log.debug(log_str)
            raise Exception("More than one thread is running: %s" % threads)

    def assertCleanShutdown(self):
        pass

    def init_repo(self, project, tag=None):
        parts = project.split('/')
        path = os.path.join(self.upstream_root, *parts[:-1])
        if not os.path.exists(path):
            os.makedirs(path)
        path = os.path.join(self.upstream_root, project)
        repo = git.Repo.init(path)

        with repo.config_writer() as config_writer:
            config_writer.set_value('user', 'email', 'user@example.com')
            config_writer.set_value('user', 'name', 'User Name')

        repo.index.commit('initial commit')
        master = repo.create_head('master')
        if tag:
            repo.create_tag(tag)

        repo.head.reference = master
        zuul.merger.merger.reset_repo_to_head(repo)
        repo.git.clean('-x', '-f', '-d')

    def create_branch(self, project, branch):
        path = os.path.join(self.upstream_root, project)
        repo = git.Repo.init(path)
        fn = os.path.join(path, 'README')

        branch_head = repo.create_head(branch)
        repo.head.reference = branch_head
        f = open(fn, 'a')
        f.write("test %s\n" % branch)
        f.close()
        repo.index.add([fn])
        repo.index.commit('%s commit' % branch)

        repo.head.reference = repo.heads['master']
        zuul.merger.merger.reset_repo_to_head(repo)
        repo.git.clean('-x', '-f', '-d')

    def create_commit(self, project):
        path = os.path.join(self.upstream_root, project)
        repo = git.Repo(path)
        repo.head.reference = repo.heads['master']
        file_name = os.path.join(path, 'README')
        with open(file_name, 'a') as f:
            f.write('creating fake commit\n')
        repo.index.add([file_name])
        commit = repo.index.commit('Creating a fake commit')
        return commit.hexsha

    def orderedRelease(self, count=None):
        # Run one build at a time to ensure non-race order:
        i = 0
        while len(self.builds):
            self.release(self.builds[0])
            self.waitUntilSettled()
            i += 1
            if count is not None and i >= count:
                break

    def release(self, job):
        if isinstance(job, FakeBuild):
            job.release()
        else:
            job.waiting = False
            self.log.debug("Queued job %s released" % job.unique)
            self.gearman_server.wakeConnections()

    def getParameter(self, job, name):
        if isinstance(job, FakeBuild):
            return job.parameters[name]
        else:
            parameters = json.loads(job.arguments)
            return parameters[name]

    def haveAllBuildsReported(self):
        # See if Zuul is waiting on a meta job to complete
        if self.executor_client.meta_jobs:
            return False
        # Find out if every build that the worker has completed has been
        # reported back to Zuul.  If it hasn't then that means a Gearman
        # event is still in transit and the system is not stable.
        for build in self.history:
            zbuild = self.executor_client.builds.get(build.uuid)
            if not zbuild:
                # It has already been reported
                continue
            # It hasn't been reported yet.
            return False
        # Make sure that none of the worker connections are in GRAB_WAIT
        for connection in self.executor_server.worker.active_connections:
            if connection.state == 'GRAB_WAIT':
                return False
        return True

    def areAllBuildsWaiting(self):
        builds = self.executor_client.builds.values()
        seen_builds = set()
        for build in builds:
            seen_builds.add(build.uuid)
            client_job = None
            for conn in self.executor_client.gearman.active_connections:
                for j in conn.related_jobs.values():
                    if j.unique == build.uuid:
                        client_job = j
                        break
            if not client_job:
                self.log.debug("%s is not known to the gearman client" %
                               build)
                return False
            if not client_job.handle:
                self.log.debug("%s has no handle" % client_job)
                return False
            server_job = self.gearman_server.jobs.get(client_job.handle)
            if not server_job:
                self.log.debug("%s is not known to the gearman server" %
                               client_job)
                return False
            if not hasattr(server_job, 'waiting'):
                self.log.debug("%s is being enqueued" % server_job)
                return False
            if server_job.waiting:
                continue
            if build.url is None:
                self.log.debug("%s has not reported start" % build)
                return False
            worker_build = self.executor_server.job_builds.get(
                server_job.unique)
            if worker_build:
                if worker_build.isWaiting():
                    continue
                else:
                    self.log.debug("%s is running" % worker_build)
                    return False
            else:
                self.log.debug("%s is unassigned" % server_job)
                return False
        for (build_uuid, job_worker) in \
            self.executor_server.job_workers.items():
            if build_uuid not in seen_builds:
                self.log.debug("%s is not finalized" % build_uuid)
                return False
        return True

    def areAllNodeRequestsComplete(self):
        if self.fake_nodepool.paused:
            return True
        if self.sched.nodepool.requests:
            return False
        return True

    def eventQueuesEmpty(self):
        for queue in self.event_queues:
            yield queue.empty()

    def eventQueuesJoin(self):
        for queue in self.event_queues:
            queue.join()

    def waitUntilSettled(self):
        self.log.debug("Waiting until settled...")
        start = time.time()
        while True:
            if time.time() - start > self.wait_timeout:
                self.log.error("Timeout waiting for Zuul to settle")
                self.log.error("Queue status:")
                for queue in self.event_queues:
                    self.log.error("  %s: %s" % (queue, queue.empty()))
                self.log.error("All builds waiting: %s" %
                               (self.areAllBuildsWaiting(),))
                self.log.error("All builds reported: %s" %
                               (self.haveAllBuildsReported(),))
                self.log.error("All requests completed: %s" %
                               (self.areAllNodeRequestsComplete(),))
                self.log.error("Merge client jobs: %s" %
                               (self.merge_client.jobs,))
                raise Exception("Timeout waiting for Zuul to settle")
            # Make sure no new events show up while we're checking

            self.executor_server.lock.acquire()
            # have all build states propogated to zuul?
            if self.haveAllBuildsReported():
                # Join ensures that the queue is empty _and_ events have been
                # processed
                self.eventQueuesJoin()
                self.sched.run_handler_lock.acquire()
                if (not self.merge_client.jobs and
                    self.haveAllBuildsReported() and
                    self.areAllBuildsWaiting() and
                    self.areAllNodeRequestsComplete() and
                    all(self.eventQueuesEmpty())):
                    # The queue empty check is placed at the end to
                    # ensure that if a component adds an event between
                    # when locked the run handler and checked that the
                    # components were stable, we don't erroneously
                    # report that we are settled.
                    self.sched.run_handler_lock.release()
                    self.executor_server.lock.release()
                    self.log.debug("...settled.")
                    return
                self.sched.run_handler_lock.release()
            self.executor_server.lock.release()
            self.sched.wake_event.wait(0.1)

    def countJobResults(self, jobs, result):
        jobs = filter(lambda x: x.result == result, jobs)
        return len(jobs)

    def getJobFromHistory(self, name, project=None):
        for job in self.history:
            if (job.name == name and
                (project is None or
                 job.parameters['ZUUL_PROJECT'] == project)):
                return job
        raise Exception("Unable to find job %s in history" % name)

    def assertEmptyQueues(self):
        # Make sure there are no orphaned jobs
        for tenant in self.sched.abide.tenants.values():
            for pipeline in tenant.layout.pipelines.values():
                for queue in pipeline.queues:
                    if len(queue.queue) != 0:
                        print('pipeline %s queue %s contents %s' % (
                            pipeline.name, queue.name, queue.queue))
                    self.assertEqual(len(queue.queue), 0,
                                     "Pipelines queues should be empty")

    def assertReportedStat(self, key, value=None, kind=None):
        start = time.time()
        while time.time() < (start + 5):
            for stat in self.statsd.stats:
                k, v = stat.split(':')
                if key == k:
                    if value is None and kind is None:
                        return
                    elif value:
                        if value == v:
                            return
                    elif kind:
                        if v.endswith('|' + kind):
                            return
            time.sleep(0.1)

        raise Exception("Key %s not found in reported stats" % key)

    def assertBuilds(self, builds):
        """Assert that the running builds are as described.

        The list of running builds is examined and must match exactly
        the list of builds described by the input.

        :arg list builds: A list of dictionaries.  Each item in the
            list must match the corresponding build in the build
            history, and each element of the dictionary must match the
            corresponding attribute of the build.

        """
        try:
            self.assertEqual(len(self.builds), len(builds))
            for i, d in enumerate(builds):
                for k, v in d.items():
                    self.assertEqual(
                        getattr(self.builds[i], k), v,
                        "Element %i in builds does not match" % (i,))
        except Exception:
            for build in self.builds:
                self.log.error("Running build: %s" % build)
            else:
                self.log.error("No running builds")
            raise

    def assertHistory(self, history, ordered=True):
        """Assert that the completed builds are as described.

        The list of completed builds is examined and must match
        exactly the list of builds described by the input.

        :arg list history: A list of dictionaries.  Each item in the
            list must match the corresponding build in the build
            history, and each element of the dictionary must match the
            corresponding attribute of the build.

        :arg bool ordered: If true, the history must match the order
            supplied, if false, the builds are permitted to have
            arrived in any order.

        """
        def matches(history_item, item):
            for k, v in item.items():
                if getattr(history_item, k) != v:
                    return False
            return True
        try:
            self.assertEqual(len(self.history), len(history))
            if ordered:
                for i, d in enumerate(history):
                    if not matches(self.history[i], d):
                        raise Exception(
                            "Element %i in history does not match %s" %
                            (i, self.history[i]))
            else:
                unseen = self.history[:]
                for i, d in enumerate(history):
                    found = False
                    for unseen_item in unseen:
                        if matches(unseen_item, d):
                            found = True
                            unseen.remove(unseen_item)
                            break
                    if not found:
                        raise Exception("No match found for element %i "
                                        "in history" % (i,))
                if unseen:
                    raise Exception("Unexpected items in history")
        except Exception:
            for build in self.history:
                self.log.error("Completed build: %s" % build)
            else:
                self.log.error("No completed builds")
            raise

    def printHistory(self):
        """Log the build history.

        This can be useful during tests to summarize what jobs have
        completed.

        """
        self.log.debug("Build history:")
        for build in self.history:
            self.log.debug(build)

    def getPipeline(self, name):
        return self.sched.abide.tenants.values()[0].layout.pipelines.get(name)

    def updateConfigLayout(self, path):
        root = os.path.join(self.test_root, "config")
        if not os.path.exists(root):
            os.makedirs(root)
        f = tempfile.NamedTemporaryFile(dir=root, delete=False)
        f.write("""
- tenant:
    name: openstack
    source:
      gerrit:
        config-projects:
          - %s
        untrusted-projects:
          - org/project
          - org/project1
          - org/project2\n""" % path)
        f.close()
        self.config.set('zuul', 'tenant_config',
                        os.path.join(FIXTURE_DIR, f.name))
        self.setupAllProjectKeys()

    def addCommitToRepo(self, project, message, files,
                        branch='master', tag=None):
        path = os.path.join(self.upstream_root, project)
        repo = git.Repo(path)
        repo.head.reference = branch
        zuul.merger.merger.reset_repo_to_head(repo)
        for fn, content in files.items():
            fn = os.path.join(path, fn)
            try:
                os.makedirs(os.path.dirname(fn))
            except OSError:
                pass
            with open(fn, 'w') as f:
                f.write(content)
            repo.index.add([fn])
        commit = repo.index.commit(message)
        before = repo.heads[branch].commit
        repo.heads[branch].commit = commit
        repo.head.reference = branch
        repo.git.clean('-x', '-f', '-d')
        repo.heads[branch].checkout()
        if tag:
            repo.create_tag(tag)
        return before

    def commitConfigUpdate(self, project_name, source_name):
        """Commit an update to zuul.yaml

        This overwrites the zuul.yaml in the specificed project with
        the contents specified.

        :arg str project_name: The name of the project containing
            zuul.yaml (e.g., common-config)

        :arg str source_name: The path to the file (underneath the
            test fixture directory) whose contents should be used to
            replace zuul.yaml.
        """

        source_path = os.path.join(FIXTURE_DIR, source_name)
        files = {}
        with open(source_path, 'r') as f:
            data = f.read()
            layout = yaml.safe_load(data)
            files['zuul.yaml'] = data
        for item in layout:
            if 'job' in item:
                jobname = item['job']['name']
                files['playbooks/%s.yaml' % jobname] = ''
        before = self.addCommitToRepo(
            project_name, 'Pulling content from %s' % source_name,
            files)
        return before

    def addEvent(self, connection, event):

        """Inject a Fake (Gerrit) event.

        This method accepts a JSON-encoded event and simulates Zuul
        having received it from Gerrit.  It could (and should)
        eventually apply to any connection type, but is currently only
        used with Gerrit connections.  The name of the connection is
        used to look up the corresponding server, and the event is
        simulated as having been received by all Zuul connections
        attached to that server.  So if two Gerrit connections in Zuul
        are connected to the same Gerrit server, and you invoke this
        method specifying the name of one of them, the event will be
        received by both.

        .. note::

            "self.fake_gerrit.addEvent" calls should be migrated to
            this method.

        :arg str connection: The name of the connection corresponding
            to the gerrit server.
        :arg str event: The JSON-encoded event.

        """
        specified_conn = self.connections.connections[connection]
        for conn in self.connections.connections.values():
            if (isinstance(conn, specified_conn.__class__) and
                specified_conn.server == conn.server):
                conn.addEvent(event)


class AnsibleZuulTestCase(ZuulTestCase):
    """ZuulTestCase but with an actual ansible executor running"""
    run_ansible = True


class ZuulDBTestCase(ZuulTestCase):
    def setup_config(self):
        super(ZuulDBTestCase, self).setup_config()
        for section_name in self.config.sections():
            con_match = re.match(r'^connection ([\'\"]?)(.*)(\1)$',
                                 section_name, re.I)
            if not con_match:
                continue

            if self.config.get(section_name, 'driver') == 'sql':
                f = MySQLSchemaFixture()
                self.useFixture(f)
                if (self.config.get(section_name, 'dburi') ==
                    '$MYSQL_FIXTURE_DBURI$'):
                    self.config.set(section_name, 'dburi', f.dburi)
