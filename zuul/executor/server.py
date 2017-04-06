# Copyright 2014 OpenStack Foundation
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
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import traceback
import yaml

import gear
import git
from six.moves import shlex_quote

import zuul.merger.merger
import zuul.ansible.action
import zuul.ansible.callback
import zuul.ansible.library
from zuul.lib import commandsocket

COMMANDS = ['stop', 'pause', 'unpause', 'graceful', 'verbose',
            'unverbose']


class Watchdog(object):
    def __init__(self, timeout, function, args):
        self.timeout = timeout
        self.function = function
        self.args = args
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.timed_out = None

    def _run(self):
        while self._running and time.time() < self.end:
            time.sleep(10)
        if self._running:
            self.timed_out = True
            self.function(*self.args)
        self.timed_out = False

    def start(self):
        self._running = True
        self.end = time.time() + self.timeout
        self.thread.start()

    def stop(self):
        self._running = False

# TODOv3(mordred): put git repos in a hierarchy that includes source
# hostname, eg: git.openstack.org/openstack/nova.  Also, configure
# sources to have an alias, so that the review.openstack.org source
# repos end up in git.openstack.org.


class JobDirPlaybook(object):
    def __init__(self, root):
        self.root = root
        self.trusted = None
        self.path = None


class JobDir(object):
    def __init__(self, root=None, keep=False):
        # root
        #   ansible
        #     trusted.cfg
        #     untrusted.cfg
        #   work
        #     src
        #     logs
        self.keep = keep
        self.root = tempfile.mkdtemp(dir=root)
        # Work
        self.work_root = os.path.join(self.root, 'work')
        os.makedirs(self.work_root)
        self.src_root = os.path.join(self.work_root, 'src')
        os.makedirs(self.src_root)
        self.log_root = os.path.join(self.work_root, 'logs')
        os.makedirs(self.log_root)
        # Ansible
        self.ansible_root = os.path.join(self.root, 'ansible')
        os.makedirs(self.ansible_root)
        self.known_hosts = os.path.join(self.ansible_root, 'known_hosts')
        self.inventory = os.path.join(self.ansible_root, 'inventory')
        self.vars = os.path.join(self.ansible_root, 'vars.yaml')
        self.playbooks = []  # The list of candidate playbooks
        self.playbook = None  # A pointer to the candidate we have chosen
        self.pre_playbooks = []
        self.post_playbooks = []
        self.roles = []
        self.roles_path = []
        self.untrusted_config = os.path.join(
            self.ansible_root, 'untrusted.cfg')
        self.trusted_config = os.path.join(self.ansible_root, 'trusted.cfg')
        self.ansible_log = os.path.join(self.log_root, 'ansible_log.txt')

    def addPrePlaybook(self):
        count = len(self.pre_playbooks)
        root = os.path.join(self.ansible_root, 'pre_playbook_%i' % (count,))
        os.makedirs(root)
        playbook = JobDirPlaybook(root)
        self.pre_playbooks.append(playbook)
        return playbook

    def addPostPlaybook(self):
        count = len(self.post_playbooks)
        root = os.path.join(self.ansible_root, 'post_playbook_%i' % (count,))
        os.makedirs(root)
        playbook = JobDirPlaybook(root)
        self.post_playbooks.append(playbook)
        return playbook

    def addPlaybook(self):
        count = len(self.playbooks)
        root = os.path.join(self.ansible_root, 'playbook_%i' % (count,))
        os.makedirs(root)
        playbook = JobDirPlaybook(root)
        self.playbooks.append(playbook)
        return playbook

    def addRole(self):
        count = len(self.roles)
        root = os.path.join(self.ansible_root, 'role_%i' % (count,))
        os.makedirs(root)
        self.roles.append(root)
        return root

    def cleanup(self):
        if not self.keep:
            shutil.rmtree(self.root)

    def __enter__(self):
        return self

    def __exit__(self, etype, value, tb):
        self.cleanup()


class UpdateTask(object):
    def __init__(self, project, url):
        self.project = project
        self.url = url
        self.event = threading.Event()

    def __eq__(self, other):
        if other.project == self.project:
            return True
        return False

    def wait(self):
        self.event.wait()

    def setComplete(self):
        self.event.set()


class DeduplicateQueue(object):
    def __init__(self):
        self.queue = collections.deque()
        self.condition = threading.Condition()

    def qsize(self):
        return len(self.queue)

    def put(self, item):
        # Returns the original item if added, or an equivalent item if
        # already enqueued.
        self.condition.acquire()
        ret = None
        try:
            for x in self.queue:
                if item == x:
                    ret = x
            if ret is None:
                ret = item
                self.queue.append(item)
                self.condition.notify()
        finally:
            self.condition.release()
        return ret

    def get(self):
        self.condition.acquire()
        try:
            while True:
                try:
                    ret = self.queue.popleft()
                    return ret
                except IndexError:
                    pass
                self.condition.wait()
        finally:
            self.condition.release()


class ExecutorServer(object):
    log = logging.getLogger("zuul.ExecutorServer")

    def __init__(self, config, connections={}, jobdir_root=None,
                 keep_jobdir=False):
        self.config = config
        self.keep_jobdir = keep_jobdir
        self.jobdir_root = jobdir_root
        # TODOv3(mordred): make the executor name more unique --
        # perhaps hostname+pid.
        self.hostname = socket.gethostname()
        self.zuul_url = config.get('merger', 'zuul_url')
        self.command_map = dict(
            stop=self.stop,
            pause=self.pause,
            unpause=self.unpause,
            graceful=self.graceful,
            verbose=self.verboseOn,
            unverbose=self.verboseOff,
        )

        if self.config.has_option('executor', 'git_dir'):
            self.merge_root = self.config.get('executor', 'git_dir')
        else:
            self.merge_root = '/var/lib/zuul/executor-git'

        if self.config.has_option('merger', 'git_user_email'):
            self.merge_email = self.config.get('merger', 'git_user_email')
        else:
            self.merge_email = None

        if self.config.has_option('merger', 'git_user_name'):
            self.merge_name = self.config.get('merger', 'git_user_name')
        else:
            self.merge_name = None

        self.connections = connections
        # This merger and its git repos are used to maintain
        # up-to-date copies of all the repos that are used by jobs, as
        # well as to support the merger:cat functon to supply
        # configuration information to Zuul when it starts.
        self.merger = self._getMerger(self.merge_root)
        self.update_queue = DeduplicateQueue()

        if self.config.has_option('zuul', 'state_dir'):
            state_dir = os.path.expanduser(
                self.config.get('zuul', 'state_dir'))
        else:
            state_dir = '/var/lib/zuul'
        path = os.path.join(state_dir, 'executor.socket')
        self.command_socket = commandsocket.CommandSocket(path)
        ansible_dir = os.path.join(state_dir, 'ansible')
        self.library_dir = os.path.join(ansible_dir, 'library')
        if not os.path.exists(self.library_dir):
            os.makedirs(self.library_dir)
        self.action_dir = os.path.join(ansible_dir, 'action')
        if not os.path.exists(self.action_dir):
            os.makedirs(self.action_dir)

        self.callback_dir = os.path.join(ansible_dir, 'callback')
        if not os.path.exists(self.callback_dir):
            os.makedirs(self.callback_dir)

        library_path = os.path.dirname(os.path.abspath(
            zuul.ansible.library.__file__))
        for fn in os.listdir(library_path):
            shutil.copy(os.path.join(library_path, fn), self.library_dir)

        action_path = os.path.dirname(os.path.abspath(
            zuul.ansible.action.__file__))
        for fn in os.listdir(action_path):
            shutil.copy(os.path.join(action_path, fn), self.action_dir)

        callback_path = os.path.dirname(os.path.abspath(
            zuul.ansible.callback.__file__))
        for fn in os.listdir(callback_path):
            shutil.copy(os.path.join(callback_path, fn), self.callback_dir)

        self.job_workers = {}

    def _getMerger(self, root):
        return zuul.merger.merger.Merger(root, self.connections,
                                         self.merge_email, self.merge_name)

    def start(self):
        self._running = True
        self._command_running = True
        server = self.config.get('gearman', 'server')
        if self.config.has_option('gearman', 'port'):
            port = self.config.get('gearman', 'port')
        else:
            port = 4730
        self.worker = gear.Worker('Zuul Executor Server')
        self.worker.addServer(server, port)
        self.log.debug("Waiting for server")
        self.worker.waitForServer()
        self.log.debug("Registering")
        self.register()

        self.log.debug("Starting command processor")
        self.command_socket.start()
        self.command_thread = threading.Thread(target=self.runCommand)
        self.command_thread.daemon = True
        self.command_thread.start()

        self.log.debug("Starting worker")
        self.update_thread = threading.Thread(target=self._updateLoop)
        self.update_thread.daemon = True
        self.update_thread.start()
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()

    def register(self):
        self.worker.registerFunction("executor:execute")
        self.worker.registerFunction("executor:stop:%s" % self.hostname)
        self.worker.registerFunction("merger:merge")
        self.worker.registerFunction("merger:cat")

    def stop(self):
        self.log.debug("Stopping")
        self._running = False
        self.worker.shutdown()
        self._command_running = False
        self.command_socket.stop()
        self.update_queue.put(None)
        self.log.debug("Stopped")

    def pause(self):
        # TODOv3: implement
        pass

    def unpause(self):
        # TODOv3: implement
        pass

    def graceful(self):
        # TODOv3: implement
        pass

    def verboseOn(self):
        # TODOv3: implement
        pass

    def verboseOff(self):
        # TODOv3: implement
        pass

    def join(self):
        self.update_thread.join()
        self.thread.join()

    def runCommand(self):
        while self._command_running:
            try:
                command = self.command_socket.get()
                if command != '_stop':
                    self.command_map[command]()
            except Exception:
                self.log.exception("Exception while processing command")

    def _updateLoop(self):
        while self._running:
            try:
                self._innerUpdateLoop()
            except:
                self.log.exception("Exception in update thread:")

    def _innerUpdateLoop(self):
        # Inside of a loop that keeps the main repositories up to date
        task = self.update_queue.get()
        if task is None:
            # We are asked to stop
            return
        self.log.info("Updating repo %s from %s" % (task.project, task.url))
        self.merger.updateRepo(task.project, task.url)
        self.log.debug("Finished updating repo %s from %s" %
                       (task.project, task.url))
        task.setComplete()

    def update(self, project, url):
        # Update a repository in the main merger
        task = UpdateTask(project, url)
        task = self.update_queue.put(task)
        return task

    def run(self):
        self.log.debug("Starting executor listener")
        while self._running:
            try:
                job = self.worker.getJob()
                try:
                    if job.name == 'executor:execute':
                        self.log.debug("Got execute job: %s" % job.unique)
                        self.executeJob(job)
                    elif job.name.startswith('executor:stop'):
                        self.log.debug("Got stop job: %s" % job.unique)
                        self.stopJob(job)
                    elif job.name == 'merger:cat':
                        self.log.debug("Got cat job: %s" % job.unique)
                        self.cat(job)
                    elif job.name == 'merger:merge':
                        self.log.debug("Got merge job: %s" % job.unique)
                        self.merge(job)
                    else:
                        self.log.error("Unable to handle job %s" % job.name)
                        job.sendWorkFail()
                except Exception:
                    self.log.exception("Exception while running job")
                    job.sendWorkException(traceback.format_exc())
            except gear.InterruptedError:
                pass
            except Exception:
                self.log.exception("Exception while getting job")

    def executeJob(self, job):
        self.job_workers[job.unique] = AnsibleJob(self, job)
        self.job_workers[job.unique].run()

    def finishJob(self, unique):
        del(self.job_workers[unique])

    def stopJob(self, job):
        try:
            args = json.loads(job.arguments)
            self.log.debug("Stop job with arguments: %s" % (args,))
            unique = args['uuid']
            job_worker = self.job_workers.get(unique)
            if not job_worker:
                self.log.debug("Unable to find worker for job %s" % (unique,))
                return
            try:
                job_worker.stop()
            except Exception:
                self.log.exception("Exception sending stop command "
                                   "to worker:")
        finally:
            job.sendWorkComplete()

    def cat(self, job):
        args = json.loads(job.arguments)
        task = self.update(args['project'], args['url'])
        task.wait()
        files = self.merger.getFiles(args['project'], args['url'],
                                     args['branch'], args['files'])
        result = dict(updated=True,
                      files=files,
                      zuul_url=self.zuul_url)
        job.sendWorkComplete(json.dumps(result))

    def merge(self, job):
        args = json.loads(job.arguments)
        ret = self.merger.mergeChanges(args['items'], args.get('files'))
        result = dict(merged=(ret is not None),
                      zuul_url=self.zuul_url)
        if args.get('files'):
            result['commit'], result['files'] = ret
        else:
            result['commit'] = ret
        job.sendWorkComplete(json.dumps(result))


class AnsibleJob(object):
    log = logging.getLogger("zuul.AnsibleJob")

    RESULT_NORMAL = 1
    RESULT_TIMED_OUT = 2
    RESULT_UNREACHABLE = 3
    RESULT_ABORTED = 4

    def __init__(self, executor_server, job):
        self.executor_server = executor_server
        self.job = job
        self.jobdir = None
        self.proc = None
        self.proc_lock = threading.Lock()
        self.running = False
        self.aborted = False

        if self.executor_server.config.has_option(
            'executor', 'private_key_file'):
            self.private_key_file = self.executor_server.config.get(
                'executor', 'private_key_file')
        else:
            self.private_key_file = '~/.ssh/id_rsa'

    def run(self):
        self.running = True
        self.thread = threading.Thread(target=self.execute)
        self.thread.start()

    def stop(self):
        self.aborted = True
        self.abortRunningProc()
        self.thread.join()

    def execute(self):
        try:
            self.jobdir = JobDir(root=self.executor_server.jobdir_root,
                                 keep=self.executor_server.keep_jobdir)
            self._execute()
        except Exception:
            self.log.exception("Exception while executing job")
            self.job.sendWorkException(traceback.format_exc())
        finally:
            self.running = False
            try:
                self.jobdir.cleanup()
            except Exception:
                self.log.exception("Error cleaning up jobdir:")
            try:
                self.executor_server.finishJob(self.job.unique)
            except Exception:
                self.log.exception("Error finalizing job thread:")

    def _execute(self):
        self.log.debug("Job %s: beginning" % (self.job.unique,))
        self.log.debug("Job %s: args: %s" % (self.job.unique,
                                             self.job.arguments,))
        self.log.debug("Job %s: job root at %s" %
                       (self.job.unique, self.jobdir.root))
        args = json.loads(self.job.arguments)
        tasks = []
        for project in args['projects']:
            self.log.debug("Job %s: updating project %s" %
                           (self.job.unique, project['name']))
            tasks.append(self.executor_server.update(
                project['name'], project['url']))
        for task in tasks:
            task.wait()

        self.log.debug("Job %s: git updates complete" % (self.job.unique,))
        for project in args['projects']:
            self.log.debug("Cloning %s" % (project['name'],))
            repo = git.Repo.clone_from(
                os.path.join(self.executor_server.merge_root,
                             project['name']),
                os.path.join(self.jobdir.src_root,
                             project['name']))
            repo.remotes.origin.config_writer.set('url', project['url'])

        # Get a merger in order to update the repos involved in this job.
        merger = self.executor_server._getMerger(self.jobdir.src_root)
        merge_items = [i for i in args['items'] if i.get('refspec')]
        if merge_items:
            commit = merger.mergeChanges(merge_items)  # noqa
        else:
            commit = args['items'][-1]['newrev']  # noqa

        # is the playbook in a repo that we have already prepared?
        self.preparePlaybookRepos(args)

        self.prepareRoles(args)

        # TODOv3: Ansible the ansible thing here.
        self.prepareAnsibleFiles(args)

        data = {
            'manager': self.executor_server.hostname,
            'url': 'https://server/job/{}/0/'.format(args['job']),
            'worker_name': 'My Worker',
        }

        # TODOv3:
        # 'name': self.name,
        # 'manager': self.executor_server.hostname,
        # 'worker_name': 'My Worker',
        # 'worker_hostname': 'localhost',
        # 'worker_ips': ['127.0.0.1', '192.168.1.1'],
        # 'worker_fqdn': 'zuul.example.org',
        # 'worker_program': 'FakeBuilder',
        # 'worker_version': 'v1.1',
        # 'worker_extra': {'something': 'else'}

        self.job.sendWorkData(json.dumps(data))
        self.job.sendWorkStatus(0, 100)

        result = self.runPlaybooks(args)

        if result is None:
            self.job.sendWorkFail()
            return
        result = dict(result=result)
        self.job.sendWorkComplete(json.dumps(result))

    def runPlaybooks(self, args):
        result = None

        for playbook in self.jobdir.pre_playbooks:
            # TODOv3(pabelanger): Implement pre-run timeout setting.
            pre_status, pre_code = self.runAnsiblePlaybook(
                playbook, args['timeout'])
            if pre_status != self.RESULT_NORMAL or pre_code != 0:
                # These should really never fail, so return None and have
                # zuul try again
                return result

        job_status, job_code = self.runAnsiblePlaybook(
            self.jobdir.playbook, args['timeout'])
        if job_status == self.RESULT_TIMED_OUT:
            return 'TIMED_OUT'
        if job_status == self.RESULT_ABORTED:
            return 'ABORTED'
        if job_status != self.RESULT_NORMAL:
            # The result of the job is indeterminate.  Zuul will
            # run it again.
            return result

        success = (job_code == 0)
        if success:
            result = 'SUCCESS'
        else:
            result = 'FAILURE'

        for playbook in self.jobdir.post_playbooks:
            # TODOv3(pabelanger): Implement post-run timeout setting.
            post_status, post_code = self.runAnsiblePlaybook(
                playbook, args['timeout'], success)
            if post_status != self.RESULT_NORMAL or post_code != 0:
                result = 'POST_FAILURE'
        return result

    def getHostList(self, args):
        # TODO(clarkb): This prefers v4 because we're not sure if we
        # expect v6 to work.  If we can determine how to prefer v6
        hosts = []
        for node in args['nodes']:
            ip = node.get('public_ipv4')
            if not ip:
                ip = node.get('public_ipv6')
            host_vars = dict(
                ansible_host=ip,
                nodepool_az=node.get('az'),
                nodepool_provider=node.get('provider'),
                nodepool_region=node.get('region'))

            username = node.get('username')
            if username:
                host_vars['ansible_user'] = username

            host_keys = []
            for key in node.get('host_keys'):
                host_keys.append("%s %s" % (ip, key))

            hosts.append(dict(
                name=node['name'],
                host_vars=host_vars,
                host_keys=host_keys))
        return hosts

    def _blockPluginDirs(self, path):
        '''Prevent execution of playbooks or roles with plugins

        Plugins are loaded from roles and also if there is a plugin
        dir adjacent to the playbook.  Throw an error if the path
        contains a location that would cause a plugin to get loaded.

        '''
        for entry in os.listdir(path):
            if os.path.isdir(entry) and entry.endswith('_plugins'):
                raise Exception(
                    "Ansible plugin dir %s found adjacent to playbook %s in"
                    " non-trusted repo." % (entry, path))

    def findPlaybook(self, path, required=False, trusted=False):
        for ext in ['.yaml', '.yml']:
            fn = path + ext
            if os.path.exists(fn):
                if not trusted:
                    playbook_dir = os.path.dirname(os.path.abspath(fn))
                    self._blockPluginDirs(playbook_dir)
                return fn
        if required:
            raise Exception("Unable to find playbook %s" % path)
        return None

    def preparePlaybookRepos(self, args):
        for playbook in args['pre_playbooks']:
            jobdir_playbook = self.jobdir.addPrePlaybook()
            self.preparePlaybookRepo(jobdir_playbook, playbook,
                                     args, required=True)

        for playbook in args['playbooks']:
            jobdir_playbook = self.jobdir.addPlaybook()
            self.preparePlaybookRepo(jobdir_playbook, playbook,
                                     args, required=False)
            if jobdir_playbook.path is not None:
                self.jobdir.playbook = jobdir_playbook
                break
        if self.jobdir.playbook is None:
            raise Exception("No valid playbook found")

        for playbook in args['post_playbooks']:
            jobdir_playbook = self.jobdir.addPostPlaybook()
            self.preparePlaybookRepo(jobdir_playbook, playbook,
                                     args, required=True)

    def preparePlaybookRepo(self, jobdir_playbook, playbook, args, required):
        self.log.debug("Prepare playbook repo for %s" % (playbook,))
        # Check out the playbook repo if needed and set the path to
        # the playbook that should be run.
        jobdir_playbook.trusted = playbook['trusted']
        source = self.executor_server.connections.getSource(
            playbook['connection'])
        project = source.getProject(playbook['project'])
        # TODO(jeblair): construct the url in the merger itself
        url = source.getGitUrl(project)
        if not playbook['trusted']:
            # This is a project repo, so it is safe to use the already
            # checked out version (from speculative merging) of the
            # playbook
            for i in args['items']:
                if (i['connection_name'] == playbook['connection'] and
                    i['project'] == playbook['project']):
                    # We already have this repo prepared
                    path = os.path.join(self.jobdir.src_root,
                                        project.name,
                                        playbook['path'])
                    jobdir_playbook.path = self.findPlaybook(
                        path,
                        required=required,
                        trusted=playbook['trusted'])
                    return
        # The playbook repo is either a config repo, or it isn't in
        # the stack of changes we are testing, so check out the branch
        # tip into a dedicated space.

        merger = self.executor_server._getMerger(jobdir_playbook.root)
        merger.checkoutBranch(project.name, url, playbook['branch'])

        path = os.path.join(jobdir_playbook.root,
                            project.name,
                            playbook['path'])
        jobdir_playbook.path = self.findPlaybook(
            path,
            required=required,
            trusted=playbook['trusted'])

    def prepareRoles(self, args):
        for role in args['roles']:
            if role['type'] == 'zuul':
                root = self.jobdir.addRole()
                self.prepareZuulRole(args, role, root)

    def findRole(self, path, trusted=False):
        d = os.path.join(path, 'tasks')
        if os.path.isdir(d):
            # This is a bare role
            if not trusted:
                self._blockPluginDirs(path)
            # None signifies that the repo is a bare role
            return None
        d = os.path.join(path, 'roles')
        if os.path.isdir(d):
            # This repo has a collection of roles
            if not trusted:
                for entry in os.listdir(d):
                    self._blockPluginDirs(os.path.join(d, entry))
            return d
        # We assume the repository itself is a collection of roles
        if not trusted:
            for entry in os.listdir(path):
                self._blockPluginDirs(os.path.join(path, entry))
        return path

    def prepareZuulRole(self, args, role, root):
        self.log.debug("Prepare zuul role for %s" % (role,))
        # Check out the role repo if needed
        source = self.executor_server.connections.getSource(
            role['connection'])
        project = source.getProject(role['project'])
        # TODO(jeblair): construct the url in the merger itself
        url = source.getGitUrl(project)
        role_repo = None
        if not role['trusted']:
            # This is a project repo, so it is safe to use the already
            # checked out version (from speculative merging) of the
            # role

            for i in args['items']:
                if (i['connection_name'] == role['connection'] and
                    i['project'] == role['project']):
                    # We already have this repo prepared;
                    # copy it into location.

                    path = os.path.join(self.jobdir.src_root,
                                        project.name)
                    link = os.path.join(root, role['name'])
                    os.symlink(path, link)
                    role_repo = link
                    break

        # The role repo is either a config repo, or it isn't in
        # the stack of changes we are testing, so check out the branch
        # tip into a dedicated space.

        if not role_repo:
            merger = self.executor_server._getMerger(root)
            merger.checkoutBranch(project.name, url, 'master')
            role_repo = os.path.join(root, project.name)

        role_path = self.findRole(role_repo, trusted=role['trusted'])
        if role_path is None:
            # In the case of a bare role, add the containing directory
            role_path = root
        self.jobdir.roles_path.append(role_path)

    def prepareAnsibleFiles(self, args):
        keys = []
        with open(self.jobdir.inventory, 'w') as inventory:
            for item in self.getHostList(args):
                inventory.write(item['name'])
                for k, v in item['host_vars'].items():
                    inventory.write(' %s=%s' % (k, v))
                inventory.write('\n')
                for key in item['host_keys']:
                    keys.append(key)

        with open(self.jobdir.known_hosts, 'w') as known_hosts:
            for key in keys:
                known_hosts.write('%s\n' % key)

        with open(self.jobdir.vars, 'w') as vars_yaml:
            zuul_vars = dict(args['vars'])
            zuul_vars['zuul']['executor'] = dict(
                hostname=self.executor_server.hostname,
                src_root=self.jobdir.src_root,
                log_root=self.jobdir.log_root)
            vars_yaml.write(
                yaml.safe_dump(zuul_vars, default_flow_style=False))
        self.writeAnsibleConfig(self.jobdir.untrusted_config)
        self.writeAnsibleConfig(self.jobdir.trusted_config, trusted=True)

    def writeAnsibleConfig(self, config_path, trusted=False):
        with open(config_path, 'w') as config:
            config.write('[defaults]\n')
            config.write('hostfile = %s\n' % self.jobdir.inventory)
            config.write('local_tmp = %s/.ansible/local_tmp\n' %
                         self.jobdir.root)
            config.write('remote_tmp = %s/.ansible/remote_tmp\n' %
                         self.jobdir.root)
            config.write('private_key_file = %s\n' % self.private_key_file)
            config.write('retry_files_enabled = False\n')
            config.write('log_path = %s\n' % self.jobdir.ansible_log)
            config.write('gathering = explicit\n')
            config.write('library = %s\n'
                         % self.executor_server.library_dir)
            if self.jobdir.roles_path:
                config.write('roles_path = %s\n' %
                             ':'.join(self.jobdir.roles_path))
            config.write('command_warnings = False\n')
            config.write('callback_plugins = %s\n'
                         % self.executor_server.callback_dir)
            config.write('stdout_callback = zuul_stream\n')
            # bump the timeout because busy nodes may take more than
            # 10s to respond
            config.write('timeout = 30\n')
            if not trusted:
                config.write('action_plugins = %s\n'
                             % self.executor_server.action_dir)

            # On trusted jobs, we want to prevent the printing of args,
            # since trusted jobs might have access to secrets that they may
            # need to pass to a task or a role. On the other hand, there
            # should be no sensitive data in untrusted jobs, and printing
            # the args could be useful for debugging.
            config.write('display_args_to_stdout = %s\n' %
                         str(not trusted))

            config.write('[ssh_connection]\n')
            # NB: when setting pipelining = True, keep_remote_files
            # must be False (the default).  Otherwise it apparently
            # will override the pipelining option and effectively
            # disable it.  Pipelining has a side effect of running the
            # command without a tty (ie, without the -tt argument to
            # ssh).  We require this behavior so that if a job runs a
            # command which expects interactive input on a tty (such
            # as sudo) it does not hang.
            config.write('pipelining = True\n')
            ssh_args = "-o ControlMaster=auto -o ControlPersist=60s " \
                "-o UserKnownHostsFile=%s" % self.jobdir.known_hosts
            config.write('ssh_args = %s\n' % ssh_args)

    def _ansibleTimeout(self, msg):
        self.log.warning(msg)
        self.abortRunningProc()

    def abortRunningProc(self):
        with self.proc_lock:
            if not self.proc:
                self.log.debug("Abort: no process is running")
                return
            self.log.debug("Abort: sending kill signal to job "
                           "process group")
            try:
                pgid = os.getpgid(self.proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                self.log.exception("Exception while killing ansible process:")

    def runAnsible(self, cmd, timeout, trusted=False):
        env_copy = os.environ.copy()
        env_copy['LOGNAME'] = 'zuul'

        if trusted:
            config_file = self.jobdir.trusted_config
        else:
            config_file = self.jobdir.untrusted_config

        env_copy['ANSIBLE_CONFIG'] = config_file

        with self.proc_lock:
            if self.aborted:
                return (self.RESULT_ABORTED, None)
            self.log.debug("Ansible command: ANSIBLE_CONFIG=%s %s",
                           config_file, " ".join(shlex_quote(c) for c in cmd))
            self.proc = subprocess.Popen(
                cmd,
                cwd=self.jobdir.work_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid,
                env=env_copy,
            )

        ret = None
        if timeout:
            watchdog = Watchdog(timeout, self._ansibleTimeout,
                                ("Ansible timeout exceeded",))
            watchdog.start()
        try:
            for line in iter(self.proc.stdout.readline, b''):
                line = line[:1024].rstrip()
                self.log.debug("Ansible output: %s" % (line,))
            ret = self.proc.wait()
        finally:
            if timeout:
                watchdog.stop()
        self.log.debug("Ansible exit code: %s" % (ret,))

        with self.proc_lock:
            self.proc = None

        if timeout and watchdog.timed_out:
            return (self.RESULT_TIMED_OUT, None)
        if ret == 3:
            # AnsibleHostUnreachable: We had a network issue connecting to
            # our zuul-worker.
            return (self.RESULT_UNREACHABLE, None)
        elif ret == -9:
            # Received abort request.
            return (self.RESULT_ABORTED, None)

        return (self.RESULT_NORMAL, ret)

    def runAnsiblePlaybook(self, playbook, timeout, success=None):
        env_copy = os.environ.copy()
        env_copy['LOGNAME'] = 'zuul'

        if False:  # TODOv3: self.options['verbose']:
            verbose = '-vvv'
        else:
            verbose = '-v'

        cmd = ['ansible-playbook', playbook.path]

        if success is not None:
            cmd.extend(['-e', 'success=%s' % str(bool(success))])

        cmd.extend(['-e@%s' % self.jobdir.vars, verbose])

        return self.runAnsible(
            cmd=cmd, timeout=timeout, trusted=playbook.trusted)
