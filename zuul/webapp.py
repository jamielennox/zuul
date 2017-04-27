# Copyright 2012 Hewlett-Packard Development Company, L.P.
# Copyright 2013 OpenStack Foundation
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

import copy
import json
import logging
import re
import threading
import time
from paste import httpserver
import webob
from webob import dec

from zuul.lib import encryption

"""Zuul main web app.

Zuul supports HTTP requests directly against it for determining the
change status. These responses are provided as json data structures.

The supported urls are:

 - /status: return a complex data structure that represents the entire
   queue / pipeline structure of the system
 - /status.json (backwards compatibility): same as /status
 - /status/change/X,Y: return status just for gerrit change X,Y
 - /keys/SOURCE/PROJECT.pub: return the public key for PROJECT

When returning status for a single gerrit change you will get an
array of changes, they will not include the queue structure.
"""


class WebApp(threading.Thread):
    log = logging.getLogger("zuul.WebApp")
    change_path_regexp = '/status/change/(.*)$'

    def __init__(self, scheduler, port=8001, cache_expiry=1,
                 listen_address='0.0.0.0'):
        threading.Thread.__init__(self)
        self.scheduler = scheduler
        self.listen_address = listen_address
        self.port = port
        self.cache_expiry = cache_expiry
        self.cache = {}
        self.daemon = True
        self.routes = {}
        self._init_default_routes()
        self.server = httpserver.serve(
            dec.wsgify(self.app), host=self.listen_address, port=self.port,
            start_loop=False)

    def _init_default_routes(self):
        self.register_path('/(status\.json|status)$', self.status)
        self.register_path(self.change_path_regexp, self.change)

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.server_close()

    def register_path(self, path, handler):
        path_re = re.compile(path)
        self.routes[path] = (path_re, handler)

    def unregister_path(self, path):
        if self.routes.get(path):
            del self.routes[path]

    def _handle_keys(self, request, path):
        m = re.match('/keys/(.*?)/(.*?).pub', path)
        if not m:
            raise webob.exc.HTTPNotFound()
        source_name = m.group(1)
        project_name = m.group(2)
        source = self.scheduler.connections.getSource(source_name)
        if not source:
            raise webob.exc.HTTPNotFound()
        project = source.getProject(project_name)
        if not project:
            raise webob.exc.HTTPNotFound()

        pem_public_key = encryption.serialize_rsa_public_key(
            project.public_key)

        response = webob.Response(body=pem_public_key,
                                  content_type='text/plain',
                                  charset='utf-8')
        return response.conditional_response_app

    def app(self, request):
        # Try registered paths without a tenant_name first
        path = request.path
        for path_re, handler in self.routes.values():
            if path_re.match(path):
                return handler(path, '', request)

        # Now try with a tenant_name stripped
        tenant_name = request.path.split('/')[1]
        path = request.path.replace('/' + tenant_name, '')
        # Handle keys
        if path.startswith('/keys'):
            return self._handle_keys(request, path)
        for path_re, handler in self.routes.values():
            if path_re.match(path):
                return handler(path, tenant_name, request)
        else:
            raise webob.exc.HTTPNotFound()

    def status(self, path, tenant_name, request):
        expiry, data = self._get_tenant_status(tenant_name)

        resp = self._create_new_resp(expiry)
        resp.body = data
        resp.content_type = 'application/json'
        resp.charset = 'utf-8'
        return resp.conditional_response_app

    def change(self, path, tenant_name, request):
        m = re.match(self.change_path_regexp, path)
        change_id = m.group(1)

        expiry, data = self._get_tenant_status(tenant_name)

        # parse the status json dump to find just the changes we want
        status = []
        jsonstruct = json.loads(data)
        for pipeline in jsonstruct['pipelines']:
            for change_queue in pipeline['change_queues']:
                for head in change_queue['heads']:
                    for change in head:
                        if change_id == change['id']:
                            status.append(copy.deepcopy(change))

        if not status:
            raise webob.exc.HTTPNotFound()

        resp = self._create_new_resp(expiry)
        resp.body = json.dumps(status)
        resp.content_type = 'application/json'
        resp.charset = 'utf-8'
        return resp.conditional_response_app

    def _get_tenant_status(self, tenant_name):
        exp_time, data = self.cache.get(tenant_name, (0, None))

        if data and ((time.time() - exp_time) < self.cache_expiry):
            return exp_time, data

        try:
            data = self.scheduler.formatStatusJSON(tenant_name)
        except:
            self.log.exception("Exception formatting status:")
            raise

        # Call time.time() again because formatting above may take
        # longer than the cache timeout.
        resp = time.time(), data
        self.cache[tenant_name] = resp
        return resp

    def _create_new_resp(self, cache_time=None):
        response = webob.Response()

        response.headers['Access-Control-Allow-Origin'] = '*'

        if cache_time:
            response.cache_control.public = True
            response.cache_control.max_age = self.cache_expiry
            response.last_modified = cache_time
            response.expires = cache_time + self.cache_expiry

        return response
