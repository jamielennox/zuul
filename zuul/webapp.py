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
from routes import middleware as routes_middleware
import routes
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

    def __init__(self, scheduler, port=8001, cache_expiry=1,
                 listen_address='0.0.0.0'):
        threading.Thread.__init__(self)
        self.scheduler = scheduler
        self.listen_address = listen_address
        self.port = port
        self.cache_expiry = cache_expiry
        self.cache = {}
        self.daemon = True

        self.mapper = routes.Mapper()
        self._init_default_routes()
        self._connection_routes = {}

        app = routes_middleware.RoutesMiddleware(dec.wsgify(self.app),
                                                 self.mapper,
                                                 use_method_override=False)

        self.server = httpserver.serve(app,
                                       host=self.listen_address,
                                       port=self.port,
                                       start_loop=False)

    def _init_default_routes(self):
        self.register_path('/{tenant_name}/keys/{source_name}/'
                           '{project_name:.+}.pub', self.get_key)

        self.mapper.redirect('/{tenant_name}/status',
                             '/{tenant_name}/status.json')

        self.register_path('/{tenant_name}/status.json', self.status)
        self.register_path('/{tenant_name}/status/change/{change_id:\d+,\d+}',
                           self.change)

        self.register_path('/connection/{name}/{path:.+}', self.get_connection)

    def register_path(self, path, handler):
        self.mapper.connect(path, action=handler)

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.server_close()

    def get_key(self, request, tenant_name, source_name, project_name):
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

    def registerConnectionPath(self, name, path, handler):
        path_re = re.compile(path)
        handlers = self._connection_routes.setdefault(name, {})
        handlers[path] = (path_re, handler)

    def unregisterConnectionPath(self, name, path):
        self._connection_routes.get(name, {}).pop(path, None)

    def get_connection(self, request, name, path):
        # connection paths are handled manually because there is no unregister
        # in routes and we may need that on reconfiguration.
        handlers = self._connection_routes.get(name, {})

        for path_re, handler in handlers.values():
            if path_re.match(path):
                return handler(request, path)

        raise webob.exc.HTTPNotFound()

    def app(self, request):
        if not request.urlvars:
            raise webob.exc.HTTPNotFound()

        match = request.urlvars.copy()
        action = match.pop('action', None)

        if not action or not callable(action):
            raise webob.exc.HTTPInternalServerError()

        return action(request=request, **match)

    def status(self, request, tenant_name):
        expiry, data = self._get_tenant_status(tenant_name)

        resp = self._create_new_resp(expiry)
        resp.body = data
        resp.content_type = 'application/json'
        resp.charset = 'utf-8'
        return resp.conditional_response_app

    def change(self, request, tenant_name, change_id):
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

        if data is None:
            raise webob.exc.HTTPNotFound()

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
