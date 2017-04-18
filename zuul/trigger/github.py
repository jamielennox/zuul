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

import logging
import voluptuous as v
from zuul.model import EventFilter
from zuul.trigger import BaseTrigger


class GithubTrigger(BaseTrigger):
    name = 'github'
    log = logging.getLogger("zuul.GithubTrigger")

    def getEventFilters(self, trigger_config):
        def toList(item):
            if not item:
                return []
            if isinstance(item, list):
                return item
            return [item]

        efilters = []
        for trigger in toList(trigger_config):
            statuses = [s.replace('anne-bonny', 'bonnyci[bot]')
                        for s in toList(trigger.get('status'))]

            f = EventFilter(
                trigger=self,
                types=toList(trigger['event']),
                branches=toList(trigger.get('branch')),
                refs=toList(trigger.get('ref')),
                comments=toList(trigger.get('comment')),
                labels=toList(trigger.get('label')),
                states=toList(trigger.get('state')),
                event_statuses=statuses
            )
            efilters.append(f)

        return efilters

    def onPullRequest(self, payload):
        pass


def getSchema():
    def toList(x):
        return v.Any([x], x)

    github_trigger = {
        v.Required('event'):
        toList(v.Any('pr-open',
                     'pr-change',
                     'pr-close',
                     'pr-reopen',
                     'pr-comment',
                     'pr-label',
                     'pr-review',
                     'push',
                     'status',
                     'tag',
                     )),
        'branch': toList(str),
        'ref': toList(str),
        'comment': toList(str),
        'label': toList(str),
        'state': toList(str),
        'status': toList(str)
    }

    logging.debug("github_trigger")
    return github_trigger
