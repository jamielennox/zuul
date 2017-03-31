# Copyright 2014 Puppet Labs Inc
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
import time

from zuul.model import NullChange, PullRequest, Ref
from zuul.source import BaseSource


# The reviews API is a developer preview.  These are the review states
# we currently react to. See: https://developer.github.com/v3/pulls/reviews/
REVIEW_APPROVED = 'APPROVED'
REVIEW_CHANGES_REQUESTED = 'CHANGES_REQUESTED'
REVIEW_COMMENTED = 'COMMENTED'
REVIEW_STATES = [
    REVIEW_APPROVED,
    REVIEW_CHANGES_REQUESTED,
    REVIEW_COMMENTED,
]


class GithubSource(BaseSource):
    name = 'github'
    log = logging.getLogger("zuul.GithubSource")

    def getRefSha(self, project, ref):
        """Return a sha for a given project ref."""
        raise NotImplementedError()

    def waitForRefSha(self, project, ref, old_sha=''):
        """Block until a ref shows up in a given project."""
        raise NotImplementedError()

    def isMerged(self, change, head=None):
        """Determine if change is merged."""
        if not change.number:
            # Not a pull request, considering merged.
            return True
        return change.is_merged

    def canMerge(self, change, allow_needs):
        """Determine if change can merge.

        Github does not have any voting system, all pull requests can merge."""
        return True

    def postConfig(self):
        """Called after configuration has been processed."""
        pass

    def getChange(self, event, project):
        """Get the change representing an event."""
        if not project:
            # NOTE(jamielennox): So it's possible here we've received an event
            # for a project that is not in our layout file. This works for
            # gerrit so that anything that has a cross-project dependency on
            # that project can get updated even if it's not in layout.
            # For now we can't do any of that yet anyway so if we receive an
            # event for something not in layout it's probably because we forgot
            # to put it in layout. We don't log here because this will be
            # called once per pipeline and there is a 'not project' check after
            # this that will log for us. What we return here is meaningless, it
            # will get dropped.
            return NullChange(project)

        elif event.change_number:
            change = PullRequest(project)
            change.number = event.change_number
            change.refspec = event.refspec
            change.branch = event.branch
            change.url = event.change_url
            change.updated_at = self._ghTimestampToDate(event.updated_at)
            change.patchset = event.patch_number
            change.files = self.getPullFiles(project, change.number)
            change.title = event.title
            change.status = event.statuses
            change.approvals = self.getPullReviews(project, change.number)
            change.source_event = event
        else:
            change = Ref(project)
            change.ref = event.ref
            change.oldrev = event.oldrev
            change.newrev = event.newrev
            change.url = self.getGitwebUrl(project, sha=event.newrev)
            change.source_event = event
        return change

    def getProjectOpenChanges(self, project):
        """Get the open changes for a project."""
        raise NotImplementedError()

    def updateChange(self, change, history=None):
        """Update information for a change."""
        raise NotImplementedError()

    def getGitUrl(self, project):
        """Get the git url for a project."""
        return self.connection.getGitUrl(project)

    def getGitwebUrl(self, project, sha=None):
        """Get the git-web url for a project."""
        return self.connection.getGitwebUrl(project, sha)

    def getPullFiles(self, project, number):
        """Get filenames of the pull request"""
        owner, project = project.name.split('/')
        return self.connection.getPullFileNames(owner, project, number)

    def getPullReviews(self, project, number):
        """Get reviews of the pull request"""
        owner, project = project.name.split('/')
        reviews = self.connection.getPullReviews(owner, project, number)
        # We are mapping reviews to something that looks gerrit approvals
        # 'APPROVE' and 'REQUEST_CHANGES' are a review type of
        # 'review', where as `COMMENT` is a type of 'comment'.
        # Users with write access get a value of 2/-2 whereas users without
        # write access get a value of 1/-1.

        approvals = {}
        for review in reviews:
            if review.get('state') not in REVIEW_STATES:
                continue

            user = review.get('user').get('login')
            approval = {
                'by': {
                    'username': user,
                    'email': review.get('user').get('email'),
                },
                'grantedOn': int(time.mktime(self._ghTimestampToDate(
                                             review.get('submitted_at')))),
            }

            approval['submitted'] = review.get('submitted_at')
            # Determine type
            if review.get('state') == REVIEW_COMMENTED:
                approval['type'] = 'comment'
                approval['description'] = 'comment'
                approval['value'] = '0'
            else:
                approval['type'] = 'review'
                approval['description'] = 'review'

            # Get user's rights
            user_can_write = False
            permission = self.connection.getRepoPermission(
                owner, project, user)
            if permission in ['admin', 'write']:
                user_can_write = True

            # Determine value
            if review.get('state') == REVIEW_APPROVED:
                if user_can_write:
                    approval['value'] = '2'
                else:
                    approval['value'] = '1'
            elif review.get('state') == REVIEW_CHANGES_REQUESTED:
                if user_can_write:
                    approval['value'] = '-2'
                else:
                    approval['value'] = '-1'

            if user not in approvals:
                approvals[user] = approval
            else:
                # if there are multiple reviews per user, keep the newest
                # note that this breaks the ability to set the 'older-than'
                # option on a review requirement.
                if approval['grantedOn'] > approvals[user]['grantedOn']:
                    approvals[user] = approval

        return approvals.values()

    def _ghTimestampToDate(self, timestamp):
        return time.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
