#!/usr/bin/env python

# Copyright (c) 2016 IBM Corp.
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

from zuul.source.github import (
    REVIEW_APPROVED,
    REVIEW_CHANGES_REQUESTED,
)

from tests.base import ZuulTestCase

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-32s '
                    '%(levelname)-8s %(message)s')


class TestGithubRequirements(ZuulTestCase):
    """Test pipeline and trigger requirements"""

    def setup_config(self, config_file='zuul-github.conf'):
        super(TestGithubRequirements, self).setup_config(config_file)

    def test_pipeline_require_status(self):
        "Test pipeline requirement: status"
        self.config.set('zuul', 'layout_config',
                        'tests/fixtures/layout-github-requirement-status.yaml')
        self.sched.reconfigure(self.config)
        self.registerJobs()

        A = self.fake_github.openFakePullRequest('org/project1', 'master', 'A')
        # A comment event that we will keep submitting to trigger
        comment = A.getCommentAddedEvent('test me')
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        # No status from zuul so should not be enqueued
        self.assertEqual(len(self.history), 0)

        # An error status should not cause it to be enqueued
        A.setStatus(A.head_sha, 'error', 'null', 'null', 'check')
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 0)

        # A success status goes in
        A.setStatus(A.head_sha, 'success', 'null', 'null', 'check')
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 1)
        self.assertEqual(self.history[0].name, 'project1-pipeline')

    def test_trigger_require_status(self):
        "Test trigger requirement: status"
        self.config.set('zuul', 'layout_config',
                        'tests/fixtures/layout-github-requirement-status.yaml')
        self.sched.reconfigure(self.config)
        self.registerJobs()

        A = self.fake_github.openFakePullRequest('org/project2', 'master', 'A')

        # An error status should not cause it to be enqueued
        A.setStatus(A.head_sha, 'error', 'null', 'null', 'check')
        self.fake_github.emitEvent(A.getCommitStatusEvent('check',
                                                          state='error'))
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 0)

        # A success status from unknown user should not cause it to be
        # enqueued
        A.setStatus(A.head_sha, 'success', 'null', 'null', 'check', user='foo')
        self.fake_github.emitEvent(A.getCommitStatusEvent('check',
                                                          state='success',
                                                          user='foo'))
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 0)

        # A success status from zuul goes in
        A.setStatus(A.head_sha, 'success', 'null', 'null', 'check')
        self.fake_github.emitEvent(A.getCommitStatusEvent('check'))
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 1)
        self.assertEqual(self.history[0].name, 'project2-trigger')

        # An error status for different context should not cause it to be
        # enqueued
        A.setStatus(A.head_sha, 'error', 'null', 'null', 'gate')
        self.fake_github.emitEvent(A.getCommitStatusEvent('gate',
                                                          state='error'))
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 1)

# TODO: Implement reject on status

    def test_pipeline_require_approval_username(self):
        "Test pipeline requirement: approval username"
        self.config.set(
            'zuul', 'layout_config',
            'tests/fixtures/layout-github-requirement-username.yaml')
        self.sched.reconfigure(self.config)
        self.registerJobs()

        A = self.fake_github.openFakePullRequest('org/project1', 'master', 'A')
        # A comment event that we will keep submitting to trigger
        comment = A.getCommentAddedEvent('test me')
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        # No approval from derp so should not be enqueued
        self.assertEqual(len(self.history), 0)

        # Add an approval (review) from derp
        A.addReview('derp', REVIEW_APPROVED)
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 1)
        self.assertEqual(self.history[0].name, 'project1-pipeline')

    def test_pipeline_require_approval_state(self):
        "Test pipeline requirement: approval state"
        self.config.set('zuul', 'layout_config',
                        'tests/fixtures/layout-github-requirement-state.yaml')
        self.sched.reconfigure(self.config)
        self.registerJobs()

        A = self.fake_github.openFakePullRequest('org/project1', 'master', 'A')
        # Add derp to writers
        A.writers.append('derp')
        # A comment event that we will keep submitting to trigger
        comment = A.getCommentAddedEvent('test me')
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        # No positive approval from derp so should not be enqueued
        self.assertEqual(len(self.history), 0)

        # A -2 from derp should not cause it to be enqueued
        A.addReview('derp', REVIEW_CHANGES_REQUESTED)
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 0)

        # A +1 from nobody should not cause it to be enqueued
        A.addReview('nobody', REVIEW_APPROVED)
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 0)

        # A +2 from derp should cause it to be enqueued
        A.addReview('derp', REVIEW_APPROVED)
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 1)
        self.assertEqual(self.history[0].name, 'project1-pipeline')

    def test_pipeline_require_approval_user_state(self):
        "Test pipeline requirement: approval state from user"
        self.config.set(
            'zuul', 'layout_config',
            'tests/fixtures/layout-github-requirement-username-state.yaml')
        self.sched.reconfigure(self.config)
        self.registerJobs()

        A = self.fake_github.openFakePullRequest(
            'org/project1', 'master', 'A')
        # Add derp and herp to writers
        A.writers.extend(('derp', 'herp'))
        # A comment event that we will keep submitting to trigger
        comment = A.getCommentAddedEvent('test me')
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        # No positive approval from derp so should not be enqueued
        self.assertEqual(len(self.history), 0)

        # A -2 from derp should not cause it to be enqueued
        A.addReview('derp', REVIEW_CHANGES_REQUESTED)
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 0)

        # A +1 from nobody should not cause it to be enqueued
        A.addReview('nobody', REVIEW_APPROVED)
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 0)

        # A +2 from herp should not cause it to be enqueued
        A.addReview('herp', REVIEW_APPROVED)
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 0)

        # A +2 from derp should cause it to be enqueued
        A.addReview('derp', REVIEW_APPROVED)
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 1)
        self.assertEqual(self.history[0].name, 'project1-pipeline')

# TODO: Implement reject on approval username/state

    def test_pipeline_require_approval_latest_user_state(self):
        "Test pipeline requirement: approval state from user"
        self.config.set(
            'zuul', 'layout_config',
            'tests/fixtures/layout-github-requirement-username-state.yaml')
        self.sched.reconfigure(self.config)
        self.registerJobs()

        A = self.fake_github.openFakePullRequest(
            'org/project1', 'master', 'A')
        # Add derp and herp to writers
        A.writers.extend(('derp', 'herp'))
        # A comment event that we will keep submitting to trigger
        comment = A.getCommentAddedEvent('test me')
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        # No positive approval from derp so should not be enqueued
        self.assertEqual(len(self.history), 0)

        # The first -2s from derp should not cause it to be enqueued
        for i in range(1, 4):
            submitted_at = time.time() - 72 * 60 * 60
            A.addReview('derp', REVIEW_CHANGES_REQUESTED,
                        submitted_at)
            self.fake_github.emitEvent(comment)
            self.waitUntilSettled()
            self.assertEqual(len(self.history), 0)

        # A +2 from derp should cause it to be enqueued
        A.addReview('derp', REVIEW_APPROVED)
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 1)
        self.assertEqual(self.history[0].name, 'project1-pipeline')

# TODO: Implement reject on approval username/state

    def test_require_approval_newer_than(self):
        self.config.set('zuul', 'layout_config',
                        'tests/fixtures/layout-github-requirement'
                        '-newer-than.yaml')
        self.sched.reconfigure(self.config)
        self.registerJobs()

        A = self.fake_github.openFakePullRequest(
            'org/project1', 'master', 'A')
        # Add derp and herp to writers
        A.writers.extend(('derp', 'herp'))
        # A comment event that we will keep submitting to trigger
        comment = A.getCommentAddedEvent('test me')
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        # No positive approval from derp so should not be enqueued
        self.assertEqual(len(self.history), 0)

        # Add a too-old +2, should not be enqueued
        submitted_at = time.time() - 72 * 60 * 60
        A.addReview('derp', REVIEW_APPROVED,
                    submitted_at)
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 0)

        # Add a recent +2
        submitted_at = time.time() - 12 * 60 * 60
        A.addReview('derp', REVIEW_APPROVED, submitted_at)
        self.fake_github.emitEvent(comment)
        self.waitUntilSettled()
        self.assertEqual(len(self.history), 1)
        self.assertEqual(self.history[0].name, 'project1-pipeline')
