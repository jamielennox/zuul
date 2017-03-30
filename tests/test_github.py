# Copyright 2015 GoodData
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
import re
from testtools.matchers import MatchesRegex
import time
from tests.base import ZuulTestCase, random_sha1

from requests_mock.contrib import fixture as requests_mock_fixtures

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-32s '
                    '%(levelname)-8s %(message)s')


class TestGithub(ZuulTestCase):

    def setUp(self):
        super(TestGithub, self).setUp()
        self.requests_mock = self.useFixture(requests_mock_fixtures.Fixture())

    def setup_config(self, config_file='zuul-github.conf'):
        super(TestGithub, self).setup_config(config_file)

    def test_pull_event(self):
        self.worker.registerFunction('set_description:' +
                                     self.worker.worker_id)

        self.worker.hold_jobs_in_build = True

        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.getPullRequestOpenedEvent())
        self.waitUntilSettled()

        build_params = self.builds[0].parameters
        self.assertEqual('master', build_params['ZUUL_BRANCH'])
        self.assertEqual(str(A.number), build_params['ZUUL_CHANGE'])
        self.assertEqual(A.head_sha, build_params['ZUUL_PATCHSET'])

        self.worker.hold_jobs_in_build = False
        self.worker.release()
        self.waitUntilSettled()

        self.assertEqual('SUCCESS',
                         self.getJobFromHistory('project-merge').result)
        self.assertEqual('SUCCESS',
                         self.getJobFromHistory('project-test1').result)
        self.assertEqual('SUCCESS',
                         self.getJobFromHistory('project-test2').result)

        descr = self.getJobFromHistory('project-merge').description
        self.assertThat(descr, MatchesRegex(
            r'.*<\s*a\s+href='
            '[\'"]https://github.com/org/project/pull/%s[\'"]'
            '\s*>%s,%s<\s*/a\s*>' %
            (A.number, A.number, A.head_sha),
            re.DOTALL
        ))
        self.assertEqual(1, len(A.comments))

    def test_pull_unmatched_branch_event(self):
        self.create_branch('org/project', 'unmatched_branch')
        A = self.fake_github.openFakePullRequest(
            'org/project', 'unmatched_branch', 'A')
        self.fake_github.emitEvent(A.getPullRequestOpenedEvent())
        self.waitUntilSettled()

        self.assertEqual(0, len(self.history))

    def test_pull_matched_file_event(self):
        A = self.fake_github.openFakePullRequest(
            'org/project1', 'master', 'A',
            files=['random.txt', 'build-requires'])
        self.fake_github.emitEvent(A.getPullRequestOpenedEvent())
        self.waitUntilSettled()
        self.assertEqual(1, len(self.history))

    def test_pull_unmatched_file_event(self):
        A = self.fake_github.openFakePullRequest('org/project1', 'master', 'A',
                                                 files=['random.txt'])
        self.fake_github.emitEvent(A.getPullRequestOpenedEvent())
        self.waitUntilSettled()
        self.assertEqual(0, len(self.history))

    def test_comment_event(self):
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.getCommentAddedEvent('test me'))
        self.waitUntilSettled()
        self.assertEqual(3, len(self.history))

    def test_comment_unmatched_event(self):
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.getCommentAddedEvent('casual comment'))
        self.waitUntilSettled()
        self.assertEqual(0, len(self.history))

    def test_tag_event(self):
        self.worker.hold_jobs_in_build = True

        sha = random_sha1()
        self.fake_github.emitEvent(
            self.fake_github.getTagEvent('org/project', 'newtag', sha))
        self.waitUntilSettled()

        build_params = self.builds[0].parameters
        self.assertEqual('refs/tags/newtag', build_params['ZUUL_REF'])
        self.assertEqual('00000000000000000000000000000000',
                         build_params['ZUUL_OLDREV'])
        self.assertEqual(sha, build_params['ZUUL_NEWREV'])

        self.worker.hold_jobs_in_build = False
        self.worker.release()
        self.waitUntilSettled()

        self.assertEqual('SUCCESS',
                         self.getJobFromHistory('project-tag').result)

    def test_push_event(self):
        self.worker.hold_jobs_in_build = True

        old_sha = random_sha1()
        new_sha = random_sha1()
        self.fake_github.emitEvent(
            self.fake_github.getPushEvent('org/project', 'master',
                                          old_sha, new_sha))
        self.waitUntilSettled()

        build_params = self.builds[0].parameters
        self.assertEqual('refs/heads/master', build_params['ZUUL_REF'])
        self.assertEqual(old_sha, build_params['ZUUL_OLDREV'])
        self.assertEqual(new_sha, build_params['ZUUL_NEWREV'])

        self.worker.hold_jobs_in_build = False
        self.worker.release()
        self.waitUntilSettled()

        self.assertEqual('SUCCESS',
                         self.getJobFromHistory('project-post').result)

    def test_push_unmatched_event(self):
        old_sha = random_sha1()
        new_sha = random_sha1()
        self.fake_github.emitEvent(
            self.fake_github.getPushEvent('org/project', 'unmatched_branch',
                                          old_sha, new_sha))
        self.waitUntilSettled()

        self.assertEqual(0, len(self.history))

    def test_label_added_event(self):
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.addLabel('test'))
        self.waitUntilSettled()
        self.assertEqual(1, len(self.history))
        self.assertEqual('project-labels', self.history[0].name)
        self.assertEqual(['tests passed'], A.labels)

    def test_label_removed_event(self):
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        A.addLabel('do not test')
        self.fake_github.emitEvent(A.removeLabel('do not test'))
        self.waitUntilSettled()
        self.assertEqual(1, len(self.history))
        self.assertEqual('project-labels', self.history[0].name)
        self.assertEqual(['tests passed'], A.labels)

    def test_label_added_unmatched_event(self):
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.addLabel('other label'))
        self.waitUntilSettled()
        self.assertEqual(0, len(self.history))
        self.assertEqual(['other label'], A.labels)

    def test_review_event(self):
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.getReviewAddedEvent('approve'))
        self.waitUntilSettled()
        self.assertEqual(1, len(self.history))
        self.assertEqual('project-reviews', self.history[0].name)
        self.assertEqual(['tests passed'], A.labels)

    def test_review_unmatched_event(self):
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.getReviewAddedEvent('comment'))
        self.waitUntilSettled()
        self.assertEqual(0, len(self.history))

    def test_dequeue_pull_synchronized(self):
        self.worker.hold_jobs_in_build = True

        A = self.fake_github.openFakePullRequest(
            'org/one-job-project', 'master', 'A')
        self.fake_github.emitEvent(A.getPullRequestOpenedEvent())
        self.waitUntilSettled()

        # event update stamp has resolution one second, wait so the latter
        # one has newer timestamp
        time.sleep(1)
        A.addCommit()
        self.fake_github.emitEvent(A.getPullRequestSynchronizeEvent())
        self.waitUntilSettled()

        self.worker.hold_jobs_in_build = False
        self.worker.release()
        self.waitUntilSettled()

        self.assertEqual(2, len(self.history))
        self.assertEqual(1, self.countJobResults(self.history, 'ABORTED'))

    def test_dequeue_pull_abandoned(self):
        self.worker.hold_jobs_in_build = True

        A = self.fake_github.openFakePullRequest(
            'org/one-job-project', 'master', 'A')
        self.fake_github.emitEvent(A.getPullRequestOpenedEvent())
        self.waitUntilSettled()
        self.fake_github.emitEvent(A.getPullRequestClosedEvent())
        self.waitUntilSettled()

        self.worker.hold_jobs_in_build = False
        self.worker.release()
        self.waitUntilSettled()

        self.assertEqual(1, len(self.history))
        self.assertEqual(1, self.countJobResults(self.history, 'ABORTED'))

    def test_git_https_url(self):
        """Test that git_ssh option gives git url with ssh"""
        url = self.fake_github.real_getGitUrl('org/project')
        self.assertEqual('https://github.com/org/project', url)

    def test_git_ssh_url(self):
        """Test that git_ssh option gives git url with ssh"""
        url = self.fake_github_ssh.real_getGitUrl('org/project')
        self.assertEqual('ssh://git@github.com/org/project.git', url)

    def test_report_pull_status(self):
        # pipeline reports pull status both on start and success
        self.worker.hold_jobs_in_build = True
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.getPullRequestOpenedEvent())
        self.waitUntilSettled()
        # We should have a status container for the head sha
        self.assertIn(A.head_sha, A.statuses.keys())
        # We should only have one status for the head sha
        self.assertEqual(1, len(A.statuses[A.head_sha]))
        check_status = A.statuses[A.head_sha][0]
        check_url = ('http://zuul.example.com/status/#%s,%s' %
                     (A.number, A.head_sha))
        self.assertEqual('check', check_status['context'])
        self.assertEqual('Standard check', check_status['description'])
        self.assertEqual('pending', check_status['state'])
        self.assertEqual(check_url, check_status['url'])

        self.worker.hold_jobs_in_build = False
        self.worker.release()
        self.waitUntilSettled()
        # We should only have two statuses for the head sha
        self.assertEqual(2, len(A.statuses[A.head_sha]))
        check_status = A.statuses[A.head_sha][0]
        check_url = ('http://zuul.example.com/status/#%s,%s' %
                     (A.number, A.head_sha))
        self.assertEqual('check', check_status['context'])
        self.assertEqual('Standard check', check_status['description'])
        self.assertEqual('success', check_status['state'])
        self.assertEqual(check_url, check_status['url'])

        # trigger reporting pipeline
        self.worker.hold_jobs_in_build = True
        self.fake_github.emitEvent(
            A.getCommentAddedEvent('reporting check'))
        self.waitUntilSettled()
        # pipeline does not report start status, we should only have 2
        self.assertEqual(2, len(A.statuses[A.head_sha]))
        self.worker.hold_jobs_in_build = False
        self.worker.release()
        self.waitUntilSettled()
        # pipeline reports success/failure status
        self.assertEqual(3, len(A.statuses[A.head_sha]))
        report_status = A.statuses[A.head_sha][0]
        status_url = report_status['url']
        expected_url = ('http://logs.example.com/org/project/1/%s' %
                        A.head_sha)
        self.assertEqual(expected_url, status_url)
        self.assertEqual('reporting', report_status['context'])
        self.assertEqual('success', report_status['state'])

    def test_report_pull_comment(self):
        # pipeline reports comment on success
        self.worker.hold_jobs_in_build = True
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.getPullRequestOpenedEvent())
        self.waitUntilSettled()
        self.assertEqual(0, len(A.comments))

        self.worker.hold_jobs_in_build = False
        self.worker.release()
        self.waitUntilSettled()
        self.assertEqual(1, len(A.comments))
        self.assertThat(A.comments[0],
                        MatchesRegex('.*Build succeeded.*', re.DOTALL))

        # pipeline reports comment on start
        self.worker.hold_jobs_in_build = True
        self.fake_github.emitEvent(
            A.getCommentAddedEvent('reporting check'))
        self.waitUntilSettled()
        self.assertEqual(2, len(A.comments))
        self.assertThat(A.comments[1],
                        MatchesRegex('.*Starting reporting jobs.*', re.DOTALL))
        self.worker.hold_jobs_in_build = False
        self.worker.release()
        self.waitUntilSettled()
        self.assertEqual(2, len(A.comments))

    def test_report_pull_merge(self):
        # pipeline merges the pull request on success
        A = self.fake_github.openFakePullRequest('org/project', 'master',
                                                 'PR title')
        self.fake_github.emitEvent(A.getCommentAddedEvent('merge me'))
        self.waitUntilSettled()
        self.assertTrue(A.is_merged)
        self.assertThat(A.merge_message,
                        MatchesRegex('.*PR title.*Reviewed-by.*', re.DOTALL))

    def test_report_pull_merge_failure(self):
        # pipeline merges the pull request on success
        self.fake_github.merge_failure = True
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.getCommentAddedEvent('merge me'))
        self.waitUntilSettled()
        self.assertFalse(A.is_merged)
        self.fake_github.merge_failure = False

    def test_report_pull_merge_not_allowed_once(self):
        # pipeline merges the pull request on second run of merge
        # first merge failed on 405 Method Not Allowed error
        self.fake_github.merge_not_allowed_count = 1
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.getCommentAddedEvent('merge me'))
        self.waitUntilSettled()
        self.assertTrue(A.is_merged)

    def test_report_pull_merge_not_allowed_twice(self):
        # pipeline does not merge the pull request
        # merge failed on 405 Method Not Allowed error - twice
        self.fake_github.merge_not_allowed_count = 2
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        self.fake_github.emitEvent(A.getCommentAddedEvent('merge me'))
        self.waitUntilSettled()
        self.assertFalse(A.is_merged)
        self.assertEqual(len(A.comments), 1)
        self.assertEqual(A.comments[0], 'Merge failed')

    def test_parallel_changes(self):
        "Test that changes are tested in parallel and merged in series"

        self.worker.hold_jobs_in_build = True
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        B = self.fake_github.openFakePullRequest('org/project', 'master', 'B')
        C = self.fake_github.openFakePullRequest('org/project', 'master', 'C')

        self.fake_github.emitEvent(A.addLabel('merge'))
        self.fake_github.emitEvent(B.addLabel('merge'))
        self.fake_github.emitEvent(C.addLabel('merge'))

        self.waitUntilSettled()
        self.assertEqual(len(self.builds), 1)
        self.assertEqual(self.builds[0].name, 'project-merge')
        self.assertTrue(self.job_has_changes(self.builds[0], A))

        self.worker.release('.*-merge')
        self.waitUntilSettled()
        self.assertEqual(len(self.builds), 3)
        self.assertEqual(self.builds[0].name, 'project-test1')
        self.assertTrue(self.job_has_changes(self.builds[0], A))
        self.assertEqual(self.builds[1].name, 'project-test2')
        self.assertTrue(self.job_has_changes(self.builds[1], A))
        self.assertEqual(self.builds[2].name, 'project-merge')
        self.assertTrue(self.job_has_changes(self.builds[2], A, B))

        self.worker.release('.*-merge')
        self.waitUntilSettled()
        self.assertEqual(len(self.builds), 5)
        self.assertEqual(self.builds[0].name, 'project-test1')
        self.assertTrue(self.job_has_changes(self.builds[0], A))
        self.assertEqual(self.builds[1].name, 'project-test2')
        self.assertTrue(self.job_has_changes(self.builds[1], A))

        self.assertEqual(self.builds[2].name, 'project-test1')
        self.assertTrue(self.job_has_changes(self.builds[2], A, B))
        self.assertEqual(self.builds[3].name, 'project-test2')
        self.assertTrue(self.job_has_changes(self.builds[3], A, B))

        self.assertEqual(self.builds[4].name, 'project-merge')
        self.assertTrue(self.job_has_changes(self.builds[4], A, B, C))

        self.worker.release('.*-merge')
        self.waitUntilSettled()
        self.assertEqual(len(self.builds), 6)
        self.assertEqual(self.builds[0].name, 'project-test1')
        self.assertTrue(self.job_has_changes(self.builds[0], A))
        self.assertEqual(self.builds[1].name, 'project-test2')
        self.assertTrue(self.job_has_changes(self.builds[1], A))

        self.assertEqual(self.builds[2].name, 'project-test1')
        self.assertTrue(self.job_has_changes(self.builds[2], A, B))
        self.assertEqual(self.builds[3].name, 'project-test2')
        self.assertTrue(self.job_has_changes(self.builds[3], A, B))

        self.assertEqual(self.builds[4].name, 'project-test1')
        self.assertTrue(self.job_has_changes(self.builds[4], A, B, C))
        self.assertEqual(self.builds[5].name, 'project-test2')
        self.assertTrue(self.job_has_changes(self.builds[5], A, B, C))

        all_builds = self.builds[:]
        self.release(all_builds[2])
        self.release(all_builds[3])
        self.waitUntilSettled()
        self.assertFalse(A.is_merged)
        self.assertFalse(B.is_merged)
        self.assertFalse(C.is_merged)

        self.release(all_builds[0])
        self.release(all_builds[1])
        self.waitUntilSettled()
        self.assertTrue(A.is_merged)
        self.assertTrue(B.is_merged)
        self.assertFalse(C.is_merged)

        self.worker.hold_jobs_in_build = False
        self.worker.release()
        self.waitUntilSettled()
        self.assertEqual(len(self.builds), 0)
        self.assertEqual(len(self.history), 9)
        self.assertTrue(C.is_merged)

        self.assertNotIn('merge', A.labels)
        self.assertNotIn('merge', B.labels)
        self.assertNotIn('merge', C.labels)

    def test_failed_changes(self):
        "Test that a change behind a failed change is retested"
        self.worker.hold_jobs_in_build = True

        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        B = self.fake_github.openFakePullRequest('org/project', 'master', 'B')

        self.worker.addFailTest('project-test1', A)

        self.fake_github.emitEvent(A.addLabel('merge'))
        self.fake_github.emitEvent(B.addLabel('merge'))
        self.waitUntilSettled()

        self.worker.release('.*-merge')
        self.waitUntilSettled()

        self.worker.hold_jobs_in_build = False
        self.worker.release()

        self.waitUntilSettled()
        # It's certain that the merge job for change 2 will run, but
        # the test1 and test2 jobs may or may not run.
        self.assertTrue(len(self.history) > 6)
        self.assertFalse(A.is_merged)
        self.assertTrue(B.is_merged)
        self.assertNotIn('merge', A.labels)
        self.assertNotIn('merge', B.labels)

    def test_failed_change_at_head(self):
        "Test that if a change at the head fails, jobs behind it are canceled"

        self.worker.hold_jobs_in_build = True
        A = self.fake_github.openFakePullRequest('org/project', 'master', 'A')
        B = self.fake_github.openFakePullRequest('org/project', 'master', 'B')
        C = self.fake_github.openFakePullRequest('org/project', 'master', 'C')

        self.worker.addFailTest('project-test1', A)

        self.fake_github.emitEvent(A.addLabel('merge'))
        self.fake_github.emitEvent(B.addLabel('merge'))
        self.fake_github.emitEvent(C.addLabel('merge'))

        self.waitUntilSettled()

        self.assertEqual(len(self.builds), 1)
        self.assertEqual(self.builds[0].name, 'project-merge')
        self.assertTrue(self.job_has_changes(self.builds[0], A))

        self.worker.release('.*-merge')
        self.waitUntilSettled()
        self.worker.release('.*-merge')
        self.waitUntilSettled()
        self.worker.release('.*-merge')
        self.waitUntilSettled()

        self.assertEqual(len(self.builds), 6)
        self.assertEqual(self.builds[0].name, 'project-test1')
        self.assertEqual(self.builds[1].name, 'project-test2')
        self.assertEqual(self.builds[2].name, 'project-test1')
        self.assertEqual(self.builds[3].name, 'project-test2')
        self.assertEqual(self.builds[4].name, 'project-test1')
        self.assertEqual(self.builds[5].name, 'project-test2')

        self.release(self.builds[0])
        self.waitUntilSettled()

        # project-test2, project-merge for B
        self.assertEqual(len(self.builds), 2)
        self.assertEqual(self.countJobResults(self.history, 'ABORTED'), 4)

        self.worker.hold_jobs_in_build = False
        self.worker.release()
        self.waitUntilSettled()

        self.assertEqual(len(self.builds), 0)
        self.assertEqual(len(self.history), 15)
        self.assertFalse(A.is_merged)
        self.assertTrue(B.is_merged)
        self.assertTrue(C.is_merged)
        self.assertNotIn('merge', A.labels)
        self.assertNotIn('merge', B.labels)
        self.assertNotIn('merge', C.labels)
