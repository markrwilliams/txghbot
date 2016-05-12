import functools
import hmac
import hashlib
import io

import six

from twisted.trial import unittest
from twisted.internet import defer
from twisted.web.server import NOT_DONE_YET
from twisted.web.http_headers import Headers
from twisted.web.test.requesthelper import DummyRequest
from twisted.python.failure import Failure

from zope.interface import implementer
from zope.interface.verify import verifyObject

import txghbot._core as C


class VerifyHMACTestCase(unittest.SynchronousTestCase):

    def _makeSignatureHeaders(self, *values):
        return Headers({C.GITHUB_SIGNATURE_HEADER: list(values)})

    def assertHeadersFail(self, headers):
        self.assertFalse(C.verifyHMAC(headers=headers,
                                      content=self.content,
                                      key=self.key))

    def setUp(self):
        self.content = b'some content'
        self.key = b'key'
        self.hexdigest = hmac.new(self.key,
                                  self.content,
                                  hashlib.sha1).hexdigest()

    def test_missingSignatureFails(self):
        """
        Headers that lack the HMAC header fail to verify.
        """
        self.assertHeadersFail(Headers({}))

    def test_tooManySignaturesFail(self):
        """
        Headers with more than one value for HMAC header fail to
        verify.
        """
        self.assertHeadersFail(self._makeSignatureHeaders(b'too', b'many'))

    def test_malformedSignatureFails(self):
        """
        Headers containing an improperly formatted HMAC fail to verify.
        """
        self.assertHeadersFail(self._makeSignatureHeaders(b''))

    def test_notSHA1Fails(self):
        """
        Headers containing a non-SHA1 HMAC fail to verify.
        """
        hexdigest = hmac.new(self.key,
                             self.content,
                             hashlib.md5).hexdigest()
        md5Signature = b'md5=' + hexdigest
        self.assertHeadersFail(self._makeSignatureHeaders(md5Signature))

    def test_incorrectSignatureFails(self):
        """
        Headers with a SHA1 HMAC that is not derived from request's
        content and the secret key fail to verify.
        """
        badSHA1 = hmac.new(self.key + self.key, self.content,
                           hashlib.sha1).hexdigest()
        self.assertNotEqual(badSHA1, self.hexdigest)

        badSignature = b'sha1=' + badSHA1
        self.assertHeadersFail(self._makeSignatureHeaders(badSignature))

    def test_correctSignatureSucceeds(self):
        """
        Headers with a SHA1 HMAC derived from the request's content and
        the secret key verify successfully.
        """

        signature = b'sha1=' + self.hexdigest

        headers = self._makeSignatureHeaders(signature)
        self.assertTrue(C.verifyHMAC(headers=headers,
                                     content=self.content,
                                     key=self.key))


def _isException(thing):
    if isinstance(thing, Exception):
        return True
    if isinstance(thing, type) and issubclass(thing, Exception):
        return True
    return False


class RecordsFakeWebhookActions(object):

    def __init__(self, matchResult=False, runResult=None):
        self.matchCalls = []
        self.matchResult = matchResult
        self.runCalls = []
        self.runResult = runResult

    def returnFromMatch(self):
        if _isException(self.matchResult):
            raise self.matchResult
        return self.matchResult

    def returnFromRun(self):
        if _isException(self.runResult):
            raise self.runResult
        return self.runResult


@implementer(C.IWebhook)
class FakeWebhook(object):

    def __init__(self, recorder):
        self._recorder = recorder

    def match(self, eventName, eventData):
        self._recorder.matchCalls.append((eventName, eventData))
        return self._recorder.returnFromMatch()

    def run(self, eventName, eventData, requestID):
        self._recorder.runCalls.append((eventName, eventData, requestID))
        return self._recorder.returnFromRun()


class DummyRequestWithContent(DummyRequest):
    """
    A L{twisted.web.test.requesthelper.DummyRequest} with a content attribute.
    """

    def __init__(self, postpath, session=None, content=None):
        DummyRequest.__init__(self, postpath, session)
        self.content = io.BytesIO() if content is None else content


class WebhookDispatchingResourceTestCase(unittest.TestCase):

    def fakeVerifier(self, signature, headers):
        self.requestSignatures.append((signature, headers))
        return self.verifyResult

    def setUp(self):
        self.requestSignatures = []
        self.verifyResult = True

        self.recorder = RecordsFakeWebhookActions()
        self.hook = FakeWebhook(self.recorder)
        verifyObject(C.IWebhook, self.hook)

        self.request = DummyRequestWithContent([b'ignoredPrepath'])
        self.eventName = b'an event'
        requestHeaders = self.request.requestHeaders
        requestHeaders.setRawHeaders(C.WebhookDispatchingResource.EVENT_HEADER,
                                     [self.eventName])
        self.requestID = b'1234'
        requestHeaders.setRawHeaders(
            C.WebhookDispatchingResource.REQUEST_ID_HEADER,
            [self.requestID])

        self.resource = C.WebhookDispatchingResource(
            signatureVerifier=self.fakeVerifier, hooks=[self.hook])

    def test__extractHeaderFailsWithMissingHeader(self):
        """
        _extractHeader raises L{txghbot.InvalidData} when the headers do
        not contain the requested header.
        """
        empty = Headers({})
        with self.assertRaises(C.InvalidData):
            self.resource._extractHeader(empty, b'x-some-header')

    def test__extractHeaderFailsWithNonASCIIValue(self):
        """
        _extractHeader raises L{txghbot.InvalidData} and logs the decoding
        error when the requested header's first value is not ASCII.
        """
        badValues = (Headers({b'x-some-header': [b'\xff']}),
                     Headers({b'x-some-header': [b'\xff', b'ignored']}))

        for badValue in badValues:
            with self.assertRaises(C.InvalidData):
                self.resource._extractHeader(badValue, b'x-some-header')
            exceptions = self.flushLoggedErrors(UnicodeDecodeError)
            self.assertEqual(len(exceptions), 1)

    def test__extractHeaderSucceedsWithFirstASCIIValue(self):
        """
        _extractHeader returns a C{unicode}/C{str} representing the first
        value for the requested header.
        """
        expected = u"hi there"
        goodValues = (Headers({b'x-some-header': [b'hi there']}),
                      Headers({b'x-some-header': [b'hi there', b'\xff']}))

        for goodValue in goodValues:
            value = self.resource._extractHeader(goodValue, b'x-some-header')
            self.assertIsInstance(value, six.text_type)
            self.assertEqual(value, expected)

    def test__deserializeContentFailsWithNonUTF8Payload(self):
        """
        _deserializeContent raises L{txghbot.InvalidData} and logs the
        decoding error when attempting to decode a non-UTF8 encoded
        payload.
        """
        with self.assertRaises(C.InvalidData):
            self.resource._deserializeContent(b'\xc3\x28')

        exceptions = self.flushLoggedErrors(UnicodeDecodeError)
        self.assertEqual(len(exceptions), 1)

    def test__deserializeContentFailsWithInvalidJSON(self):
        """
        _deserializeContent raises L{txghbot.InvalidData} and logs the
        underlying deserialization exception when attempting to
        deserialize invalid JSON.
        """
        with self.assertRaises(C.InvalidData):
            self.resource._deserializeContent(b'{"a": ')

        exceptions = self.flushLoggedErrors(ValueError)
        self.assertEqual(len(exceptions), 1)

    def test__deserializeContentSucceedsWithUTF8_JSON(self):
        """
        _deserializeContent successfully decodes and deserializes. UTF-8
        encoded JSON.
        """
        expected = {"this is ok": {'for every': [1]}}
        actual = self.resource._deserializeContent(
            b'{"this is ok": {"for every": [1]}}')
        self.assertEqual(expected, actual)

    def test__matchHookReturnsFalseOnException(self):
        """
        _matchHook returns False if the L{IWebhook}'s match method raises
        an Exception.
        """
        failingWebhookRecorder = RecordsFakeWebhookActions(
            matchResult=Exception)
        failingWebhook = FakeWebhook(failingWebhookRecorder)

        self.assertFalse(self.resource._matchHook(failingWebhook,
                                                  "Ignored", "Ignored"))

        self.assertEqual(failingWebhookRecorder.matchCalls,
                         [("Ignored", "Ignored")])

        exceptions = self.flushLoggedErrors(Exception)
        self.assertEqual(len(exceptions), 1)

    def test__matchHookReturnsHookResult(self):
        """
        _matchHook returns whatever the L{IWebhook}'s match method returns.
        """
        nonMatchingRecorder = RecordsFakeWebhookActions(matchResult=False)
        matchingRecorder = RecordsFakeWebhookActions(matchResult=True)

        webhook = FakeWebhook(nonMatchingRecorder)

        self.assertFalse(self.resource._matchHook(webhook,
                                                  "Ignored1", "Ignored1"))
        self.assertEqual(nonMatchingRecorder.matchCalls,
                         [("Ignored1", "Ignored1")])

        webhook._recorder = matchingRecorder

        self.assertTrue(self.resource._matchHook(webhook,
                                                 "Ignored2", "Ignored2"))
        self.assertEqual(matchingRecorder.matchCalls,
                         [("Ignored2", "Ignored2")])

    def test__processHookResultsFailsWithBadRequest(self):
        """
        _processHookResults sets a status code of 400, logs the failure,
        and finishes the request if one or more of the hooks has
        failed.
        """
        results = [(True, "A result"),
                   (False, Failure(Exception(":("))),
                   (False, Failure(Exception(":'(")))]

        hooks = ['ignored', self.hook, self.hook]

        self.resource._processHookResults(results, hooks,
                                          self.request,
                                          self.requestID)

        self.assertEqual(self.request.responseCode, 400)
        self.assertGreater(self.request.finished, 0)

        exceptions = self.flushLoggedErrors(Exception)
        self.assertEqual(len(exceptions), 2)

    def test__processHookResultsSucceedsWithOK(self):
        """
        _processHookResults sets a status code of 200 and finishes the request
        if all hooks have run without raising an exception.
        """
        results = [(True, "A result"),
                   (True, "Another result")]
        hooks = ['ignored', self.hook]

        requestCompleted = self.request.notifyFinish()

        self.resource._processHookResults(results, hooks,
                                          self.request,
                                          self.requestID)

        self.assertEqual(self.request.responseCode, 200)
        self.successResultOf(requestCompleted)

    def test_render_POSTFailsWithPermissionDeniedOnInvalidHMAC(self):
        """
        An invalid signature results in a 403 and no hooks running.
        """

        self.verifyResult = False

        self.resource.render_POST(self.request)

        self.assertEqual(self.request.responseCode, 403)
        self.assertFalse(self.recorder.matchCalls)
        self.assertFalse(self.recorder.runCalls)

    def test_render_POSTFailsWithBadRequestOnInvalidHeaders(self):
        """
        If its headers lack the necessary metadata, the request fails with
        a 400 and no hooks are run.
        """
        def _failingExtractHeaders(headers, name):
            raise C.InvalidData(name)

        self.resource._extractHeader = _failingExtractHeaders

        self.resource.render_POST(self.request)

        self.assertEqual(self.request.responseCode, 400)
        self.assertFalse(self.recorder.matchCalls)
        self.assertFalse(self.recorder.runCalls)

    def test_render_POSTFailsWithBadRequestOnInvalidContent(self):
        """
        If its content cannot be decoded, the request fails with a 400 and
        no hooks are run.
        """
        def _failingDeserializeContent(content):
            raise C.InvalidData(content)

        self.resource._deserializeContent = _failingDeserializeContent

        self.resource.render_POST(self.request)

        self.assertEqual(self.request.responseCode, 400)
        self.assertFalse(self.recorder.matchCalls)
        self.assertFalse(self.recorder.runCalls)

    def test_render_POSTDoesNotRunNonMatchingHooks(self):
        """
        Webhooks that do not match the event aren't run.
        """
        def _fakeExtractHeaders(headers, name):
            return 'fake'

        def _fakeDeserializeContent(content):
            return {'fake': True}

        def _failingMatchHook(hook, eventName, eventData):
            return False

        hooksCompleted = defer.Deferred()

        def _fakeProcessHookResults(results, hooksToRun, request, requestID):
            self.assertFalse(hooksToRun)
            hooksCompleted.callback(None)

        self.resource._extractHeader = _fakeExtractHeaders
        self.resource._deserializeContent = _fakeDeserializeContent
        self.resource._matchHook = _failingMatchHook
        self.resource._processHookResults = _fakeProcessHookResults

        self.assertIs(self.resource.render_POST(self.request),
                      NOT_DONE_YET)

        self.successResultOf(hooksCompleted)


class WebhookDispatchingResourceIntegrationTestCase(
        unittest.SynchronousTestCase):

    def setUp(self):
        # establish request
        self.secretKey = b'key'
        self.eventName = u'some name'
        self.requestID = u'1234'
        self.eventData = {u"a": 1}
        self.request = DummyRequestWithContent([b'ignored'],
                                               content=io.BytesIO(b'{"a": 1}'))

        requestHeaders = self.request.requestHeaders
        requestHeaders.setRawHeaders(
            C.GITHUB_SIGNATURE_HEADER,
            [b'sha1=b559d6b83de3fd6ec2ea91e3009b46779a3dd47e'])
        requestHeaders.setRawHeaders(
            C.WebhookDispatchingResource.EVENT_HEADER,
            [self.eventName])
        requestHeaders.setRawHeaders(
            C.WebhookDispatchingResource.REQUEST_ID_HEADER,
            [self.requestID])

        # establish hooks
        self.hookCompleted = defer.Deferred()
        self.matchedRecorder = RecordsFakeWebhookActions(
            matchResult=True,
            runResult=self.hookCompleted)
        self.matchedHook = FakeWebhook(self.matchedRecorder)

        self.unmatchedRecorder = RecordsFakeWebhookActions(
            matchResult=False)
        self.unmatchedHook = FakeWebhook(self.unmatchedRecorder)

        # establish resource under test
        self.resource = C.WebhookDispatchingResource(
            signatureVerifier=functools.partial(C.verifyHMAC,
                                                key=self.secretKey),
            hooks=[self.unmatchedHook, self.matchedHook])

    def test_happyPath(self):
        """Providing a properly signed and constructed request should result
        in a 200 response after all relevant Webhooks have run.
        """
        requestFinished = self.request.notifyFinish()

        self.assertIs(self.resource.render_POST(self.request),
                      NOT_DONE_YET)

        self.assertEqual(self.unmatchedRecorder.matchCalls,
                         [(self.eventName, self.eventData)])
        self.assertEqual(self.unmatchedRecorder.runCalls,
                         [])

        self.assertEqual(self.matchedRecorder.matchCalls,
                         [(self.eventName, self.eventData)])
        self.assertEqual(self.matchedRecorder.runCalls,
                         [(self.eventName, self.eventData, self.requestID)])

        self.assertNoResult(requestFinished)

        self.hookCompleted.callback(None)

        self.successResultOf(requestFinished)
