# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
The core functionality of the webhook server.  Don't use this
directly!
"""

import json
import hmac
import hashlib
from twisted.internet import defer
from twisted.web.server import NOT_DONE_YET
from twisted.web.resource import Resource
from twisted.logger import Logger
from zope.interface import Interface

log = Logger()


GITHUB_SIGNATURE_HEADER = b'X-Hub-Signature'



def verifyHMAC(headers, content, key):
    """
    Verify the signature of a request.

    @param headers: the headers that contain the request under the
        expected header name.
    @type headers: L{twisted.web.http_headers.Headers}

    @param content: the signed content
    @type content: L{bytes}

    @param key: the key that signed this request.
    @type key: L{bytes}

    @return: L{True} if the signature could be verified and L{False}
        if not.
    @rtype: L{bool}
    """
    algorithmSignaturePairs = headers.getRawHeaders(GITHUB_SIGNATURE_HEADER)

    if algorithmSignaturePairs is None or len(algorithmSignaturePairs) != 1:
        log.debug("Not exactly one signature in header: "
                  " {headers}",
                  headers=headers)
        return False

    (algorithmAndSignature,) = algorithmSignaturePairs

    algorithm, _, signature = algorithmAndSignature.partition(b'=')

    if algorithm.lower() != b'sha1':
        log.debug("Signature algorithm not SHA1: "
                  " {algorithm}"
                  " {headers}",
                  algorithm=algorithm,
                  headers=headers)
        return False

    calculatedSignature = hmac.new(key, content, hashlib.sha1).hexdigest()

    return hmac.compare_digest(signature, calculatedSignature)



class IWebhook(Interface):
    """
    A Github webhook.
    """

    def match(eventName, eventData):
        """
        Decide if this webhook run for this event.

        @type eventName: C{unicode}/C{str}
        @param eventName: the name of the received Github event.

        @type eventData: C{dict}
        @param eventData: the deserialized event payload.

        @rtype: C{bool}
        @return: True if this hook should run on this event; False otherwise.
        """

    def run(eventName, eventData, requestID):
        """
        Run the webhook

        @type eventName: C{unicode}/C{str}
        @param eventName: the name of the received Github event.

        @type eventData: C{dict}
        @param eventData: the deserialized event payload.

        @type requestID: C{unicode}/C{str}
        @param requestID: the identifier Github provided for this event.
           Useful for logging.

        @rtype: L{Deferred} or some immediate value.
        @return: If a L{Deferred} is return, it must fire when this hook has
            finished running. Failures will be logged by
            L{WebhookDispatchingResource}.  All other results will be ignored.
        """



class InvalidData(Exception):
    """
    Raised when L{WebhookDispatchingResource} can't interpret some
    aspect of a request.
    """



class WebhookDispatchingResource(Resource):
    """
    A L{Resource} subclass that authenticates Github web hook requests
    and dispatches to L{IWebhook} implementing plugins.

    @param signatureVerifier: a callable that accepts two arguments: a
        L{twisted.web.http_headers.Headers} instance and the L{bytes}
        body of the corresponding request, and returns L{True} if the
        request's signature passes verification and L{False} if not.
    @type signatureVerifier: L{callable}

    @param hooks: An iterable of web hooks to match and possibly run
        against a request.
    @type hooks: an iterable of L{IWebhook}-providing objects.
    """
    isLeaf = True
    JSON_ENCODING = 'utf-8'

    EVENT_HEADER = b'X-Github-Event'
    REQUEST_ID_HEADER = b'X-Github-Delivery'

    def __init__(self, signatureVerifier, hooks):
        self.signatureVerifier = signatureVerifier
        self.hooks = hooks


    def _extractHeader(self, headers, name):
        """
        Extract the first value for C{name} in C{headers} or raise
        L{InvalidData}.

        @param headers: The headers from which to extract the desired
            value.
        @type headers: L{twisted.web.http_headers.Headers}

        @param name: The name of the header to extract.
        @type name: L{bytes}

        @return: The first header value under C{name}
        @rtype: L{str}, decoded as ASCII.

        @raises: L{InvalidData} if the header is missing, or if its
            first value cannot be decoded as ASCII.
        """
        headerValues = headers.getRawHeaders(name)
        if not headerValues:
            raise InvalidData(name)
        try:
            return headerValues[0].decode('ascii')
        except UnicodeDecodeError:
            log.failure("Non-ASCII in header {name}: {value!r}",
                        name=name, value=headerValues)
            raise InvalidData(name)


    def _deserializeContent(self, content):
        """
        Deserialize the JSON stored in C{content}.

        @param content: The serialized JSON to deserialize
        @type content: L{bytes}

        @return: the deserialized JSON object.
        @rtype: L{dict}

        @raises: L{InvalidData} if a JSON object cannot be decoded.
        """
        try:
            decoded = content.decode(self.JSON_ENCODING)
            return json.loads(decoded)
        except (UnicodeDecodeError, ValueError):
            log.failure("Could not deserialize payload body"
                        " {content!r}", content=content)
            raise InvalidData(content)


    def _matchHook(self, hook, eventName, eventData):
        """
        Determine if C{hook} matches C{eventName} and C{eventData}.

        @param hook: the web hook to try to match against C{eventName}
            and C{eventData}
        @type hook: an L{IWebhook}-providing object

        @param eventName: the name of the Github webhook event
        @type eventName: L{str}

        @param eventData: the event data for this Github webhook
            event.
        @type eventData: L{dict}

        @return: L{True} if the hook matched and L{False} if not.
        """
        try:
            return hook.match(eventName, eventData)
        except Exception:
            log.failure("Hook {hook} failed during match on"
                        " {eventName} {eventData}",
                        hook=hook,
                        eventName=eventName,
                        eventData=eventData)
            return False


    def _processHookResults(self, results, hooks, request, requestID):
        """
        Traverse C{results} and set the response code to 400 if any
        hooks failed to run.

        Intended to be run as added as a callback to a L{DeferredList}
        of hook results.

        @param results: The results of running each hook in C{hooks}
            against C{request}
        @type results: A list of (index, (outcome, value)) L{tuple}s.

        @param hooks: an iterable of L{IWebhook}-providing objects that
            were run against C{request}
        @type hooks: iterable of L{IWebhook}-providing objects.

        @param request: the Github web hook request.
        @type request: L{twisted.web.server.Request}

        @param requestID: the Github ID for C{request}
        @type requestID: L{str}
        """
        request.setResponseCode(200)

        for idx, (outcome, value) in enumerate(results):
            if not outcome:
                log.failure("Failed to run hook {hook} on request {requestID}",
                            failure=value,
                            hook=hooks[idx],
                            requestID=requestID)
                request.setResponseCode(400)

        request.finish()


    def render_POST(self, request):
        """
        Verify that C{request} came from Github, then run any matching
        L{IWebhook}s from C{self.hooks}

        @param request: The request to verify and match hooks against.
        @type request: L{twisted.web.server.Request}

        @return: L{NOT_DONE_YET}
        @rtype: L{NOT_DONE_YET}
        """
        content = request.content.read()
        if not self.signatureVerifier(request.requestHeaders, content):
            request.setResponseCode(403)
            return b''

        try:
            eventName = self._extractHeader(request.requestHeaders,
                                            self.EVENT_HEADER)
            requestID = self._extractHeader(request.requestHeaders,
                                            self.REQUEST_ID_HEADER)
            eventData = self._deserializeContent(content)
        except InvalidData:
            request.setResponseCode(400)
            return b''

        hooksToRun = [hook for hook in self.hooks
                      if self._matchHook(hook, eventName, eventData)]

        pending = defer.DeferredList(
            [defer.maybeDeferred(hook.run, eventName, eventData, requestID)
             for hook in hooksToRun],
            consumeErrors=True)

        pending.addCallback(self._processHookResults,
                            hooksToRun,
                            request,
                            requestID)

        return NOT_DONE_YET
