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
    """Raised when L{WebhookDispatchingResource}"""


class WebhookDispatchingResource(Resource):
    JSON_ENCODING = 'utf-8'

    EVENT_HEADER = b'X-Github-Event'
    REQUEST_ID_HEADER = b'X-Github-Delivery'

    def __init__(self, signatureVerifier, hooks):
        self.signatureVerifier = signatureVerifier
        self.hooks = hooks

    def _extractHeader(self, headers, name):
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
        try:
            decoded = content.decode(self.JSON_ENCODING)
            return json.loads(decoded)
        except (UnicodeDecodeError, ValueError):
            log.failure("Could not deserialize payload body"
                        " {content!r}", content=content)
            raise InvalidData(content)

    def _matchHook(self, hook, eventName, eventData):
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
