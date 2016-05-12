import functools
import os

from zope.interface.verify import verifyObject
from zope.interface import implementer

from twisted.python import usage, modules
from twisted.plugin import IPlugin, getPlugins
from twisted.web import server
from twisted.application.service import IServiceMaker
from twisted.application import strports

from ._core import verifyHMAC, IWebhook, WebhookDispatchingResource


def makeWebhookDispatchingResource(secretKey, hooks):
    """
    Creates a L{txghbot._core.WebhookDispatchingResource} instance.

    @type secretKey: C{unicode}/C{str}
    @param secretKey: The secret key that Github HMACs each request body with.
        See the Github docs.

    @type hooks: Sequence of L{txghbot._core.IWebhook}
    @type hooks: The hooks to possibly run upon receiving an event.

    @rtype: L{txghbot._core.WebhookDispatchingResource}
    @return: Returns the event dispatch resource.
    """

    for hook in hooks:
        verifyObject(IWebhook, hook)

    return WebhookDispatchingResource(
        signatureVerifier=functools.partial(verifyHMAC,
                                            key=secretKey),
        hooks=hooks)


class Options(usage.Options):
    optParameters = [["port", "p", "tcp:8080",
                      "strports description of the port to "
                      "start the server on."],
                     ["logfile", "l", None,
                      "Path to web CLF (Combined Log Format) log file."],
                     ["secret", "s", None,
                      "Path to the secret key"
                      " - should be a single line file."],
                     ["plugins", "e", None,
                      "Path to additional IWebhook plugins"]]


def readSecret(path):
    if not path or not os.path.exists(path):
        raise RuntimeError("must provide secret file path")
    with open(path, 'r') as f:
        return f.read().rstrip('\r').rstrip('\n')


@implementer(IServiceMaker,
             IPlugin)
class WebhookDispatchServiceMaker(object):
    tapname = "txghbot"
    description = "A Github Webhook event dispatacher"
    options = Options

    def makeService(self, config):
        """
        Construct a TCPServer from a factory defined in myproject.
        """
        if config['plugins']:
            pluginLocation = modules.getModule(config['plugins']).load()
            hooks = list(getPlugins(IWebhook, pluginLocation))
        else:
            hooks = list(getPlugins(IWebhook))

        root = makeWebhookDispatchingResource(readSecret(config['secret']),
                                              hooks)
        if config['logfile']:
            site = server.Site(root, logPath=config['logfile'])
        else:
            site = server.Site(root)

        return strports.service(config['port'], site)
