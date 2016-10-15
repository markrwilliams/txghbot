# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
The C{twistd} support code.  Don't call this directly!
"""

import functools

from zope.interface.verify import verifyObject
from zope.interface import implementer

from twisted.python import usage, modules
from twisted.plugin import IPlugin, getPlugins
from twisted.web import server
from twisted.application.service import IServiceMaker
from twisted.application import strports

from ._core import verifyHMAC, IWebhook, WebhookDispatchingResource


def makeWebhookDispatchingResource(secretKey, hooks,
                                   _verifyHMAC=verifyHMAC):
    """
    Creates a L{txghbot._core.WebhookDispatchingResource} instance.

    @type secretKey: L{bytes}
    @param secretKey: The secret key that Github HMACs each request
        body with.  See the Github docs.

    @param hooks: Sequence of L{txghbot._core.IWebhook}
    @type hooks: The hooks to possibly run upon receiving an event.

    @rtype: L{txghbot._core.WebhookDispatchingResource}
    @return: Returns the event dispatch resource.
    """

    for hook in hooks:
        verifyObject(IWebhook, hook)

    return WebhookDispatchingResource(
        signatureVerifier=functools.partial(_verifyHMAC,
                                            key=secretKey),
        hooks=hooks)



class Options(usage.Options):
    """
    C{twistd} plugin command line options.
    """

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
    """
    Retrieve the secret key stored at L{path}.

    @type path: L{str}
    @param path: the path to the secret key

    @return: the secret
    @rtype: L{bytes}

    @raise: L{RuntimeError} if the secret file is empty.
    """
    with open(path, 'rb') as f:
        secret = f.read().rstrip(b'\r\n')

    if not secret:
        raise RuntimeError("Secret file {} was empty!".format(path))

    return secret



@implementer(IServiceMaker,
             IPlugin)
class WebhookDispatchServiceMaker(object):
    """
    Make the web hook dispatching
    L{twisted.application.service.Service}
    """
    tapname = "txghbot"
    description = "A Github Webhook event dispatacher"
    options = Options

    def __init__(
            self,
            _readSecret=readSecret,
            _getPlugins=getPlugins,
            _makeWebhookDispatchingResource=makeWebhookDispatchingResource,
            _strportsService=strports.service,
            _getModule=modules.getModule,
            _Site=server.Site):
        self.readSecret = _readSecret
        self.getModule = _getModule
        self.getPlugins = _getPlugins
        self.makeWebhookDispatchingResource = _makeWebhookDispatchingResource
        self.strportsService = _strportsService
        self.Site = _Site


    def makeService(self, config):
        """
        Create the service.

        @param config: the command line configuration for this
            service.
        @type config: a L{dict}-like object

        @return: an L{twisted.application.service.IService}-providing
            object.
        @rtype: L{twisted.application.service.IService}
        """
        secretPath = config['secret']
        if not secretPath:
            raise RuntimeError("--secret is required")

        secret = self.readSecret(secretPath)

        if config['plugins']:
            pluginLocation = self.getModule(config['plugins']).load()
            hooks = list(self.getPlugins(IWebhook, pluginLocation))
        else:
            hooks = list(self.getPlugins(IWebhook))

        root = self.makeWebhookDispatchingResource(secret, hooks)
        if config['logfile']:
            site = self.Site(root, logPath=config['logfile'])
        else:
            site = self.Site(root)

        return self.strportsService(config['port'], site)
