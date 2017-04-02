# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
The C{twistd} support code.  Don't call this directly!
"""

import functools

import os

from zope.interface.verify import verifyObject
from zope.interface import implementer

import six

from twisted.python import modules, usage
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
                     ["secret-from-path", "s", None,
                      "Path to the secret key"
                      " - should be a single line file.  You must provide"
                      " this or --secret-from-env"],
                     ["secret-from-env", "e", None,
                      "An environment variable under which the secret key is"
                      " stored.  You must provide this or --secret-from-path"],
                     ["plugins", None, None,
                      "Path to additional IWebhook plugins"]]


    def __init__(self, _os=os):
        super(Options, self).__init__()
        self._os = _os


    def retrieveSecretFromPath(self, path):
        """
        Retrieve the secret key stored at L{path}.

        @type path: L{str}
        @param path: the path to the secret key

        @return: the secret
        @rtype: L{bytes}
        """
        with open(path, 'rb') as f:
            secret = f.read().rstrip(b'\r\n')

        if not secret:
            raise usage.UsageError("{} is empty".format(path))

        return secret


    def retrieveSecretFromEnvironment(self, variable):
        """
        Retrieve the secret key from the provided environment
        variable.

        @type variable: L{str}
        @param variable: the name of the environment variable.

        @return: the secret
        @rtype: L{bytes}
        """
        if isinstance(variable, six.text_type):
            variable = variable.encode('ascii')
        try:
            return getattr(self._os, 'environb', self._os.environ)[variable]
        except KeyError:
            raise usage.UsageError(
                "specified environment variable does not exist")


    def postOptions(self):
        """
        Check and prepare the parameters for use.
        """
        path = self["secret-from-path"]
        variable = self["secret-from-env"]
        if path and variable:
            raise usage.UsageError(
                "Cannot provide both --secret-from-path and --secret-from-env")
        elif path:
            self["secret"] = self.retrieveSecretFromPath(path)
        elif variable:
            self["secret"] = self.retrieveSecretFromEnvironment(variable)
        else:
            raise usage.UsageError(
                "Must provide --secret-from-path or --secret-from-env")



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
            _getPlugins=getPlugins,
            _makeWebhookDispatchingResource=makeWebhookDispatchingResource,
            _strportsService=strports.service,
            _getModule=modules.getModule,
            _Site=server.Site):
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
        secret = config['secret']
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
