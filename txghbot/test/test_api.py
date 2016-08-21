from txghbot._api import (makeWebhookDispatchingResource, readSecret,
                          WebhookDispatchServiceMaker)
from txghbot._core import IWebhook
from twisted.python.filepath import FilePath
from twisted.trial import unittest
from zope.interface import implementer
from zope.interface.exceptions import DoesNotImplement, BrokenImplementation


class MakeWebhookDispatchingResourceTestCase(unittest.SynchronousTestCase):
    """
    Tests for L{txghbot._api.makeWebhookDispatchingResource}
    """

    def test_hooksDoNotProvideIWebhook(self):
        """
        L{txghbot._api.makeWebhookDispatchingResource} raises
        L{zope.interface.DoesNotImplement} if any hook does not
        provide L{txghbot._core.IWebhook}.
        """
        self.assertRaises(DoesNotImplement,
                          makeWebhookDispatchingResource,
                          secretKey="ignored",
                          hooks=["not a webhook"])

    def test_hooksDoesNotImplementIWebhook(self):
        """
        L{txghbot._api.makeWebhookDispatchingResource} raises
        L{zope.interface.BrokenImplementation} if any hook does not
        provide all of L{txghbot._core.IWebhook}'s interface.
        """

        @implementer(IWebhook)
        class BrokenWebhook(object):
            """
            Doesn't actually implement L{txghbot._core.IWebhook}
            """

        self.assertRaises(BrokenImplementation,
                          makeWebhookDispatchingResource,
                          secretKey="ignored",
                          hooks=[BrokenWebhook()])

    def test_createsWebhookDispatchingResource(self):
        """
        L{txghbot._api.makeWebhookDispatchingResource} returns a
        L{txghbot._core.WebhookDispatchingResource} with the provided
        C{hooks} and a signature verifier that uses the provided
        C{secretKey}
        """

        @implementer(IWebhook)
        class SimpleWebhook(object):
            """
            A minimal L{txghbot._core.IWebhook} implementation.
            """
            def match(self, eventName, eventData):
                """
                A meaningless match implementation.
                """

            def run(self, eventName, eventData, requestID):
                """
                A meaningless run implementation.
                """

        def fakeHMAC(uncurried, key):
            return uncurried, key

        secret = "secret"
        hooks = [SimpleWebhook()]

        rsrc = makeWebhookDispatchingResource(secret, hooks,
                                              _verifyHMAC=fakeHMAC)

        self.assertEqual(rsrc.signatureVerifier("something"),
                         ("something", secret))
        self.assertEqual(rsrc.hooks, hooks)


class ReadSecretTests(unittest.TestCase):
    """
    Tests for L{txghbot._api.readSecret}
    """
    def setUp(self):
        self.secretFilePath = self.mktemp()
        self.secretFile = FilePath(self.secretFilePath)
        self.addCleanup(self.secretFile.remove)

    def test_emptySecret(self):
        """
        An empty secret file raises a L{RuntimeError}
        """
        self.secretFile.touch()
        exc = self.assertRaises(RuntimeError, readSecret, self.secretFilePath)
        self.assertIn("empty", str(exc).lower())

    def test_secretRetrieved(self):
        """
        A newline-stripped secret is returned.  Internal whitespace is
        preserved.
        """
        with self.secretFile.open('w') as f:
            f.write(" this is a secret \r\n")

        self.assertEqual(readSecret(self.secretFilePath),
                         " this is a secret ")


class FakeModuleWrapper(object):

    def __init__(self, loadReturns):
        self._loadReturns = loadReturns

    def load(self):
        return self._loadReturns


class WebhookDispatchServiceMakerTests(unittest.TestCase):
    """
    Tests for L{txghbot._api.WebhookDispatchServiceMaker}
    """

    def setUp(self):
        self.config = {
            "secret": "secret path",
            "plugins": "plugin path",
            "logfile": "logfile path",
            "port": "strport"}
        self.readSecretCalls = []
        self.readSecretReturns = None

        self.getModuleCalls = []
        self.fakeModule = 'fake module'
        self.fakeModuleWrapper = FakeModuleWrapper(self.fakeModule)
        self.getModuleReturns = self.fakeModuleWrapper

        self.getPluginsCalls = []
        self.getPluginsReturns = ()

        self.makeWebhookDispatchingResourceCalls = []
        self.makeWebhookDispatchingResourceReturns = None

        self.siteCalls = []
        self.siteReturns = None

        self.strportsServiceCalls = []
        self.strportsServiceReturns = None

        self.service = WebhookDispatchServiceMaker(
            _readSecret=self.fakeReadSecret,
            _getModule=self.fakeGetModule,
            _getPlugins=self.fakeGetPlugins,
            _makeWebhookDispatchingResource=self.fakeMakeWebhookDR,
            _Site=self.fakeSite,
            _strportsService=self.fakeStrportsService,
        )

    def fakeReadSecret(self, path):
        self.readSecretCalls.append(path)
        return self.readSecretReturns

    def fakeGetModule(self, fqpn):
        self.getModuleCalls.append(fqpn)
        return self.getModuleReturns

    def fakeGetPlugins(self, interface, path=None):
        self.getPluginsCalls.append((interface, path))
        return self.getPluginsReturns

    def fakeMakeWebhookDR(self, secret, hook):
        self.makeWebhookDispatchingResourceCalls.append((secret, hook))
        return self.makeWebhookDispatchingResourceReturns

    def fakeSite(self, root, logPath=None):
        self.siteCalls.append((root, logPath))
        return self.siteReturns

    def fakeStrportsService(self, port, site):
        self.strportsServiceCalls.append((port, site))
        return self.strportsServiceReturns

    def test_missingSecret(self):
        """
        "A L{RuntimeError} is raised when the secret parameter is not
        provided."
        """
        self.config['secret'] = None
        exc = self.assertRaises(RuntimeError,
                                self.service.makeService, self.config)
        self.assertIn("secret", str(exc))

    def test_secretRead(self):
        """
        The secret passed to
        L{txghbot._api.makeWebhookDispatchingResource} is retrieved
        from the path provided in the C{secret} configuration
        parameter.
        """
        self.readSecretReturns = "a secret"

        self.service.makeService(self.config)

        self.assertEqual(self.readSecretCalls, [self.config["secret"]])
        self.assertEqual(len(self.makeWebhookDispatchingResourceCalls), 1)
        [(secret, _)] = self.makeWebhookDispatchingResourceCalls
        self.assertIs(secret, self.readSecretReturns)

    def test_pluginPathProvided(self):
        """
        The plugin path provided via the C{plugins} configuration
        parameter is searched for plugins.
        """
        self.assertIsNot(self.config['plugins'], None)
        self.getModuleReturns = self.fakeModuleWrapper

        self.service.makeService(self.config)

        self.assertEqual(self.getModuleCalls, [(self.config['plugins'])])
        self.assertEqual(self.getPluginsCalls, [(IWebhook, self.fakeModule)])

    def test_defaultPluginPath(self):
        """
        The plugin path configuration parameter is not required
        """
        self.config['plugins'] = None
        self.getModuleReturns = self.fakeModule

        self.service.makeService(self.config)

        self.assertEqual(self.getModuleCalls, [])
        self.assertEqual(self.getPluginsCalls, [(IWebhook, None)])

    def test_pluginsPassedAsHooks(self):
        """
        Loaded plugins are passed as hooks to
        L{txghbot._api.makeWebhookDispatchingResource}
        """
        self.getPluginsReturns = ["fake webhook"]

        self.service.makeService(self.config)

        [(_, hooks)] = self.makeWebhookDispatchingResourceCalls
        self.assertEqual(hooks, self.getPluginsReturns)

    def test_logfileProvided(self):
        """
        The C{logfile} configuration parameter is honored.
        """
        self.service.makeService(self.config)
        self.assertEqual(len(self.siteCalls), 1)
        [(_, logPath)] = self.siteCalls
        self.assertEqual(logPath, self.config['logfile'])

    def test_defaultLogfile(self):
        """
        The C{logfile} configuration parameter is not required.
        """
        self.config['logfile'] = None
        self.service.makeService(self.config)
        [(_, logPath)] = self.siteCalls
        self.assertIsNone(logPath)

    def test_strportsServiceCreated(self):
        """
        L{twisted.application.strports.service} parses the port
        specification in C{port}.
        """
        self.siteReturns = 'site'
        self.strportsServiceReturns = 'strports service'

        service = self.service.makeService(self.config)

        self.assertIs(service, self.strportsServiceReturns)
        self.assertEqual(self.strportsServiceCalls,
                         [(self.config['port'], self.siteReturns)])
