import attr
import attr.validators
import errno
from txghbot._api import (Options, makeWebhookDispatchingResource,
                          WebhookDispatchServiceMaker)
from txghbot._core import IWebhook
from twisted.python.usage import UsageError
from twisted.python.filepath import FilePath
from twisted.trial import unittest
import six
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


@attr.s
class _FakeOSModule(object):
    """
    A fake L{os} module that exposes an environment dictionary.
    """
    environ = attr.ib()
    if not six.PY2:
        environb = attr.ib()

    @classmethod
    def fromdicts(cls, str_dict, bytes_dict):
        """
        Create an instance where L{str_dict} goes to L{environ} and,
        on Python 3, L{bytes_dict} goes to L{environb}.

        @type str_dict: A L{dict} of L{str}s
        @param str_dict: A fake process environment, as native
            strings.

        @type bytes_dict: A L{dict} of L{bytes}s
        @param bytes_dict: A fake process environment, as bytes.

        @return: The fake.
        @rtype: L{_FakeOSModule}
        """
        kwargs = {"environ": str_dict}
        if not six.PY2:
            kwargs["environb"] = bytes_dict
        return cls(**kwargs)


class OptionsTests(unittest.TestCase):
    """
    Tests for L{txghbot._api.Options}
    """
    def setUp(self):
        self.secretFilePath = self.mktemp()
        self.secretFile = FilePath(self.secretFilePath)
        self.secretFromPathOption = "--secret-from-path={}".format(
            self.secretFilePath)

        self.stringEnviron = {}
        self.bytesEnviron = {}

        self.osModuleFake = _FakeOSModule.fromdicts(self.stringEnviron,
                                                    self.bytesEnviron)

        self.config = Options(self.osModuleFake)

    def tearDown(self):
        if self.secretFile.exists():
            self.secretFile.remove()

    def secretFromEnvironmentOption(self, variable):
        """
        Generate the secret from environment variable command line
        option.

        @type variable: L{str}
        @param variable: The variable name

        @return: The formatted option containing the path.
        @rtype: L{str}
        """
        return "--secret-from-env={}".format(variable)

    def test_retrieveSecretFromEmptyPath(self):
        """
        An empty secret file raises an L{OSError}
        """
        self.secretFile.touch()
        exc = self.assertRaises(
            UsageError,
            self.config.parseOptions, [self.secretFromPathOption],
        )
        self.assertIn("empty", str(exc).lower())

    def test_retrieveSecretFromMissingPath(self):
        """
        An missing secret file raises an L{IOError}
        """
        self.assertRaises(
            IOError,
            self.config.parseOptions, [self.secretFromPathOption],
        )

    def test_retrieveSecretFromPath(self):
        """
        A newline-stripped secret is returned.  Internal whitespace is
        preserved.
        """
        with self.secretFile.open('wb') as f:
            f.write(b" this is a secret \r\n")
        self.config.parseOptions([self.secretFromPathOption])

        self.assertEqual(self.config["secret"], b" this is a secret ")

    def test_retrieveSecretFromEmptyEnvironment(self):
        """
        A L{UsageError} is raised when attempting to retrieve a secret
        from an environment that doesn't contain the provided
        variable.
        """

        self.assertRaises(UsageError,
                          self.config.parseOptions,
                          [self.secretFromEnvironmentOption("MISSING")])

    def test_retrieveSecretFromEnvironment(self):
        """
        The secret is retrieved as bytes from the process'
        environment.
        """
        self.bytesEnviron[b"SECRET"] = b"a secret"
        self.stringEnviron["SECRET"] = "a secret"

        self.config.parseOptions([self.secretFromEnvironmentOption("SECRET")])

        self.assertEqual(self.config["secret"], b"a secret")

    def test_missingSecret(self):
        """
        Omitting both a secret path and a secret environment variable
        name results in a L{UsageError}.
        """
        self.assertRaises(UsageError, self.config.parseOptions, [])

    def test_bothSecrets(self):
        """
        Including both a secret path and a secret environment variable
        name results in a L{UsageError}.
        """
        self.assertRaises(UsageError, self.config.parseOptions,
                          [self.secretFromPathOption,
                           self.secretFromEnvironmentOption("REDUNDANT")])


@attr.s
class FakeModuleWrapper(object):
    """
    A fake L{twisted.python.modules.PythonModule}
    """
    _loadReturns = attr.ib()

    def load(self):
        return self._loadReturns


class WebhookDispatchServiceMakerTests(unittest.TestCase):
    """
    Tests for L{txghbot._api.WebhookDispatchServiceMaker}
    """

    def setUp(self):
        self.config = {
            "secret": "secret",
            "plugins": "plugin path",
            "logfile": "logfile path",
            "port": "strport"}

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
            _getModule=self.fakeGetModule,
            _getPlugins=self.fakeGetPlugins,
            _makeWebhookDispatchingResource=self.fakeMakeWebhookDR,
            _Site=self.fakeSite,
            _strportsService=self.fakeStrportsService,
        )

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
