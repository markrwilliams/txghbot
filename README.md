# Don't use this yet

But if you do, try this:

Set up a Github webhook that fires on issue_comment and point at your computer, port 8080 (firewalls!).

Then, do this:

````
$ mkdir -p scratch/twisted/plugins && cd scratch
````

Then put your secret in a file called, say, `secret` in that directory.

Then put this in, say, `reopener.py` inside `scratch/twisted/plugins`:

````python
from txghbot import IWebhook
from twisted.internet.defer import gatherResults
from twisted.plugin import IPlugin

from zope.interface import implementer
from txgithub.api import GithubApi


@implementer(IWebhook, IPlugin)
class ReopenPullRequest(object):
    MAGIC = u"!please-review"

    def __init__(self, token):
        self.api = GithubApi(token)

    def match(self, eventName, eventData):
        return (eventName == u'issue_comment'
                and u'pull_request' in eventData[u'issue']
                and eventData[u'action'] in (u'created',
                                             u'edited')
                and eventData[u'comment'][u'body'].strip() == self.MAGIC)

    def run(self, eventName, eventData, requestID):
        user = eventData[u'repository'][u'owner'][u'login'].encode('ascii')
        repo = eventData[u'repository'][u'name'].encode('ascii')
        pullNumber = str(eventData[u'issue'][u'number'])

        reopen = self.api.pulls.edit(user, repo, pullNumber, state="open")

        def makeComment(ignored):
            return self.api.comments.create(user, repo, pullNumber,
                                            "Reopened, just for you!")

        reopen.addCallback(makeComment)
        return reopen

reopener = ReopenPullRequest(YOUR_OAUTH2_TOKEN_HERE)
````

...then run txghbot like so:

````
$ twistd -n txghbot --secret ./secret
````

And watch as you find out about pull requests against your repo that gain a special comment.