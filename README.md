# Don't use this yet

But if you do, try this:

Set up a Github webhook that fires on issue_comment and point at your computer, port 8080 (firewalls!).

Then, do this:

````
$ mkdir -p scratch/twisted/plugins && cd scratch
````

Then put your secret in a file called, say, `secret` in that directory.

Then put this in, say, `reopener.py` inside `scratch/twisted/pluins`:

````python
from txghbot import IWebhook
from twisted.plugin import IPlugin

from zope.interface import implementer


@implementer(IWebhook, IPlugin)
class ReopenPullRequest(object):
    MAGIC = u"!please-review"

    def match(self, eventName, eventData):
        return (eventName == u'issue_comment'
                and u'pull_request' in eventData[u'issue']
                and eventData[u'action'] in (u'created',
                                             u'edited')
                and eventData[u'comment'][u'body'].strip() == self.MAGIC)

    def run(self, eventName, eventData, requestID):
        print 'please reopen this one!', eventData['issue']['html_url']


reopener = ReopenPullRequest()
````

...then run txghbot like so:

````
$ twistd -n txghbot --secret ./secret
````

And watch as you find out about pull requests against your repo that gain a special comment.