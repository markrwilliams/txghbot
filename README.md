# txghbot

[![Build Status](https://api.travis-ci.org/markrwilliams/txghbot.svg?branch=master)](https://travis-ci.org/markrwilliams/txghbot)
[![Coverage Status](https://codecov.io/github/markrwilliams/txghbot/coverage.svg?branch=master)](https://codecov.io/github/markrwilliams/txghbot)

A server that runs [Twisted](https://www.twistedmatrix.com) [plugins](http://twistedmatrix.com/documents/current/core/howto/tap.html) on [Github webhook requests](https://developer.github.com/webhooks/).

## Usage

1. Write a plugin that implements `txghbot.IWebhook` and make it accessible to `twisted.plugin`.
2. Put the secret in a file, such as `.dev/secret`
3. `twist txghbot --secret=./dev/secret`
