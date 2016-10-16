"""
Run and publish the API docs
"""
import argparse
import subprocess

TXGHBOT_MODULE_DIR = "txghbot"
INTERSPHINX_LINKS = ("https://docs.python.org/2/objects.inv",
                     "https://docs.python.org/3/objects.inv")


def generateDocs():
    """
    Generate the API docs.
    """
    intersphinxArgs = ['--intersphinx=%s' % (url,)
                       for url in INTERSPHINX_LINKS]
    subprocess.check_call(["pydoctor", TXGHBOT_MODULE_DIR] +
                          intersphinxArgs)


def commitToGithubPages():
    """
    Commit generated API docs to the `gh-pages` branch.
    """
    subprocess.check_call(['git', 'checkout', 'gh-pages'])
    open('index.html', 'w').close()
    subprocess.check_call(['git', 'add', 'index.html'])
    subprocess.check_call(['git', 'add', 'apidocs'])
    subprocess.check_call(['git', 'commit', '-m', 'update API docs'])
    subprocess.check_call(['git', 'checkout', 'master'])


parser = argparse.ArgumentParser("generate and maybe publish API docs.")
parser.add_argument('--publish', '-p',
                    default=False,
                    help="commit the generated docs to gh-pages and push")

args = parser.parse_args()
generateDocs()
if args.publish:
    commitToGithubPages()
