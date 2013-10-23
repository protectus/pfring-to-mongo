import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.txt')).read()
CHANGES = open(os.path.join(here, 'CHANGES.txt')).read()

# "VERSION" is a keyword that the build system will look for.  Feel free to
# change, but know that the build system is running sed, looking for
# something like "^VERSION.*", and will replace it. --TCG
VERSION = '0.1'

requires = [
    'pyramid == 1.2',
    'ujson',
    'pymongo >= 2.2',
    'WebError',
    'pygeoip'
]

setup(name='TrafMongo',
      version=VERSION,
      description='TrafMongo',
      long_description=README + '\n\n' +  CHANGES,
      classifiers=[
        "Programming Language :: Python",
        "Framework :: Pylons",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        ],
      author='PROTECTUS',
      author_email='tgarvin@protectus.com',
      url='http://www.protectus.com',
      keywords='web pyramid pylons',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="trafmongo",
      entry_points = """\
      [paste.app_factory]
      main = trafmongo:main
      """,
      paster_plugins=['pyramid'],
      )

