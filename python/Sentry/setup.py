import os
import sys
from zipfile import ZipFile # For egg manipulation
import glob

from setuptools import setup, find_packages

# Cython actually accepts an extended glob pattern, where ** means more than one directory
cythonize_glob = 'sentry/**/*.py'

# "VERSION" is a keyword that the build system will look for.  Feel free to
# change, but know that the build system is running sed, looking for
# "^VERSION.*" in any setup.py files, and will replace it. --TCG
VERSION = '0.1'

requires = [
    'pymongo >= 2.6',
]

setup_settings = {}
if sys.argv[1] in ['bdist_egg', 'install']:
    from Cython.Distutils import build_ext
    from Cython.Build import cythonize

    setup_settings = {
        'cmdclass': {'build_ext':build_ext},
        'ext_modules': cythonize(cythonize_glob)
    }

setup(name='Sentry',
      version=VERSION,
      description='Sentry shared code',
      classifiers=[
        "Programming Language :: Python"
        ],
      author='PROTECTUS',
      author_email='tgarvin@protectus.com',
      url='http://www.protectus.com',
      keywords='sentry pymongo',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="sentry",
      **setup_settings
      )

# XXX: Apparently, this should actually be implimented as an extention of
# setuptools.install, maybe?  http://stackoverflow.com/q/1321270
if sys.argv[1] == 'bdist_egg':
    dist_dir = "dist"
    if '--dist-dir' in sys.argv:
        dist_dir=sys.argv[sys.argv.index('--dist-dir')+1]

    print "Stripping egg of proprietary source code... (hopefully)"
    filenames = glob.glob(dist_dir+'/Sentry*.egg')
    if len(filenames) != 1:
        print "Not sure which egg file to use! Tell Tim to fix his setup.py."

    # Move the original to make room for the new
    target_name = filenames[0]
    original = target_name + '.original'
    os.rename(target_name,original)
    egg = ZipFile(original)
    newegg = ZipFile(target_name,'w')

    # Make a new egg file, and put everything except the .c files into it.
    for item in egg.infolist():
        path = item.filename
        if path.endswith('.c'):
            print "\tRemoving " + path
        else:
            newegg.writestr(item, egg.read(path))

    egg.close()
    newegg.close()
    os.remove(original)

    print "Done removing proprietary source code"
