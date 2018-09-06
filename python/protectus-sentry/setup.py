import glob
from subprocess import run
import sys
#from distutils.extension import Extension
from setuptools import setup, find_packages, Extension

# Cython actually accepts an extended glob pattern, where ** means more than one directory
cythonize_glob = 'protectus_sentry/**/*.py'
pyx_glob = 'protectus_sentry/**/*.pyx'

# "VERSION" is a keyword that the build system will look for.  Feel free to
# change, but know that the build system is running sed, looking for
# "^VERSION.*" in any setup.py files, and will replace it. --TCG
VERSION = '0.1'

requires = [
    'pymongo == 3.6',
    'geoip2',
    'PyYAML',
    'passlib',
    #'impacket',
    'dnspython',
    'pythondialog'
]

setup_settings = {}
if sys.argv[1] in ['bdist_wheel', 'install']:

    from Cython.Distutils import build_ext
    from Cython.Build import cythonize

    extensions = [
        Extension("trafcapProcess", ["protectus_sentry/**/trafcapProcess.pyx"],
        libraries = ["pfring", "pcap", "numa"],
        library_dirs = ["/usr/local/lib"])
    ]

    python2_directives = {"language_level":2}
    python3_directives = {"language_level":3}

    c1 = cythonize(extensions, language_level=3)
    c2 = cythonize(cythonize_glob, language_level=3)
    c3 = cythonize(pyx_glob, language_level=3)
    setup_settings = {
        'cmdclass': {'build_ext':build_ext},
        'ext_modules': c1 + c2 + c3
    }

setup(name='protectus-sentry',
      version=VERSION,
      description='Sentry shared code',
      classifiers=[
        "Programming Language :: Python"
        ],
      author='PROTECTUS',
      author_email='tgarvin@protectus.com',
      url='http://www.protectus.com',
      keywords='protectus',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="protectus_sentry",
      **setup_settings
      )

if sys.argv[1] == 'bdist_wheel':
    dist_dir = "dist"

    print("Stripping wheel of proprietary source code... (hopefully)")
    filenames = glob.glob(dist_dir+'/protectus_sentry*.whl')
    if len(filenames) != 1:
        print("Not sure which wheel file to use! Tell Tim to fix his setup.py.")

    # Move the original to make room for the new
    target_name = filenames[0]
    print("Here we should call obfuscate.sh", target_name)
    run(["../../scripts/build/obfuscatewheel.sh", target_name])
