import os
import sys
from zipfile import ZipFile # For egg manipulation
import glob
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
    'pymongo >= 3.4',
    'GeoIP',
    'PyYAML',
    'passlib',
    'impacket',
    'dnspython',
    'python2-pythondialog'
]

setup_settings = {}
if sys.argv[1] in ['bdist_egg', 'install']:

    from Cython.Distutils import build_ext
    from Cython.Build import cythonize

    extensions = [
        Extension("trafcapProcess", ["protectus_sentry/**/trafcapProcess.pyx"],
        libraries = ["pfring", "pcap", "numa"],
        library_dirs = ["/usr/local/lib"])
    ]

    #       library_dirs = ["/usr/local/lib", "/home/sentry/PF_RING/userland/lib"])
    print(isinstance(extensions[0], Extension))
    setup_settings = {
        'cmdclass': {'build_ext':build_ext},
        'ext_modules': cythonize(extensions) + cythonize(cythonize_glob) + cythonize(pyx_glob)
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

# XXX: Apparently, this should actually be implimented as an extention of
# setuptools.install, maybe?  http://stackoverflow.com/q/1321270
if sys.argv[1] == 'bdist_egg':
    dist_dir = "dist"
    if '--dist-dir' in sys.argv:
        dist_dir=sys.argv[sys.argv.index('--dist-dir')+1]

    print("Stripping egg of proprietary source code... (hopefully)")
    filenames = glob.glob(dist_dir+'/protectus_sentry*.egg')
    if len(filenames) != 1:
        print("Not sure which egg file to use! Tell Tim to fix his setup.py.")

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
            print("\tRemoving " + path)
        else:
            newegg.writestr(item, egg.read(path))

    egg.close()
    newegg.close()
    os.remove(original)

    print("Done removing proprietary source code")
