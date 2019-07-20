import glob
from subprocess import run
import sys
from setuptools import setup, find_packages, Extension

requires = [
    'pymongo == 3.6',
    'geoip2',
    'dnspython'
]

extension_settings = {}
if set(sys.argv[1:]).intersection(['bdist_wheel', 'install']):

    from Cython.Distutils import build_ext
    from Cython.Build import cythonize

    extensions = [
        Extension("trafcapProcess", ["trafcap/trafcapProcess.pyx"],
        libraries = ["pfring", "pcap"],
        library_dirs = ["/usr/local/lib"])
    ]

    c1 = cythonize(extensions, language_level=3)
    c2 = cythonize('trafcap/*.py', language_level=3)
    c3 = cythonize('trafcap/*.pyx', language_level=3)
    extension_settings = {
        'cmdclass': {'build_ext':build_ext},
        'ext_modules': c1 + c2 + c3
    }

setup(
	name='trafcap',
    version="0.1", # TODO: Best Practicejj
    # TODO description='Sentry shared code',
    classifiers=[
        "Programming Language :: Python :: 3"
    ],
    author='PROTECTUS',
    author_email='pgarvin@protectus.com',
    url='http://www.protectus.com',
    keywords=['protectus', 'network'],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=requires,
    **extension_settings
)
