#!/usr/bin/env python2.7
# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      setup.py
## Description:   Fireflies setup file.
## Author:        Håard Dagenborg Johansen <haavardj@cs.uit.no>
##                
## $Id: setup.py,v 1.10 2011/08/30 13:55:51 haavardj Exp $
##                
######################################################################

from distutils.core import setup, Extension
import glob, os.path

#########################################################################

sourcePath = os.path.basename(__file__)


module1 = Extension('fireflies.setrecon._setreconbase',
                    #extra_compile_args=["-fno-dce",],
                    swig_opts=["-c++",],
                    sources = ['fireflies/setrecon/constants.cpp',
                               'fireflies/setrecon/node.cpp',
                               'fireflies/setrecon/prob_recon_support.cpp',
                               'fireflies/setrecon/reconciled_set.cpp',
			       'fireflies/setrecon/setreconbase.i' #_wrap.cxx'
                               ],
                    libraries=['ntl', 'gmp'],
                    )

#'fireflies/setrecon/setreconbase.i',


setup(name="fireflies",
      version="0.2",
      description="Fireflies.",
      author="Haavard D Johansen",
      author_email="haavardj@cs.uit.no",
      url="http://sourceforge.net/projects/fireflies",
      scripts=['scripts/ffcanew', 'scripts/fireflyd',
               'scripts/ffreq', 'scripts/ffcasign'],
      packages=['fireflies', 'fireflies.web', 'fireflies.setrecon'],
      license="GPL",
#      ext_modules = [module1],
      package_data = {'fireflies.web': ["*.html", "css/*.css"]}
      )



