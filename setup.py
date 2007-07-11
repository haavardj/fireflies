#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      setup.py
## Description:   Fireflies setup file.
## Author:        Håard Dagenborg Johansen <haavardj@cs.uit.no>
##                
## $Id: setup.py,v 1.4 2007/07/11 08:21:16 haavardj Exp $
##                
######################################################################

from distutils.core import setup, Extension
import glob, os.path

#########################################################################

sourcePath = os.path.basename(__file__)


wf = glob.glob("./fireflies/web/*.html")
cf = glob.glob("./fireflies/web/css/*.css")

module1 = Extension('fireflies.setrecon._setreconbase',
                    sources = ['fireflies/setrecon/constants.cpp',
                               'fireflies/setrecon/node.cpp',
                               'fireflies/setrecon/prob_recon_support.cpp',
                               'fireflies/setrecon/reconciled_set.cpp',
			       'fireflies/setrecon/setreconbase_wrap.cxx'
                               ],
                    libraries=['ntl', 'gmp'],
                    )

#'fireflies/setrecon/setreconbase.i',


setup(name="fireflies",
      version="0.0.1",
      description="Fireflies.",
      author="Haavard D Johansen",
      author_email="haavardj@cs.uit.no",
      url="http://sourceforge.net/projects/fireflies",
      scripts=['scripts/ffcakey', 'scripts/fireflyd',
               'scripts/ffrunmany'],
      packages=['fireflies', 'fireflies.web', 'fireflies.setrecon'],
      license="GPL",
      ext_modules = [module1],
      data_files=[ ("lib/python2.5/site-packages/fireflies/web", wf),
                   ("lib/python2.5/site-packages/fireflies/web/css", cf)
                   ]
      )
