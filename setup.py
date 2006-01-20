#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      setup.py
## Description:   Fireflies setup file
## Author:        H�ard Dagenborg Johansen <haavardj@cs.uit.no>
##                
## $Id: setup.py,v 1.1 2006/01/20 12:41:26 haavardj Exp $
##                
######################################################################

from distutils.core import setup, Extension
import glob, os.path
import fireflies

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
      version=fireflies.version,
      description="Fireflies.",
      author="H�ard D Johansen",
      author_email="haavardj@cs.uit.no",
      url="N/A",
      scripts=['scripts/ffcakey', 'scripts/fireflyd',
               'scripts/ffrunmany'],
      packages=['fireflies', 'fireflies.web', 'fireflies.setrecon'],
      license="N/A",
      ext_modules = [module1],
      data_files=[ ("lib/python2.3/site-packages/fireflies/web", wf),
                   ("lib/python2.3/site-packages/fireflies/web/css", cf)
                   ]
      )
