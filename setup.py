#!/usr/bin/env python3
"""Build script for the set reconciliation C++ extension.

Project metadata is in pyproject.toml. The extension needs a C++
compiler and the NTL and GMP libraries (on Debian/Ubuntu:
build-essential libntl-dev libgmp-dev python3-dev). SWIG comes from
PyPI as a build dependency.

Set FIREFLIES_NO_EXT=1 to skip the extension. Everything except the
gossip protocol then works.
"""

import os

from setuptools import Extension, setup
from setuptools.command.build_py import build_py


class BuildPyAfterExt(build_py):
    """Run build_ext first so SWIG's generated setreconbase.py exists
    when the Python files are collected."""

    def run(self):
        if self.distribution.ext_modules:
            self.run_command("build_ext")
        super().run()


ext_modules = []
if not os.environ.get("FIREFLIES_NO_EXT"):
    ext_modules.append(Extension(
        "fireflies.setrecon._setreconbase",
        sources=[
            "fireflies/setrecon/constants.cpp",
            "fireflies/setrecon/node.cpp",
            "fireflies/setrecon/prob_recon_support.cpp",
            "fireflies/setrecon/reconciled_set.cpp",
            "fireflies/setrecon/setreconbase.i",
        ],
        swig_opts=["-c++"],
        libraries=["ntl", "gmp"],
        language="c++",
    ))

setup(ext_modules=ext_modules, cmdclass={"build_py": BuildPyAfterExt})
