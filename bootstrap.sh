#!/bin/bash
###############################################################################
# bootstrap.sh                                                                #
#                                                                             #
# Reset the project and generate configuration script and makefiles.          #
#                                                                             #
#                                                                             #
#   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                               #
#                                                                             #
#                                                                             #
#   Copyright 2013 Carnegie Mellon University                                 #
#                                                                             #
#   Licensed under the Apache License, Version 2.0 (the "License");           #
#   you may not use this file except in compliance with the License.          #
#   You may obtain a copy of the License at                                   #
#                                                                             #
#       http://www.apache.org/licenses/LICENSE-2.0                            #
#                                                                             #
#   Unless required by applicable law or agreed to in writing, software       #
#   distributed under the License is distributed on an "AS IS" BASIS,         #
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  #
#   See the License for the specific language governing permissions and       #
#   limitations under the License.                                            #
###############################################################################

# Cleanup directory structure
./maintainer-clean

# Make all necessary dirs
if [ ! -d build-aux ]
then
        mkdir build-aux
fi

if [ ! -d build-aux/m4 ]
then
        mkdir build-aux/m4
fi

if [ ! -d src/common ]
then
        mkdir src/common
fi

# Generate build scripts
autoreconf --install --force
