#!/bin/bash

set -e

#
# Copyright (C) 2016, Netronome Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
#
#

SDKDIR=${SDKDIR:-/opt/nfp-sdk-6.0.2}

if [ -n "$SERVER" ] ; then
    SERVER="-r $SERVER"
fi

#before loading make sure use unload.sh!
#echo "Cleaning up VMs"

echo "Loading firmware -- this may take a long time"

# load the design
$SDKDIR/p4/bin/rtecli $SERVER design-load -f out/int_transit.nffw -p out/pif/pif_design.json

# load the rules
$SDKDIR/p4/bin/rtecli $SERVER config-reload -c ../p4cfg/int_transit.p4cfg

# switch id is compiled in for now
#$SDKDIR/p4/bin/rtecli registers -r switch_id -s 0xcafe -i 0 -c 1 set
