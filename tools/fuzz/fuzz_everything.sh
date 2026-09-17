#!/bin/bash

for t in FuzzCorrectness FuzzMatch FuzzGroups FuzzGroupsBothEngines FuzzFindIteration FuzzSet FuzzSetCaps FuzzFindBatch; do ./fuzz-budget.sh 15m 5 "$t"; done
