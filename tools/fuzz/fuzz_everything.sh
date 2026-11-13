#!/bin/bash

for t in FuzzCorrectness FuzzMatch FuzzGroups FuzzGroupsBothEngines FuzzGroupsBothBodies FuzzFindIteration FuzzSet FuzzSetCaps FuzzFindBatch FuzzLongInput FuzzSetRoutes; do ./fuzz-budget.sh 15m 5 "$t"; done
