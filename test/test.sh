#!/bin/bash

python3 testserver.py &
TEST_APP_PID=$!

rm test.db
sslyzedb -vvvvv --sql sqlite:///test.db db create
sslyzedb -vvvvv --sql sqlite:///test.db createproject haha
sslyzedb -vvvvv --sql sqlite:///test.db createscan 1
sslyzedb -vvvvv --sql sqlite:///test.db addtarget 1 file targets.txt
sslyzedb -vvvvv --sql sqlite:///test.db addcommand 1 ALL
sslyzedb -vvvvv --sql sqlite:///test.db scan 1
sslyzedb -vvvvv --sql sqlite:///test.db report 1

kill -9 $TEST_APP_PID
