#!/bin/sh
#
# This script filters out words from the logfile.
# The log entries are generated if a search on a token (for example "00")
# have generated over "file_count_threshold" (that's a var in your config)
# I have set it to 1000. If a search on a word has more than 1000 hit's, then
# I feed it into the filter with this script. Next time it will skip the same
# word. In the end this saves CPU. Don't set it too low or your server won't
# generate any search results!

grep fdb_search log | awk '{print $3}' | sed 's/"//g' | sort > filter.new
> log
cat filter >> filter.new

RESULT=`cat filter.new | sort`

rm -f filter.new

LAST=""

for i in $RESULT; do
 if [ a$i != a$LAST ];
 then
    echo $i >> filter.new
    LAST=$i
 fi
done;

mv filter filter.bak
mv filter.new filter

