./proj & 
P1=$!
stress-ng --cpu 4 -t 7200 & 
P2=$!
wait $P1
pkill $P2
cp logs.csv logs-bg.csv
