cat /dev/null > logs.csv
for i in 1 2 3 4 5 6 7 8 9 10
do
    echo "running at $i%"
    cpulimit -l $i -i ./proj >> logs.csv
done