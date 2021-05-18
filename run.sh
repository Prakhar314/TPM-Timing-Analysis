echo -e "%\tReadClock\tPCR_Read\t16\t512\t1024" > logs.tsv
for i in 1 2 3 4 5 6 7 8 9 10
do
    echo "running at $i%"
    echo -en "$i%\t" >> logs.tsv
    cpulimit -l $i -i ./proj >> logs.tsv
done
