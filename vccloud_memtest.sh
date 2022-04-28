for i in `seq 1 100`
do
echo "##############################################
echo "Time: $i - performing test ram by perl script"
echo "###############################################
echo "perl memtest-adv.pl 99%"
perl memtest-adv.pl 99%
sleep 20;

#setup memtester
apt-get install -y memtester

# (64423- Memory in MB, 10- times number loopback
mem=$(expr $(free -m|grep Mem|awk {'print $2'}) - 4000)
echo "performing memtester $mem 2"
memtester $mem 2
sleep 10;


echo "##############################################
echo "performing test ram by dd"
echo "###############################################

echo "dd if=/dev/urandom bs=64000M of=/tmp/memtest count=1"
dd if=/dev/urandom bs=64000M of=/tmp/memtest count=1;
for i in `seq 1 10`
do
md5sum /tmp/memtest &
done

rm -rf /tmp/memtest;
sync;
sleep 20;

echo "Finish Test time $i"

done
#remove memtester
#apt-get remove -y memtester cpuburn

