connect test
mondir test1
expect 2
mkdir test1
expect 1
wait
mkfile test1/foo
expect 1
wait
rmfile test1/foo
expect 1
disconnect
rmdir test1
