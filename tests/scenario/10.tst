mkdir /tmp/test_gamin
mkdir /tmp/test_gamin/subdir
mkfile /tmp/test_gamin/subdir/foo
connect test
mondir /tmp/test_gamin
wait
expect 2
monfile /tmp/test_gamin/subdir/foo
wait
expect 1
cancel 0
wait
append /tmp/test_gamin/subdir/foo
expect 1
disconnect
rmfile /tmp/test_gamin/subdir/foo
rmdir /tmp/test_gamin/subdir
rmdir /tmp/test_gamin
