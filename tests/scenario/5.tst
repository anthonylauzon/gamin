mkdir test1
mkfile test1/foo
connect test
monfile test1/foo
expect 2
wait
append test1/foo
expect 1
disconnect
rmfile test1/foo
rmdir test1
