mkdir test1
connect test
monfile test1/missing
expect 2
mkfile test1/missing
expect 1
append test1/missing
expect 1
rmfile test1/missing
expect 1
disconnect
rmdir test1
