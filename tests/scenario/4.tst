mkdir test1
mkfile test1/foo
connect test
mondir test1
expect 3
# for some reason if we don't wait here the server does not
# notify the changes made to test1 when it gets the dnotify event
wait
append test1/foo
expect 1
kill
events
sleep
append test1/foo
expect 1
rmfile test1/foo
expect 1
disconnect
rmdir test1
