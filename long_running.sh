$ cat long_running.sh
#!/bin/bash
while true; do
    sleep 3
    date +"The Process [$$] says: The current date and time is %F %T"
done