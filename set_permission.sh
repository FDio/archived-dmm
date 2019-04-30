#! /bin/bash

#dir:750,exec:550,else:640
set_sec_permission()
{
    for var in $*
    do
      if [ -d "$var" ]
      then
          find "$var" -type d | xargs chmod 750 
          find "$var" -perm /+x -type f | xargs chmod 550
	  find "$var" ! -perm /+x -type f | xargs chmod 640
          find "$var" -type f | grep -E "*\.so" | xargs chmod 640
          find "$var" -type f | grep -E "*\.sh|*\.py" | xargs chmod 550
      fi
    done   
}
