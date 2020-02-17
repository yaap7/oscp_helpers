#!/bin/bash

echo -e "\e[91mpwdump\e[0m"
~/tools/creddump7/pwdump.py ./system.save ./sam.save
echo -e "\e[91mlsadump\e[0m"
~/tools/creddump7/lsadump.py system.save security.save true
echo -e "\e[91mcachedump\e[0m"
~/tools/creddump7/cachedump.py system.save security.save true
