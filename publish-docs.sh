#!/bin/bash
git pull
cd ../parsedmarc-docs || exit
git pull
cd ../parsedmarc || exit
./build.sh
cd ../parsedmarc-docs || exit
git add .
git commit -m "Update docs"
git push
