#!/bin/bash

# Note the path to Janus below should match the one on your machine

docker run \
  --rm -it \
  -v /c/uni_work/Janus:/janus_project\
  janus \
  bash

