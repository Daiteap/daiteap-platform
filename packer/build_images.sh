#!/bin/sh

./packer init ./images-ubuntu.pkr.hcl
./packer validate ./images-ubuntu.pkr.hcl
./packer build ./images-ubuntu.pkr.hcl
