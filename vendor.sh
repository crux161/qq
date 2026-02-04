#!/bin/bash

wget https://monocypher.org/download/monocypher-4.0.2.tar.gz
tar -xvf ./monocypher-4.0.2.tar.gz
cd monocypher-4.0.2
cp -v src/monocypher.c ../..
cp -v src/monocypher.h ../../include
