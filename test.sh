#!/bin/bash
cd ApplicationServer/
./Main &
cd ../CaptureManager/
./CaptureManager &
wait $(jobs -p)
