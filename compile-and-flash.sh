#!/bin/sh

cd js
echo 'Are npm packages installed?'
if [ ! -d node_modules ]; then
    echo 'Nope, installing npm packages.'
    npm install
fi
echo 'Yes, building JavaScript bundle using Rollup.'
node_modules/rollup/bin/rollup -c

cd dist
echo 'Putting JavaScript bundle into a C array.'
xxd -i main.bundle.js > ../../src/main.bundle.h
cd ../..

echo 'Making bundle C array static const.'
sed -i -e 's/^unsigned/static const/' src/main.bundle.h

echo "Running Docker using sudo."
echo
sudo docker run -t -i --privileged -v /dev/bus/usb:/dev/bus/usb -v $(pwd)/src:/build/jerryscript/targets/particle/source -v $(pwd)/Makefile.particle:/build/jerryscript/targets/particle/Makefile.particle -v $(pwd)/custom.profile:/build/jerryscript/jerry-core/profiles/custom.profile -v $(pwd)/dist:/tmp/dist -v $(pwd)/mbedtls:/build/mbedtls --rm sebadoom/jerryphoton:sensor_hub /bin/bash -c 'cd /build/jerryscript && make -f ./targets/particle/Makefile.particle && cp ./build/particle/jerry_main.bin /tmp/dist/firmware.bin && dfu-util -d 2b04:d006 -a 0 -i 0 -s 0x80A0000:leave -D ./build/particle/jerry_main.bin'

