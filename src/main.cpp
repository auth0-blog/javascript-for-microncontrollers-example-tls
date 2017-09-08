#include "application.h"

#include "jerryphoton/jerryphoton.h"
#include "main.bundle.h"

#include <vector>
#include <cstdint>

using namespace jerryphoton;

// This enables automatic connections to WiFi networks
SYSTEM_MODE(MANUAL);

// Instantiates the default logger, uses the serial port over USB for logging.
static SerialLogHandler loghandler(LOG_LEVEL_ALL);

static String ipaddress;
static uint32_t freemem = 0;

// Called once when the microcontroller boots
void setup() {
    // Disable OTA updates (partition used by user firmware)
    System.disableUpdates();

    WiFi.on();
    WiFi.connect();

    // Enable serial USB.
    USBSerial1.begin();
    
    // Give some time for other system modules to initialize 
    // before starting the loop
    delay(2000);

    Particle.variable("ipAddress", ipaddress);
    Particle.variable("freeMemory", freemem);
    Particle.publish("spark/device/ip");
    
    /*js::instance().eval(
        "count = 0;"
        "photon.pin.mode(7, 'OUTPUT');"
        "setInterval(function() {"
        "   photon.pin(7, !photon.pin(7));"
        "   photon.log.trace('Hello from JavaScript! ' + count.toString());"
        "   ++count;"
        "}, 1000);"
    );*/
    
    Log.trace("About to run stored script");
    js::instance().eval(main_bundle_js, main_bundle_js_len);
    Log.trace("Setup ended");    

    delay(1000);
}

void loop() {
    ipaddress = WiFi.localIP().toString();
    freemem = System.freeMemory();

    js::instance().loop();

    delay(1000);
}
