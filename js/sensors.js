const interval = 7000;
let host = 'i5-4590-LIN';
let path = '/';
let port = 3000;

const eventReport = 'sensor-report';
const eventAlarm = 'sensor-alarm';
const coreid = 'PUT THE RIGHT VALUE HERE';
const secret = 'PUT THE RIGHT VALUE HERE';

const gasThreshold = 1000;
const tempThreshold = 40;
const alarmWaitMs = 5000;

const pins = {
    movement: photon.pin.D0,
    flame: photon.pin.D1,
    humidity: photon.pin.D2,
    gas: photon.pin.A0
}

Object.keys(pins).forEach(k => {
    photon.pin.mode(pins[k], 'INPUT');
});

photon.pin.mode(pins.humidity, 'INPUT_PULLDOWN');

function readSensors() {
    const dht = dht11.read(pins.humidity);
    return {
        movement: photon.pin(pins.movement),
        flame: !photon.pin(pins.flame),
        humidity: dht.humidity,
        temperature: dht.temperature,
        gas: photon.pin(pins.gas)
    };
}

function checkData(data) {
    return data.movement || 
           data.flame || 
           (data.gas > gasThreshold) || 
           (data.temperature > tempThreshold);
}

function buildHttpRequest(data) {
    const request = 
        `POST ${path} HTTP/1.1\r\n` + 
        `Host: ${host}\r\n` + 
        `Content-Length: ${data.length}\r\n` +
        `Content-Type: application/x-www-form-urlencoded\r\n` +
        `Secret: ${secret}\r\n` +
        'Connection: close\r\n\r\n' + 
        data;
    
    return request;
}

function sendData(data) {
    const client = photon.TLSTCPClient();
    
    client.connect(host, port);
    if(!client.connected()) {
        photon.log.error(`Could not connect to ${host}:${port}, ` + 
                         `discarding data.`);
        return;
    }

    client.write(buildHttpRequest(data));
    client.stop();
}

function objectUrlEncode(obj) {
    var str = [];
    for(let p in obj) {
        if(obj.hasOwnProperty(p)) {
            const key = encodeURIComponent(p);
            const val = encodeURIComponent(obj[p]);
            str.push(key + "=" + val);
        }
    }
    return str.join("&");
}

function sendEvent(event, data) {        
    try {
        const datastr = JSON.stringify(data);
        
        photon.log.trace(`Sending event ${event}, data: ${datastr}`);
        try {
            // Send event to our server
            sendData(objectUrlEncode({ 
                event: event,
                data: datastr,
                coreid: coreid
            }));
        } catch(e) {
            photon.log.error(`Could not send event to server: ${e.toString()}`);
        }

        // Send event to Particle cloud: disabled to reduce memory usage
        // photon.publish(event, datastr);
    } catch(e) {
        photon.log.error(`Could not publish event: ${e.toString()}`);
    }
}

let data = {};
let timeSinceAlarmMs = 0;
const intervals = [];

function parseHost(h) {
    let i = h.indexOf('/');
    if(i === -1) {
        host = h;
    } else {
        i += 2;
        let j = h.indexOf('/', i);
        if(j === -1) {
            host = h.substring(i);
        } else {
            host = h.substring(i, j);
            path = h.substring(j);
        }
    }
}

export function startReports(host_, port_) {
    if(host_) {
        parseHost(host_);        
    }
    if(port_) {
        port = port_; 
    }

    // Check sensors as fast as possible for 
    // values outside the normal thresholds
    intervals.push(
        setInterval(() => {
            timeSinceAlarmMs += 500;

            try {
                data = readSensors();
                if(checkData(data)) {
                    photon.pin(photon.pin.D7, true);
                    if(timeSinceAlarmMs >= alarmWaitMs) {
                        sendEvent(eventAlarm, data);
                        timeSinceAlarmMs = 0;
                    }
                } else {
                    photon.pin(photon.pin.D7, false);
                }
            } catch(e) {
                photon.log.error(e.toString());
            }
        }, 500)
    );

    // Send a snapshot every interval milliseconds
    intervals.push(
        setInterval(() => {
            try {
                sendEvent(eventReport, data);
            } catch(e) {
                photon.log.error(e.toString());
            }
        }, interval)
    );
}

export function stopReports() {
    intervals.forEach(clearInterval);
}

export function getLastReport() {
    return {
        data: data,
        timeSinceLastAlarmMs: timeSinceAlarmMs
    };
}
