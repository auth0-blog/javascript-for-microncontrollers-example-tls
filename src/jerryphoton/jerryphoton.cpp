#define JERRYPHOTON_CPP_STATIC_GUARD

#include "jerryphoton.h"
#include "log.h"
#include "pin.h"
#include "tls_tcp_client.h"
#include "delay.h"
#include "utils.h"

#include "application.h"
#include "jerryscript.h"
#include "jerryscript-port.h"
#include "../dhtlib/dht.h"

#include <cstdint>
#include <vector>

//extern "C" void jerry_port_default_set_log_level (jerry_log_level_t level);

namespace jerryphoton {

static js* instance_ = nullptr;

struct jerry_timer final {
    unsigned long period = 0;
    unsigned long lastrun = 0;
    jerry_value_t f = 0;
    bool once = false;    
};

struct js::impl final {
    impl() {
    }
    ~impl() {        
        // Timer indexes are offset by 1 to comply with setTimeout
        for(size_t i = 1; i <= timers_.size(); ++i) {
            remove_timer(i);
        }
    }

    jerry_value_t new_timer(unsigned long millis, 
                            jerry_value_t func,
                            bool oneshot);
    void remove_timer(size_t idx);
    void check_timers();

    void add_timers_to_js();

    std::vector<jerry_timer> timers_;
};

jerry_value_t js::impl::new_timer(unsigned long millis_, 
                                  jerry_value_t func,
                                  bool oneshot) {
    size_t i = 0;
    for(; i < timers_.size(); ++i) {
        if(timers_[i].f == 0) {
            break;
        }
    }

    if(i == timers_.size()) {
        timers_.push_back(jerry_timer());
    }

    timers_[i].period = millis_;
    timers_[i].f = func;
    timers_[i].once = oneshot;
    timers_[i].lastrun = millis();

    jerry_acquire_value(func);
    
    // Timer indexes are offset by 1 to comply with setTimeout
    return jerry_create_number(i + 1);
}

void js::impl::remove_timer(size_t idx) {
    if((idx == 0) || (idx > timers_.size())) {
        Log.error("Attempted to remove invalid timer");
        return;
    }

    // Timer indexes are offset by 1 to comply with setTimeout
    const size_t i = idx - 1; // Real index
    jerry_release_value(timers_[i].f);
    timers_[i] = jerry_timer();
}

static unsigned long timediff(unsigned long recent, unsigned long past) {
    return recent < past ?        
        (recent + (ULONG_MAX - past)) : // overflow
        (recent - past);                // no overflow
}

void js::impl::check_timers() {
    for(size_t i = 0; i < timers_.size(); ++i) {
        jerry_timer& t = timers_[i];
        if(t.f == 0) {
            continue;
        }        

        if(timediff(millis(), t.lastrun) >= t.period) {
            const bool once = t.once;

            jerry_value_t result = jerry_run(t.f);
            if(jerry_value_has_error_flag(result)) {
                log_jerry_error(result);
            }
            jerry_release_value(result);

            if(once) {
                // Timer indexes are offset by 1 to comply with setTimeout
                remove_timer(i + 1);
            } else {
                t.lastrun = millis();
            }
        }
    }
}

static jerry_value_t
set_timer(bool oneshot, 
          const jerry_value_t func,
          const jerry_value_t thiz,
          const jerry_value_t *args,
          const jerry_length_t argscount) {    
    jerry_value_t callback = 0;
    double millis = 0;

    jerryx_arg_t validators[] = {
        jerryx_arg_function(&callback, JERRYX_ARG_REQUIRED),
        jerryx_arg_number(&millis, JERRYX_ARG_COERCE, JERRYX_ARG_OPTIONAL)
    };
    const size_t validatorscnt = sizeof(validators) / sizeof(*validators);

    jerry_value_t valid = 
        jerryx_arg_transform_args(args, argscount, validators, validatorscnt);
    if(!jerry_value_is_undefined(valid)) {
        Log.trace("Bad arguments in 'setTimeout/setInterval' function.");
        return valid;
    }
    jerry_release_value(valid);

    const jerry_object_native_info_t* ignored = NULL;
    js::impl* that = NULL;
    jerry_get_object_native_pointer(func, 
        reinterpret_cast<void**>(&that), &ignored);
    if(!that) {
        const static char msg[] = 
            "set_timer: BUG: missing associated impl pointer";
        Log.error(msg);
        return jerry_create_error(JERRY_ERROR_COMMON,
            reinterpret_cast<const jerry_char_t*>(msg));
    }

    if(millis < 0) {
        millis = 0;
    }
    return that->new_timer(static_cast<unsigned long>(millis), 
                           callback,
                           oneshot);
}

static jerry_value_t
set_interval(const jerry_value_t func,
             const jerry_value_t thiz,
             const jerry_value_t *args,
             const jerry_length_t argscount) {
    return set_timer(false, func, thiz, args, argscount);
}

static jerry_value_t
set_timeout(const jerry_value_t func,
            const jerry_value_t thiz,
            const jerry_value_t *args,
            const jerry_length_t argscount) {
    return set_timer(true, func, thiz, args, argscount);
}

void js::impl::add_timers_to_js() {
    jerry_value_t global = jerry_get_global_object();

    {
        jerry_value_t timeout = jerry_create_external_function(set_timeout);
        jerry_value_t prop = create_string("setTimeout");

        jerry_set_object_native_pointer(timeout, this, NULL);

        jerry_set_property(global, prop, timeout);

        jerry_release_value(prop);
        jerry_release_value(timeout);
    }

    {
        jerry_value_t interval = jerry_create_external_function(set_interval);
        jerry_value_t prop = create_string("setInterval");

        jerry_set_object_native_pointer(interval, this, NULL);

        jerry_set_property(global, prop, interval);

        jerry_release_value(prop);
        jerry_release_value(interval);
    }

    jerry_release_value(global);
}

static jerry_value_t create_log_object()  {
    jerry_value_t log = jerry_create_object();

    // log.trace
    {
        jerry_value_t func = 
            jerry_create_external_function(photon_log_trace);
        jerry_value_t prop = create_string("trace");
        
        jerry_set_property(log, prop, func);
        
        jerry_release_value(prop);
        jerry_release_value(func);
    }

    // log.info
    {
        jerry_value_t func = 
            jerry_create_external_function(photon_log_info);
        jerry_value_t prop = create_string("info");
        
        jerry_set_property(log, prop, func);
        
        jerry_release_value(prop);
        jerry_release_value(func);
    }

    // log.warn
    {
        jerry_value_t func = 
            jerry_create_external_function(photon_log_warn);
        jerry_value_t prop = create_string("warn");
        
        jerry_set_property(log, prop, func);
        
        jerry_release_value(prop);
        jerry_release_value(func);
    }

    // log.error
    {
        jerry_value_t func = 
            jerry_create_external_function(photon_log_error);
        jerry_value_t prop = create_string("error");
        
        jerry_set_property(log, prop, func);
        
        jerry_release_value(prop);
        jerry_release_value(func);
    }

    return log;
}

static void add_pin_helpers() {
    static const char script[] = 
        "photon.pin.mode.OUTPUT = 'OUTPUT';"
        "photon.pin.mode.INPUT = 'INPUT';"
        "photon.pin.mode.INPUT_PULLUP = 'INPUT_PULLUP';"
        "photon.pin.mode.INPUT_PULLDOWN = 'INPUT_PULLDOWN';"
        "Object.freeze(photon.pin.mode);"
        "Object.freeze(photon.pin);";

    jerry_value_t global = jerry_get_global_object();

    jerry_release_value(
        jerry_eval(reinterpret_cast<const jerry_char_t*>(script), 
                   sizeof(script) - 1, 
                   true));

    jerry_release_value(global);
}

static void add_pin_number(jerry_value_t pin, const char *name, int number) {
    jerry_value_t num = jerry_create_number(number);
    jerry_value_t n = create_string(name);

    jerry_set_property(pin, n, num);

    jerry_release_value(n);
    jerry_release_value(num);
}

static jerry_value_t create_pin_object() {
    jerry_value_t pin = jerry_create_external_function(photon_pin);

    // mode
    {
        jerry_value_t func = 
            jerry_create_external_function(photon_pin_mode);
        jerry_value_t prop = create_string("mode");
        
        jerry_set_property(pin, prop, func);
        
        jerry_release_value(prop);
        jerry_release_value(func);
    }

    // pins
    {
        add_pin_number(pin, "A0", A0);
        add_pin_number(pin, "A1", A1);
        add_pin_number(pin, "A2", A2);
        add_pin_number(pin, "A3", A3);
        add_pin_number(pin, "A4", A4);
        add_pin_number(pin, "A5", A5);
        add_pin_number(pin, "DAC", DAC);

        add_pin_number(pin, "D0", D0);
        add_pin_number(pin, "D1", D1);
        add_pin_number(pin, "D2", D2);
        add_pin_number(pin, "D3", D3);
        add_pin_number(pin, "D4", D4);
        add_pin_number(pin, "D5", D5);
        add_pin_number(pin, "D6", D6);
        add_pin_number(pin, "D7", D7);
    }

    return pin;
}

static void client_destructor(void* client_) {
    TCPClient* client = reinterpret_cast<TCPClient*>(client_);
    client->flush();
    delete client;
}

static void server_destructor(void* server_) {
    TCPServer* server = reinterpret_cast<TCPServer*>(server_);
    delete server;
}

static const jerry_object_native_info_t client_native_info = {
    client_destructor
};

static const jerry_object_native_info_t server_native_info = {
    server_destructor
};

static jerry_value_t 
tcp_client_connected(const jerry_value_t func,
                     const jerry_value_t thiz,
                     const jerry_value_t *args,
                     const jerry_length_t argscount) {
    TCPClient *client = nullptr;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &client_native_info, JERRYX_ARG_REQUIRED)
    };

    const jerry_value_t valid = 
        jerryx_arg_transform_this_and_args(
            thiz, args, argscount, validators, 
            sizeof(validators) / sizeof(*validators));

    if(jerry_value_has_error_flag(valid)) {
        return valid;
    }
    jerry_release_value(valid);

    return jerry_create_boolean(client->connected());
}

static jerry_value_t 
tcp_client_connect(const jerry_value_t func,
                   const jerry_value_t thiz,
                   const jerry_value_t *args,
                   const jerry_length_t argscount) {
    TCPClient *client = nullptr;
    std::vector<char> host(1024);
    host.back() = '\0';
    double port = 0;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &client_native_info, JERRYX_ARG_REQUIRED),
        jerryx_arg_string(host.data(), host.size() - 1, JERRYX_ARG_COERCE, 
            JERRYX_ARG_REQUIRED),
        jerryx_arg_number(&port, JERRYX_ARG_COERCE, JERRYX_ARG_REQUIRED)
    };

    const jerry_value_t valid = 
        jerryx_arg_transform_this_and_args(
            thiz, args, argscount, validators, 
            sizeof(validators) / sizeof(*validators));

    if(jerry_value_has_error_flag(valid)) {
        return valid;
    }
    jerry_release_value(valid);

    Log.trace("TCPClient.connect(): %s %i", 
        host.data(), static_cast<int>(port));

    const bool connected = 
        client->connect(host.data(), static_cast<uint16_t>(port));

    Log.trace("TCPClient.connect(): remote IP: %s", 
        client->remoteIP().toString().c_str());

    return jerry_create_boolean(connected);
}

static jerry_value_t 
tcp_client_write(const jerry_value_t func,
                 const jerry_value_t thiz,
                 const jerry_value_t *args,
                 const jerry_length_t argscount) {
    TCPClient *client = nullptr;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &client_native_info, JERRYX_ARG_REQUIRED)
    };

    const jerry_value_t valid = 
        jerryx_arg_transform_this_and_args(
            thiz, args, argscount, validators, 
            sizeof(validators) / sizeof(*validators));

    if(jerry_value_has_error_flag(valid)) {
        return valid;
    }
    jerry_release_value(valid);

    if(argscount != 1) {
        return jerry_create_error(JERRY_ERROR_COMMON, 
            reinterpret_cast<const jerry_char_t*>(
                "TCPClient.write wrong number of arguments"));
    }

    jerry_value_t data = jerry_value_is_string(*args) ? 
        *args : jerry_value_to_string(*args);

    const size_t size = jerry_get_string_size(data);
    std::vector<char> buf(size);
    jerry_string_to_char_buffer(data, 
        reinterpret_cast<jerry_char_t*>(buf.data()), buf.size());

    const jerry_value_t written =
        jerry_create_number(client->write(
            reinterpret_cast<const uint8_t*>(buf.data()), buf.size()));

    if(!jerry_value_is_string(*args)) {
        jerry_release_value(data);
    }

    return jerry_create_number(written);
}

static jerry_value_t 
tcp_client_available(const jerry_value_t func,
                     const jerry_value_t thiz,
                     const jerry_value_t *args,
                     const jerry_length_t argscount) {
    TCPClient *client = nullptr;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &client_native_info, JERRYX_ARG_REQUIRED)
    };

    const jerry_value_t valid = 
        jerryx_arg_transform_this_and_args(
            thiz, args, argscount, validators, 
            sizeof(validators) / sizeof(*validators));

    if(jerry_value_has_error_flag(valid)) {
        return valid;
    }
    jerry_release_value(valid);

    return jerry_create_number(client->available());
}

static jerry_value_t 
tcp_client_read(const jerry_value_t func,
                const jerry_value_t thiz,
                const jerry_value_t *args,
                const jerry_length_t argscount) {
    TCPClient *client = nullptr;
    double maxbytes = 0;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &client_native_info, JERRYX_ARG_REQUIRED),
        jerryx_arg_number(&maxbytes, JERRYX_ARG_COERCE, JERRYX_ARG_OPTIONAL)
    };

    const jerry_value_t valid = 
        jerryx_arg_transform_this_and_args(
            thiz, args, argscount, validators, 
            sizeof(validators) / sizeof(*validators));

    if(jerry_value_has_error_flag(valid)) {
        return valid;
    }
    jerry_release_value(valid);

    if(maxbytes < 0) {
        maxbytes = 0;
    }

    const size_t available = client->available();
    const size_t toread = maxbytes == 0 ? 
        available : (maxbytes < available ? maxbytes : available);

    std::vector<char> buf(toread);

    client->read(reinterpret_cast<uint8_t*>(buf.data()), toread);

    return jerry_create_string_sz(
        reinterpret_cast<const jerry_char_t*>(buf.data()), toread);
}

static jerry_value_t 
tcp_client_stop(const jerry_value_t func,
                const jerry_value_t thiz,
                const jerry_value_t *args,
                const jerry_length_t argscount) {
    TCPClient *client = nullptr;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &client_native_info, JERRYX_ARG_REQUIRED)
    };

    const jerry_value_t valid = 
        jerryx_arg_transform_this_and_args(
            thiz, args, argscount, validators, 
            sizeof(validators) / sizeof(*validators));

    if(jerry_value_has_error_flag(valid)) {
        return valid;
    }
    jerry_release_value(valid);

    Log.trace("TCPClient.stop() called");
    client->flush();
    client->stop();

    return jerry_create_undefined();
}

static void
build_tcp_client_object(jerry_value_t instance, TCPClient *native) {
    static const struct {
        const char* name;
        jerry_external_handler_t handler;
    } funcs[] = {
        { "connected", tcp_client_connected },
        { "connect"  , tcp_client_connect   },
        { "write"    , tcp_client_write     },
        { "available", tcp_client_available },
        { "read"     , tcp_client_read      },
        { "stop"     , tcp_client_stop      }
    };

    for(const auto& f: funcs) {
        const jerry_value_t name = create_string(f.name);
        const jerry_value_t func = jerry_create_external_function(f.handler);
        
        jerry_set_property(instance, name, func);
        
        jerry_release_value(func);
        jerry_release_value(name);
    }

    jerry_set_object_native_pointer(instance, native, &client_native_info);
}

static jerry_value_t 
create_tcp_client(const jerry_value_t func,
                  const jerry_value_t thiz,
                  const jerry_value_t *args,
                  const jerry_length_t argscount) {
    jerry_value_t constructed = thiz;
    
    // Construct object if new was not used to call this function
    {
        const jerry_value_t ownname = create_string("TCPClient");
        if(jerry_has_property(constructed, ownname)) {
            constructed = jerry_create_object();
        }
        jerry_release_value(ownname);
    }

    // Backing object
    TCPClient* client = new TCPClient;
    
    build_tcp_client_object(constructed, client);

    return constructed;
}

static jerry_value_t 
tcp_server_available(const jerry_value_t func,
                     const jerry_value_t thiz,
                     const jerry_value_t *args,
                     const jerry_length_t argscount) {
    TCPServer* server = NULL;
    const jerry_object_native_info_t *native_info = NULL;
    
    jerry_get_object_native_pointer(thiz, 
        reinterpret_cast<void**>(&server), &native_info);
    
    if(native_info != &server_native_info) {
        return jerry_create_error(JERRY_ERROR_TYPE,
            reinterpret_cast<const jerry_char_t*>(
                "TCPServer.available called with wrong this pointer"));
    }

    TCPClient* client = new TCPClient(server->available());
    jerry_value_t jsclient = jerry_create_object();

    build_tcp_client_object(jsclient, client);

    return jsclient;
}

static jerry_value_t 
create_tcp_server(const jerry_value_t func,
                  const jerry_value_t thiz,
                  const jerry_value_t *args,
                  const jerry_length_t argscount) {
    jerry_value_t constructed = thiz;
    
    Log.trace("TCPServer: argscount %u", argscount);

    if(argscount != 1 || !jerry_value_is_number(*args)) {
        return jerry_create_error(JERRY_ERROR_COMMON,
            reinterpret_cast<const jerry_char_t*>("TCPServer: missing port"));
    }

    const uint16_t port = static_cast<uint16_t>(jerry_get_number_value(*args));

    Log.trace("TCPServer: port: %hu", port);

    // Construct object if new was not used to call this function
    {
        const jerry_value_t ownname = create_string("TCPServer");
        if(jerry_has_property(constructed, ownname)) {
            constructed = jerry_create_object();
        }
        jerry_release_value(ownname);
    }

    Log.trace("TCPServer: constructed empty object");

    {
        const jerry_value_t name = create_string("available");
        const jerry_value_t func =
            jerry_create_external_function(tcp_server_available);
        
        jerry_set_property(constructed, name, func);
        
        jerry_release_value(func);
        jerry_release_value(name);
    }

    Log.trace("TCPServer: added available");

    // Backing object
    TCPServer* server = new TCPServer(port);
    Log.trace("TCPServer: new backing object");
    jerry_set_object_native_pointer(constructed, server, &server_native_info);

    return constructed;
}

static jerry_value_t 
particle_process(const jerry_value_t func,
                 const jerry_value_t thiz,
                 const jerry_value_t *args,
                 const jerry_length_t argscount) {
    Particle.process();
    return jerry_create_undefined();
}

static jerry_value_t 
enter_dfu(const jerry_value_t func,
          const jerry_value_t thiz,
          const jerry_value_t *args,
          const jerry_length_t argscount) {
    bool persistent = false;

    const jerryx_arg_t validators[] = {
        jerryx_arg_boolean(&persistent, JERRYX_ARG_COERCE, JERRYX_ARG_OPTIONAL)
    };

    const jerry_value_t valid = 
        jerryx_arg_transform_args(args, argscount, 
            validators, sizeof(validators) / sizeof(*validators));

    if(jerry_value_has_error_flag(valid)) {
        return valid;
    }
    jerry_release_value(valid);

    Log.trace("Entering DFU mode, bye bye...");
    delay(1000);
    System.dfu(persistent);

    return jerry_create_undefined();
}

static jerry_value_t 
particle_publish(const jerry_value_t func,
                 const jerry_value_t thiz,
                 const jerry_value_t *args,
                 const jerry_length_t argscount) {
    if(argscount == 0) {
        return jerry_create_error(JERRY_ERROR_COMMON,
            reinterpret_cast<const jerry_char_t*>("Wrong number of arguments"));
    }

    std::vector<char> event;
    
    {
        jerry_value_t eventstr = jerry_value_is_string(*args) ? 
            *args : jerry_value_to_string(*args);
        const size_t eventsize = jerry_get_string_size(eventstr);
        
        event.resize(eventsize + 1);
        
        jerry_string_to_char_buffer(eventstr, 
            reinterpret_cast<jerry_char_t*>(event.data()), 
            eventsize);
        
        if(!jerry_value_is_string(*args)) {
            jerry_release_value(eventstr);
        }

        if(eventsize > 63) {
            return jerry_create_error(JERRY_ERROR_RANGE,
                reinterpret_cast<const jerry_char_t*>(
                    "Event name too long (max 63)"));
        }
    }

    bool published = false;
    if(argscount == 1) {
        published = Particle.publish(event.data());
    } else {
        jerry_value_t datastr = jerry_value_is_string(args[1]) ? 
            args[1] : jerry_value_to_string(args[1]);
        const size_t datasize = jerry_get_string_size(datastr);
        
        std::vector<char> data(datasize + 1);
        
        jerry_string_to_char_buffer(datastr, 
            reinterpret_cast<jerry_char_t*>(data.data()), 
            datasize);

        if(!jerry_value_is_string(args[1])) {
            jerry_release_value(datastr);
        }

        if(datasize > 255) {
            return jerry_create_error(JERRY_ERROR_RANGE,
                reinterpret_cast<const jerry_char_t*>(
                    "Data too big (max 255)"));
        }

        published = Particle.publish(event.data(), data.data());
    }    

    return published ? 
        jerry_create_undefined() : 
        jerry_create_error(JERRY_ERROR_COMMON, 
            reinterpret_cast<const jerry_char_t*>(
                "Failed to publish message"));
}

static jerry_value_t 
dht11_read(const jerry_value_t func,
           const jerry_value_t thiz,
           const jerry_value_t *args,
           const jerry_length_t argscount) {
    double pin = 0;

    const jerryx_arg_t validators[] = {
        jerryx_arg_number(&pin, JERRYX_ARG_COERCE, JERRYX_ARG_REQUIRED)
    };

    const jerry_value_t valid = 
        jerryx_arg_transform_args(args, argscount, 
            validators, sizeof(validators) / sizeof(*validators));

    if(jerry_value_has_error_flag(valid)) {
        return valid;
    }
    jerry_release_value(valid);

    dht d;
    uint8_t ec = d.read11(pin);
    if(ec == DHTLIB_OK) {
        jerry_value_t result = jerry_create_object();
        
        jerry_value_t tempstr = create_string("temperature");
        jerry_value_t temp = jerry_create_number(d.temperature);

        jerry_value_t humstr = create_string("humidity");
        jerry_value_t hum = jerry_create_number(d.humidity);

        jerry_set_property(result, tempstr, temp);
        jerry_set_property(result, humstr, hum);

        jerry_release_value(hum);
        jerry_release_value(humstr);
        jerry_release_value(temp);
        jerry_release_value(tempstr);

        return result;
    } else {
        Log.error("DHT read error %hu", ec);
        return jerry_create_error(JERRY_ERROR_COMMON, 
            reinterpret_cast<const jerry_char_t*>("DHT read error"));
    }
}

js::js(): pimpl_(new impl) {

}

js& js::instance()  {
    if(instance_) {
        return *instance_;
    }

    instance_ = new js;

    jerry_init(JERRY_INIT_DEBUGGER);

    // 'photon' object
    jerry_value_t photon = jerry_create_object();

    // 'pin' object
    {
        jerry_value_t pin = create_pin_object();
        jerry_value_t prop = create_string("pin");
        
        jerry_set_property(photon, prop, pin);

        jerry_release_value(prop);
        jerry_release_value(pin);
    }

    // 'log' object
    {
        jerry_value_t log = create_log_object();    
        jerry_value_t prop = create_string("log");
        
        jerry_set_property(photon, prop, log);
        
        jerry_release_value(prop);
        jerry_release_value(log);
    }

    // 'delay' function
    {
        jerry_value_t func = jerry_create_external_function(photon_delay);    
        jerry_value_t prop = create_string("delay");
        
        jerry_set_property(photon, prop, func);
        
        jerry_release_value(prop);
        jerry_release_value(func);
    }

    // TCP client constructor/factory
    {
        jerry_value_t func = jerry_create_external_function(create_tcp_client);    
        jerry_value_t prop = create_string("TCPClient");
        
        jerry_set_property(photon, prop, func);
        
        jerry_release_value(prop);
        jerry_release_value(func);
    }

    // TLS-enabled TCP client constructor/factory
    {
        jerry_value_t func = 
            jerry_create_external_function(create_tls_tcp_client);    
        jerry_value_t prop = create_string("TLSTCPClient");
        
        jerry_set_property(photon, prop, func);
        
        jerry_release_value(prop);

        {
            jerry_value_t func2 = jerry_create_external_function(
                tls_tcp_client_add_certificates);    
            prop = create_string("addCertificates");
            
            jerry_set_property(func, prop, func2);
            
            jerry_release_value(prop);
            jerry_release_value(func2);
        }

        jerry_release_value(func);

        tls_tcp_client_init();
    }

    // TCP server constructor/factory
    {
        jerry_value_t func = jerry_create_external_function(create_tcp_server);    
        jerry_value_t prop = create_string("TCPServer");
        
        jerry_set_property(photon, prop, func);
        
        jerry_release_value(prop);
        jerry_release_value(func);
    }

    // Expose Particle.process()
    {
        jerry_value_t func = jerry_create_external_function(particle_process);
        jerry_value_t prop = create_string("process");
        
        jerry_set_property(photon, prop, func);
        
        jerry_release_value(prop);
        jerry_release_value(func);
    }

    // Expose System.dfu()
    {
        jerry_value_t func = jerry_create_external_function(enter_dfu);
        jerry_value_t prop = create_string("dfu");
        
        jerry_set_property(photon, prop, func);
        
        jerry_release_value(prop);
        jerry_release_value(func);
    }

    // 'publish' function
    {
        jerry_value_t func = jerry_create_external_function(particle_publish);
        jerry_value_t prop = create_string("publish");
        
        jerry_set_property(photon, prop, func);
        
        jerry_release_value(prop);
        jerry_release_value(func);
    }

    // Add 'photon' to the global object/scope
    {
        // The global object is the object in the outermost scope in 
        // the JS interpreter, properties added to it are available globally
        jerry_value_t global = jerry_get_global_object();
        jerry_value_t prop = create_string("photon");

        jerry_set_property(global, prop, photon);
        
        jerry_release_value(prop);
        // The global object lives as long as the interpreter instance is
        // alive, so all objects stored in it (and it itself) 
        // live past this line
        jerry_release_value(global);                
    }

    // It is now stored inside the global object, so we must release it here
    jerry_release_value(photon);

    // DHT11 object (humidity sensor)
    {
        jerry_value_t dht11 = jerry_create_object();

        {
            jerry_value_t func = jerry_create_external_function(dht11_read);
            jerry_value_t prop = create_string("read");

            jerry_set_property(dht11, prop, func);

            jerry_release_value(prop);
            jerry_release_value(func);
        }
        
        {
            jerry_value_t global = jerry_get_global_object();
            jerry_value_t prop = create_string("dht11");

            jerry_set_property(global, prop, dht11);

            jerry_release_value(prop);
            jerry_release_value(global);
        }
        
        jerry_release_value(dht11);
    }

    // Execute JavaScript init scripts.
    add_pin_helpers();

    // Add limited setTimeout/setInterval
    instance_->pimpl_->add_timers_to_js();

    Log.trace("JavaScript interpreter initialized");

    //jerry_port_default_log_level = JERRY_LOG_LEVEL_TRACE;

    return *instance_;
}

js::~js()  {
    tls_tcp_client_deinit();

    delete pimpl_;

    jerry_cleanup();
    
    instance_ = nullptr;

    Log.trace("JavaScript interpreter freed");
}

bool js::instantiated() {
    return static_cast<bool>(instance_);
}

void js::eval(const char* script, size_t size)  {
    if(!script) {
        Log.error("jerryphoton::eval(): script can't be nullptr");
        return;
    }

    // Parse the script and get it ready for execution
    jerry_value_t result = 
        jerry_eval(reinterpret_cast<const jerry_char_t*>(script), 
                   size == 0 ? strlen(script) : size, 
                   false);
    if(jerry_value_has_error_flag(result)) {
        log_jerry_error(result);
    }

    jerry_release_value(result);
}

void js::loop()  {
    pimpl_->check_timers();
}

} //namespace jerryphoton
