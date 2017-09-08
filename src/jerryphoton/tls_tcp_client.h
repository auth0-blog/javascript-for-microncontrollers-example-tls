#ifndef JERRYPHOTON_CPP_STATIC_GUARD
#error "This file is only meant to be included by jerryphoton.cpp"
#endif

#include "application.h"
#include "jerryscript.h"
#include "jerryscript-ext/arg.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"

#include <vector>
#include <cstdarg>

namespace jerryphoton {

static mbedtls_x509_crt global_tls_ca;

extern "C" int trace_adaptor(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[512];
    vsnprintf(buf, sizeof(buf), fmt, args);
    Log.trace("%s", buf);
    va_end(args);
    return 0;
}

// Print cert to console for debugging purposes
static void per_line_print(const char *buf) {
    char line[128] = { 0 };
    for(size_t i = 0, j = 0;; ++i) {
        if(buf[i] == 0) {
            line[j] = 0;
            Log.trace("%s", line);
            break;
        }

        line[j] = buf[i];
        
        if(line[j] == '\n') {
            line[j] = 0;
            Log.trace("%s", line);
            j = 0;
        } else {
            ++j;
            if(j == sizeof(line)) {
                --j;
            }
        }        
    }
}

struct tls_tcp_client {
    tls_tcp_client() {
        mbedtls_ssl_init(&this->ssl);
        mbedtls_ssl_config_init(&this->conf);
        mbedtls_entropy_init(&this->entropy);
        mbedtls_ctr_drbg_init(&this->ctr_drbg);

        /* This is the best entropy source we have, NOT SECURE */
        mbedtls_entropy_add_source(&entropy, get_random, NULL, 1,   
            MBEDTLS_ENTROPY_SOURCE_STRONG);

        mbedtls_ctr_drbg_seed(&ctr_drbg,
            mbedtls_entropy_func, &entropy, NULL, 0);
    
        mbedtls_ssl_config_defaults(&conf,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT);
        
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

        mbedtls_ssl_conf_ca_chain(&conf, &global_tls_ca, NULL);
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

        //mbedtls_ssl_conf_verify(&conf, verify, NULL);

        mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);
        mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);
    }

    ~tls_tcp_client() {
        mbedtls_ssl_free(&this->ssl);
        mbedtls_ssl_config_free(&this->conf);
        mbedtls_ctr_drbg_free(&this->ctr_drbg);
        mbedtls_entropy_free(&this->entropy);           
        client.stop();     
    }

    bool connect(const char *host, uint16_t port) {     
        mbedtls_ssl_session_reset(&ssl);

        mbedtls_ssl_setup(&ssl, &conf);        
        
        mbedtls_ssl_set_bio(&ssl, &client, 
            tcp_client_send, tcp_client_recv, NULL);   

        Log.trace("TLS connect to host: %s", host);
        mbedtls_ssl_set_hostname(&ssl, host);

        client.connect(host, port);
        Log.print(client.remoteIP().toString());

        int code = 0;
        unsigned long now = millis();
        while((code = mbedtls_ssl_handshake(&ssl)) ==
              MBEDTLS_ERR_SSL_WANT_READ) {
            if((millis() - now) > 10000) {
                // timeout
                break;
            }
            //Log.trace("10 Free mem: %u", System.freeMemory());
            Particle.process();
        }

        if(code != 0) {
            char buf[128];
            mbedtls_strerror(code, buf, sizeof(buf));
            Log.trace("TLS connected failed, code %i -> %s", code, buf);
            client.stop();
            return false;
        }

        return true;
    }

    bool connected() {
        return client.connected();
    }

    void stop() {
        mbedtls_ssl_session_reset(&ssl);
        client.stop();
    }

    size_t available() {
        if(buffer.empty()) {
            buffer = read(0);
        }

        return buffer.size();
    }

    size_t write(const std::vector<char>& data) {
        return mbedtls_ssl_write(&ssl,
            reinterpret_cast<const unsigned char*>(data.data()), data.size());
    }

    std::vector<char> read(size_t max) {
        std::vector<char> data;

        if(max == 0) {
            max = 1024;
        }
        
        if(buffer.empty()) {
            data.resize(max);
            size_t read = mbedtls_ssl_read(&ssl,
                reinterpret_cast<unsigned char*>(data.data()), 
                data.size());
            if(read < 0) {
                data.clear();
            } else {
                data.resize(read);
            }            
        } else {
            if(buffer.size() > max) {
                data.resize(max);
                memcpy(data.data(), buffer.data(), max);
                
                const size_t remaining = buffer.size() - max;
                memmove(buffer.data(), &buffer[max], remaining);
                buffer.resize(remaining);
            } else {
                data = std::move(buffer);
                buffer.clear();
            }
        }

        return data;
    }

private:
    TCPClient client;

    std::vector<char> buffer;

    mbedtls_ssl_context ssl;    
    mbedtls_ssl_config conf;            
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    static int
    get_random(void *data, unsigned char *output, size_t len, size_t *olen) {
        for(size_t i = 0; i < len; ++i) {
            output[i] = random(0, 256);
        }
        
        *olen = len;
    
        return 0;
    }

    static int
    tcp_client_send(void *ctx, const unsigned char *buf, size_t len) {
        TCPClient *client = reinterpret_cast<TCPClient *>(ctx);
        return client->write(buf, len);
    }
    
    static int
    tcp_client_recv(void *ctx, unsigned char *buf, size_t len) {
        TCPClient *client = reinterpret_cast<TCPClient *>(ctx);
        const int read = client->read(buf, len);
        if(read <= 0) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        } else {
            return read;
        }
    }

    static int
    verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
        char buf[1024];
        ((void) data);
    
        Log.trace( "\nVerify requested for (Depth %d):\n", depth );
        mbedtls_x509_crt_info( buf, sizeof( buf ) - 1, "", crt );
        per_line_print(buf);
    
        if ( ( *flags ) == 0 )
            Log.trace( "  This certificate has no flags\n" );
        else
        {
            mbedtls_x509_crt_verify_info( buf, sizeof( buf ), "  ! ", *flags );
            per_line_print(buf);
        }
    
        return 0;
    }
};

static void tls_tcp_client_init() {
    mbedtls_x509_crt_init(&global_tls_ca);

    mbedtls_platform_set_printf(trace_adaptor);
    //mbedtls_debug_set_threshold(3);
}

static void tls_tcp_client_deinit() {
    mbedtls_x509_crt_free(&global_tls_ca);
}

static void tls_client_destructor(void* client_) {
    tls_tcp_client* client = reinterpret_cast<tls_tcp_client*>(client_);
    delete client;
}

static const jerry_object_native_info_t tls_client_native_info = {
    tls_client_destructor
};

static jerry_value_t 
tls_tcp_client_connected(const jerry_value_t func,
                     const jerry_value_t thiz,
                     const jerry_value_t *args,
                     const jerry_length_t argscount) {
    tls_tcp_client *client = nullptr;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &tls_client_native_info, JERRYX_ARG_REQUIRED)
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
tls_tcp_client_connect(const jerry_value_t func,
                   const jerry_value_t thiz,
                   const jerry_value_t *args,
                   const jerry_length_t argscount) {
    tls_tcp_client *client = nullptr;
    std::vector<char> host(1024);
    host.back() = '\0';
    double port = 0;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &tls_client_native_info, JERRYX_ARG_REQUIRED),
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

    const bool connected = 
        client->connect(host.data(), static_cast<uint16_t>(port));

    return jerry_create_boolean(connected);
}

static jerry_value_t 
tls_tcp_client_write(const jerry_value_t func,
                 const jerry_value_t thiz,
                 const jerry_value_t *args,
                 const jerry_length_t argscount) {
    tls_tcp_client *client = nullptr;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &tls_client_native_info, JERRYX_ARG_REQUIRED)
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

    const jerry_value_t written = jerry_create_number(client->write(buf));

    if(!jerry_value_is_string(*args)) {
        jerry_release_value(data);
    }

    return jerry_create_number(written);
}

static jerry_value_t 
tls_tcp_client_available(const jerry_value_t func,
                     const jerry_value_t thiz,
                     const jerry_value_t *args,
                     const jerry_length_t argscount) {
    tls_tcp_client *client = nullptr;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &tls_client_native_info, JERRYX_ARG_REQUIRED)
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
tls_tcp_client_read(const jerry_value_t func,
                const jerry_value_t thiz,
                const jerry_value_t *args,
                const jerry_length_t argscount) {
    tls_tcp_client *client = nullptr;
    double maxbytes = 0;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &tls_client_native_info, JERRYX_ARG_REQUIRED),
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

    const std::vector<char> data(client->read(maxbytes));

    return jerry_create_string_sz(
        reinterpret_cast<const jerry_char_t*>(data.data()), data.size());
}

static jerry_value_t 
tls_tcp_client_stop(const jerry_value_t func,
                const jerry_value_t thiz,
                const jerry_value_t *args,
                const jerry_length_t argscount) {
    tls_tcp_client *client = nullptr;

    const jerryx_arg_t validators[] = {
        jerryx_arg_native_pointer(reinterpret_cast<void**>(&client), 
            &tls_client_native_info, JERRYX_ARG_REQUIRED)
    };

    const jerry_value_t valid = 
        jerryx_arg_transform_this_and_args(
            thiz, args, argscount, validators, 
            sizeof(validators) / sizeof(*validators));

    if(jerry_value_has_error_flag(valid)) {
        return valid;
    }
    jerry_release_value(valid);

    client->stop();

    return jerry_create_undefined();
}

static jerry_value_t 
create_tls_tcp_client(const jerry_value_t func,
                      const jerry_value_t thiz,
                      const jerry_value_t *args,
                      const jerry_length_t argscount) {
    jerry_value_t constructed = thiz;
    
    // Construct object if new was not used to call this function
    {
        const jerry_value_t ownname = create_string("TLSTCPClient");
        if(jerry_has_property(constructed, ownname)) {
            constructed = jerry_create_object();
        }
        jerry_release_value(ownname);
    }

    // Backing object
    tls_tcp_client *client = new tls_tcp_client;
    
    static const struct {
        const char* name;
        jerry_external_handler_t handler;
    } funcs[] = {
        { "connected", tls_tcp_client_connected },
        { "connect"  , tls_tcp_client_connect   },
        { "write"    , tls_tcp_client_write     },
        { "available", tls_tcp_client_available },
        { "read"     , tls_tcp_client_read      },
        { "stop"     , tls_tcp_client_stop      }
    };

    for(const auto& f: funcs) {
        const jerry_value_t name = create_string(f.name);
        const jerry_value_t func = jerry_create_external_function(f.handler);
        
        jerry_set_property(constructed, name, func);
        
        jerry_release_value(func);
        jerry_release_value(name);
    }

    jerry_set_object_native_pointer(constructed, client, 
        &tls_client_native_info);

    return constructed;
}

static jerry_value_t 
tls_tcp_client_add_certificates(const jerry_value_t func,
                                const jerry_value_t thiz,
                                const jerry_value_t *args,
                                const jerry_length_t argscount) {
    if(argscount != 1 || !jerry_value_is_string(*args)) {
        return jerry_create_error(JERRY_ERROR_TYPE, 
            reinterpret_cast<const jerry_char_t *>(
                "Expected certificate as string"));
    }

    const size_t size = jerry_get_string_size(*args);
    std::vector<char> buf(size + 1);
    jerry_string_to_char_buffer(*args, 
        reinterpret_cast<jerry_char_t*>(buf.data()), buf.size());

    int code = 0;
    if((code = mbedtls_x509_crt_parse(&global_tls_ca,
        reinterpret_cast<unsigned char *>(buf.data()),
        buf.size())) != 0) {
        Log.trace("Failed to parse certificate: %i", code);
        Log.trace("%s", buf.data());
        return jerry_create_error(JERRY_ERROR_TYPE, 
            reinterpret_cast<const jerry_char_t *>(
                "Failed to parse certificate"));
    }

    return jerry_create_undefined();
}

} //namespace jerryphoton

