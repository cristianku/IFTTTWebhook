/* 
   IFTTTWebhook.cpp
   Created by John Romkey - https://romkey.com/
   Modified by Cristian Zantedeschi
   July 2023
 */

#ifndef ESP32
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#endif

#ifdef ESP32
#include <WiFi.h>
#include <HTTPClient.h>
#endif

#include "IFTTTWebhook.h"

IFTTTWebhook::IFTTTWebhook(const char* api_key, const char* event_name) : IFTTTWebhook::IFTTTWebhook(api_key, event_name, DEFAULT_IFTTT_FINGERPRINT) {
}

IFTTTWebhook::IFTTTWebhook(const char* api_key, const char* event_name, const char* ifttt_fingerprint) {
  _api_key = api_key;
  _event_name = event_name;
  _ifttt_fingerprint = ifttt_fingerprint;
}

int IFTTTWebhook::trigger() {
  return IFTTTWebhook::trigger(NULL, NULL, NULL);
}

int IFTTTWebhook::trigger(const char* value1) {
  return IFTTTWebhook::trigger(value1, NULL, NULL);
}

int IFTTTWebhook::trigger(const char* value1, const char* value2) {
  return IFTTTWebhook::trigger(value1, value2, NULL);
}

#ifdef ESP32
const char* _ifttt_root_certificate = \
"-----BEGIN CERTIFICATE-----\n" \
"MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF"\
"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6"\
"b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL"\
"MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv"\
"b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj"\
"ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM"\
"9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw"\
"IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6"\
"VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L"\
"93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm"\
"jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC"\
"AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA"\
"A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI"\
"U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs"\
"N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv"\
"o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU"\
"5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy"\
"rqXRfboQnoZsG4q5WTP468SQvvG5"\
"-----END CERTIFICATE-----\n";
#endif

int IFTTTWebhook::trigger(const char* value1, const char* value2, const char* value3) {
  HTTPClient http;
  const char* ifttt_base = "https://maker.ifttt.com/trigger";

  int url_length = strlen(ifttt_base) + strlen("/") + strlen(_event_name) + strlen("/with/key/") + strlen(_api_key) + strlen("?") + (strlen("&valuex=")*3);
  url_length += (value1 ? strlen(value1) : 0) + (value2 ? strlen(value2) : 0) + (value3 ? strlen(value3) : 0);
  url_length += 5;
  char ifttt_url[url_length];

#ifdef IFTTT_WEBHOOK_DEBUG  
  Serial.print("URL length: ");
  Serial.println(url_length);
#endif
  
  snprintf(ifttt_url, url_length, "%s/%s/with/key/%s", ifttt_base, _event_name, _api_key);
  if(value1 || value2 || value3) {
    strcat(ifttt_url, "?");
  }

  if(value1) {
    strcat(ifttt_url, "value1=\"");
    strcat(ifttt_url, value1);
    strcat(ifttt_url, "\"");
    if(value2 || value3) {
      strcat(ifttt_url, "&");
    }
  }
  
  if(value2) {
    strcat(ifttt_url, "value2=\"");
    strcat(ifttt_url, value2);
    strcat(ifttt_url, "\"");
    if(value3) {
      strcat(ifttt_url, "&");
    }
  }
  
  if(value3) {
    strcat(ifttt_url, "value3=\"");
    strcat(ifttt_url, value3);
    strcat(ifttt_url, "\"");
  }

#ifdef IFTTT_WEBHOOK_DEBUG  
  Serial.println(ifttt_url);
#endif
  
#ifdef ESP32
  // certificate: openssl s_client -showcerts -connect maker.ifttt.com:443 < /dev/null
  http.begin(ifttt_url, _ifttt_root_certificate);
#else
  // fingerprint: openssl s_client -connect maker.ifttt.com:443  < /dev/null 2>/dev/null | openssl x509 -fingerprint -noout | cut -d'=' -f2
  http.begin(ifttt_url, _ifttt_fingerprint);
#endif
  int httpCode = http.GET();

#ifdef IFTTT_WEBHOOK_DEBUG  
  if (httpCode > 0) {
    Serial.printf("[HTTP] GET... code: %d\n", httpCode);

    if(httpCode == HTTP_CODE_OK) {
      Serial.println(http.getString());
    }
  } else {
      Serial.printf("[HTTP] GET... failed, error: %s\n", http.errorToString(httpCode).c_str());
    }
#endif

    http.end();

    return httpCode != HTTP_CODE_OK;
  }
