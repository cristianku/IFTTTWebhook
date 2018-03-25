# IFTTTWebHook ESP8266 library

This is a small library that calls IFTTT web hooks from your ESP8266 project.

[IFTTT webhooks](https://ifttt.com/maker_webhooks) allow you to trigger IFTTT actions from your project. You might trigger an action because a button has been pushed, a temperature threshold has been passed, or just because you feel like it. You can pass up to three values with the trigger. IFTTT 

## Usage

1. If you haven't already, add the library to your Arduino project. Either:
- use "Manage Libraries" under the Sketch menu, locate `IFTTTWebhook` and install it
or
- download https://github.com/romkey/IFTTTWebhook/archive/master.zip and install it using "Add Zip" under the Sketch menu

2. Include the library in your project:
```
#include <IFTTTWebhook.h>
```

3. You'll need an IFTTT account, an IFTTT API key for that an account and a webhook event name.

Once you're logged into IFTTT you can get your API key by going to https://ifttt.com/maker_webhooks and clicking the `Documentation` button.

Instantiate an `IFTTTWebhook` object using your API key and the event name:

```
IFTTTWeb webhook(YOUR_IFTTT_API_KEY, YOUR_IFTTT_EVENT_NAME);
```

When you want to trigger the webhook, call the `trigger` method with zero to three `char*` to be passed as values:
```
webhook.trigger("value", "value2", "value3");
```

You can trigger the same webhook object as many times as you.
