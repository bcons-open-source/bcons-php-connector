# bcons PHP connector
This package enables you to send messages from your PHP code to your bcons console.

Please visit the demo page TODO links!! to see it in action, and consult the documentation for a detailed explanation of all available options.

![bcons console in a devtool panel](https://bcons.dev/img/bconsScreenshot1.png)
![bcons messages shown in the devtools console](https://bcons.dev/img/bconsScreenshot2.png)
![Warning messages](https://bcons.dev/img/bconsScreenshot3.png)
![Error messages](https://bcons.dev/img/bconsScreenshot4.png)
![Payload sent to the server](https://bcons.dev/img/bconsScreenshot5.png)
![Session data](https://bcons.dev/img/bconsScreenshot6.png)
![Cookies data](https://bcons.dev/img/bconsScreenshot7.png)

## Requirements
This package requires only PHP >= 5.3, allowing its use in legacy code (where it is most needed 😅).

You will also need a bcons account (there is a 'free forever' plan for 1 user and 1 project) and the free bcons browser extension.

## Setup instructions

1. Create an account at [bcons.dev](https://bcons.dev)
    1. On the 'Account' page, copy your user token.
    1. Navigate to the *Projects* page, create your project, and a token will be assigned to it. Copy this token.

2. Install the bcons browser extension. TODO: add links

   After installation, click on the extension icon in your browser and select *Options*. Enter your user token.
   The browser extension adds a *Bcons-User* header to every request made to the domains defined in your project, using your user token. This enables the server code to send any debug messages generated by that request to you.

3. Install the PHP package

    `composer require karontek/bcons`

## Usage

Instantiate the bcons class.

```php
use Karontek\Bcons\Bcons;

$console = new Bcons('your project token');
```

When the bcons class is instantiated, it automatically sends debug messages including the request data payload, current session data, and cookies sent.

It will also send warning and error messages for every warning and error raised by PHP.

But the true power of bcons is unlocked with the ability to send your own messages. Use the log, warn, error methods (or any method of the [Console API](https://developer.mozilla.org/en-US/docs/Web/API/console)) to send messages and view them on your bcons console.

```php
$console->log($currentUserData);
$console->warn("Zip code not available for user $userId");
$console->error("No user with id $userId found");
```

## Where are all these messages displayed?

All these messages are displayed in the bcons console, which you can access via the bcons website (log in and navigate to the [Console](https://bcons.dev/console) page) or through the browser extension. They will also appear in your browser's devtools console.

## Console API support notes

- All methods that accept data can receive multiple parameters. Unless any of the parameters is an array/object, bcons will concatenate all values and show them as a single string, mimicking the behavior of the devtools console.

- The [group](https://developer.mozilla.org/en-US/docs/Web/API/console/group_static) and [groupCollapsed](https://developer.mozilla.org/en-US/docs/Web/API/console/groupcollapsed_static) methods accept a second parameter that will be used as the CSS class name for the `details` element used to display the group data.

  Classes `group1` to `group22` are predefined in the bcons console with optimized colors for light and dark themes. They are also available with the named classes `red`, `orange`, `amber`, `yellow`, `lime`, `green`, `emerald`, `teal`, `cyan`, `sky`, `blue`, `indigo`, `violet`, `purple`, `fuchsia`, `pink`, `rose`, `stone`, `neutral`, `zinc`, `gray` and `slate` (see [Tailwind Color Palette](https://tailwindcolor.com)). Colored groups are exclusive to the bcons console. When a colored group is displayed in the devtools console, it appears as a regular group.

- In the devtools console, a call to [clear](https://developer.mozilla.org/en-US/docs/Web/API/console/clear_static) clears the console and displays a `Console cleared` message. The bcons clear method accepts an optional boolean parameter; if set to false, that message is not displayed.

- In the devtools console, the [table](https://developer.mozilla.org/en-US/docs/Web/API/console/table_static) method displays a table with clickable headers to sort data by that column value. This sorting feature is not yet available in the bcons console.

- The [debug](https://developer.mozilla.org/en-US/docs/Web/API/console/debug_static), [info](https://developer.mozilla.org/en-US/docs/Web/API/console/info_static), [dir](https://developer.mozilla.org/en-US/docs/Web/API/console/dir_static) and [dirxml](https://developer.mozilla.org/en-US/docs/Web/API/console/dirxml_static) methods are all aliases of [log](https://developer.mozilla.org/en-US/docs/Web/API/console/log_static).
