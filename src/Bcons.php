<?php
// https://bcons.dev

namespace Karontek\Bcons;

class Bcons
{
  // Predefined message types
  const TYPE_LOG = 'l';
  const TYPE_WARN = 'w';
  const TYPE_ERROR = 'e';
  const TYPE_REQUEST = 'r';
  const TYPE_SESSION = 's';
  const TYPE_COOKIE = 'c';

  // Predefined content types
  const CONTENT_TEXT = 't';
  const CONTENT_HTML = 'h';
  const CONTENT_DATA = 'd';
  const CONTENT_TABLE = 'r';
  const CONTENT_AUTO = 'auto';

  // Package version
  public $version = '1.0.27';

  // Default options
  protected $options = array(
    // The token of this project
    'projectToken' => null,
    // If set to true the class won't send any messages
    'disabled' => false,
    // The token of the user who requested the URL that sends the debug message.
    // The browser extension sends this value in the HTTP request header
    // 'Bcons-User'.
    'userToken' => null,
    // The key used to encrypt the debug data. If none is provided the user
    // token will be used.
    'cryptKey' => null,
    // bcons will send messages for the error levels listed in this array.
    'reportErrorLevels' => array(E_ALL),
    // The bcons server to which messages are sent
    'bconsHost' => 'apps.bcons.dev',
    'bconsPort' => 61947,
    // The key of the http request header that contains the bcons user token, as
    // appears in the $_SERVER superglobal. If, for example, the header is
    // "Bcons-User: XXXXX" the key will appear as HTTP_BCONS_USER
    'userTokenHttpHeader' => 'HTTP_BCONS_USER',
    // By default, when creating a new instance request, session and cookies
    // messages will be sent.
    'sendRequestDataOnStart' => true,
    'sendSessionDataOnStart' => true,
    'sendCookiesDataOnStart' => true
  );

  // Sometimes, two consecutive messages may have the same timestamp. Here
  // we'll track how many messages have been sent and add that count to
  // the timestamp to ensure they are displayed in the correct order.
  protected $msgCount = 0;

  // The file name and line that are sent as the origin of the debug function
  // call are obtained by calling debug_backtrace. This value represents the
  // number of items we remove from the start of the returned array to get the
  // correct file name.
  protected $numSkipBt = 1;

  // Max size for a message in bytes; any message larger than this will be split
  protected $maxMsgSize = 1000;

  // Here we store the values for the labels of the count() method
  protected $countValues = array();

  // Here we store the stack of groups created by calls to
  // group / groupCollapsed / groupEnd
  protected $msgGroups = array();

  // Here we store date for the time / timeEnd calls
  protected $timers = array();

  // The last error / warning message sent to the console, to avoid duplicates
  // when the shutdown handler is called
  protected $lastError = null;

  /**
   * The constructor may receive a string with the project token or a named
   * array where the keys set will overwrite the default values in the
   * $options member.
   * @param mixed $customOptions
   */
  function __construct($customOptions)
  {
    if (is_string($customOptions))
      $this->options['projectToken'] = $customOptions;
    else
    {
      // Overwrite default options
      foreach ($this->options as $k => $v)
        if (isset($customOptions[$k]))
          $this->options[$k] = $customOptions[$k];
    }

    // If the class is disabled we don't have to do anything else
    if ($this->options['disabled'])
      return;

    // If user token not provided look for it in request header
    if (
      !$this->options['userToken'] &&
      isset($_SERVER[$this->options['userTokenHttpHeader']])
    )
    {
      $this->options['userToken'] = $_SERVER[
        $this->options['userTokenHttpHeader']
      ];
    }

    // If bcons project or user is missing there's nothing else to do here
    if (!$this->options['userToken'])
      return;

    if (!$this->options['projectToken'])
    {
      trigger_error('bcons project token not found', E_USER_WARNING);
      return;
    }

    // If no passphrase is provided, use user token
    if (!$this->options['cryptKey'])
      $this->options['cryptKey'] = $this->options['userToken'];

    // Hook into error handler and shutdown functions
    set_error_handler(array($this, 'errorHandler'));
    register_shutdown_function(array($this, "shutdown"));

    // Send request data
    if ($this->options['sendRequestDataOnStart'])
      $this->sendRequestPayload();
    if ($this->options['sendSessionDataOnStart'])
      $this->sendSessionData();
    if ($this->options['sendCookiesDataOnStart'])
      $this->sendCookiesData();
  }

  /**
   * Sends a message to the "log" panel of the bcons console. If more than one
   * param is received an array with all params will be shown.
   *
   * @param mixed $data
   * @return Bcons
   */
  public function log($data)
  {
    $args = $this->parseMultipleParams(func_get_args());
    $this->buildMessage(self::TYPE_LOG, $args, self::CONTENT_AUTO);

    return $this;
  }

  /**
   * Sends a message to the "log" panel of the bcons console. It is exactly the
   * same as calling the log method, we include it just to mimic the devtools
   * console API as closely as possible.
   *
   * @param mixed $data
   * @return Bcons
   */
  public function debug($data)
  {
    $this->skipBacktrace();
    $args = $this->parseMultipleParams(func_get_args());

    return $this->log($args);
  }

  /**
   * Sends a message to the "log" panel of the bcons console. It is exactly the
   * same as calling the log method, we include it just to mimic the devtools
   * console API as closely as possible.
   *
   * @param mixed $data
   * @return Bcons
   */
  public function info($data)
  {
    $this->skipBacktrace();
    $args = $this->parseMultipleParams(func_get_args());

    return $this->log($args);
  }

  /**
   * Sends a message to the "log" panel of the bcons console. It is exactly the
   * same as calling the log method, we include it just to mimic the devtools
   * console API as closely as possible.
   *
   * @param mixed $data
   * @return Bcons
   */
  public function dir($data)
  {
    $this->skipBacktrace();
    $args = $this->parseMultipleParams(func_get_args());

    return $this->log($args);
  }

  /**
   * Sends a message to the "log" panel of the bcons console. It is exactly the
   * same as calling the log method, we include it just to mimic the devtools
   * console API as closely as possible.
   *
   * @param mixed $data
   * @return Bcons
   */
  public function dirxml($data)
  {
    $this->skipBacktrace();
    $args = $this->parseMultipleParams(func_get_args());

    return $this->log($args);
  }

  /**
   * Same as log, but for the warnings panel
   *
   * @param mixed $data
   * @return Bcons
   */
  public function warn($data)
  {
    $args = $this->parseMultipleParams(func_get_args());
    $this->buildMessage(self::TYPE_WARN, $args, self::CONTENT_AUTO);

    return $this;
  }

  /**
   * Same as log, but for the errors panel
   *
   * @param mixed $data
   * @return Bcons
   */
  public function error($data)
  {
    $args = $this->parseMultipleParams(func_get_args());
    $this->buildMessage(self::TYPE_ERROR, $args, self::CONTENT_AUTO);

    return $this;
  }

  /**
   * Same as log, but for the request panel
   *
   * @param mixed $data
   * @return Bcons
   */
  public function request($data)
  {
    $args = $this->parseMultipleParams(func_get_args());
    $this->buildMessage(self::TYPE_REQUEST, $args, self::CONTENT_AUTO);

    return $this;
  }

  /**
   * Same as log, but for the session panel
   *
   * @param mixed $data
   * @return Bcons
   */
  public function session($data)
  {
    $args = $this->parseMultipleParams(func_get_args());
    $this->buildMessage(self::TYPE_SESSION, $args, self::CONTENT_AUTO);

    return $this;
  }

  /**
   * Same as log, but for the cookies panel
   *
   * @param mixed $data
   * @return Bcons
   */
  public function cookies($data)
  {
    $args = $this->parseMultipleParams(func_get_args());
    $this->buildMessage(self::TYPE_COOKIE, $args, self::CONTENT_AUTO);

    return $this;
  }

  /**
   * Logs data to the error panel only if the condition is false.
   *
   * @param boolean $condition The condition to check. If false any other
   *                           params provided will be displayed in the error
   *                           panel.
   * @return Bcons
   */
  public function assert(bool $condition)
  {
    if (!$condition)
    {
      $args = func_get_args();
      array_shift($args);

      if (!count($args))
        array_unshift($args, 'bcons assert');

      array_unshift($args, 'Assertion failed:');

      $this->skipBacktrace(2);
      call_user_func_array(array($this, "error"), $args);
    }

    return $this;
  }

  /**
   * Logs the number of times this method has been called with this label as
   * parameter ("default" if none is provided).
   *
   * @param string $label
   * @return Bcons
   */
  public function count($label = 'default')
  {
    if (isset($this->countValues[$label]))
      ++$this->countValues[$label];
    else $this->countValues[$label] = 1;

    $this->skipBacktrace();
    $this->log("$label: ".$this->countValues[$label]);

    return $this;
  }

  /**
   * Resets the count value for the provided label ("default" if none is
   * provided).
   *
   * @param string $label
   * @return Bcons
   */
  public function countReset($label = 'default')
  {
    $this->countValues[$label] = 0;

    return $this;
  }

  /**
   * Starts a timer you can use to track how long an operation takes.
   *
   * @param string $label A string representing the name to give the new timer
   * @return Bcons
   */
  public function time($label = 'default')
  {
    $this->timers[$label] = microtime(true) * 1000;

    return $this;
  }

  /**
   * Stops a timer that was previously started by calling time()
   *
   * @param string $label A string representing the name of the timer to stop
   * @return void
   */
  public function timeEnd($label = 'default')
  {
    $this->skipBacktrace(2);

    $args = func_get_args();

    call_user_func_array(array($this, "timeLog"), $args);
  }

  /**
   * Logs the current value of a timer that was previously started by calling
   * time(). Any
   *
   * @param string $label The name of the timer to log to the console
   * @return Bcons
   */
  public function timeLog($label = 'default')
  {
    $this->skipBacktrace();

    $args = func_get_args();
    $label = array_shift($args);

    if (!isset($this->timers[$label]))
    {
      $this->warn("Timer '$label' does not exist ");
      return $this;
    }

    $diff = (microtime(true) * 1000) - $this->timers[$label];

    array_unshift($args, "$label: $diff"."ms");
    $args = $this->parseMultipleParams($args);

    return $this->log($args);
  }

  /**
   * Outputs a stack trace to the console
   *
   * @return Bcons
   */
  public function trace()
  {
    $this->skipBacktrace();
    $args = $this->parseMultipleParams(func_get_args());

    return $this->log($args);
  }

  /**
   * Clears all console panels.
   *
   * @param bool $showInfo If true (default) a message with "Console cleared"
   *                       will be shown, otherwise the console will be cleared
   *                       with no messages.
   * @return Bcons
   */
  public function clear($showInfo = true)
  {
    $extra = array('clearConsole' => true, 'showClearInfo' => $showInfo);

    $this->buildMessage('l', 'Console cleared', self::CONTENT_AUTO, null, $extra);

    return $this;
  }

  /**
   * Clears all console panels without showing any message
   *
   * @return Bcons
   */
  public function clr()
  {
    $this->skipBacktrace();

    return $this->clear(false);
  }

  /**
   * Displays tabular data as a table.
   *
   * @param array $value The data to display.
   * @param array $columns An array containing the names of columns to include
   *                       in the output.
   * @return Bcons
   */
  public function table($value, $columns = array())
  {
    if (!is_array($value))
      return $this;

    $extra = array();
    if (isset($columns))
      $extra = array('columns' => $columns);

    $this->buildMessage(self::TYPE_LOG, $value, self::CONTENT_TABLE, null, $extra);

    return $this;
  }

  /**
   * Creates a new inline group in the log console, causing any subsequent
   * messages to be indented by an additional level, until groupEnd() is called.
   *
   * @param string $label Label for the group
   * @param string $className See createGroup() for more information
   * @return Bcons
   */
  public function group($label = '', $className = '')
  {
    $this->createGroup($label, false, $className);

    return $this;
  }

  /**
   * Like group(), however the new group is created collapsed.
   *
   * @param string $label Label for the group
   * @param string $className See createGroup() for more information
   * @return Bcons
   */
  public function groupCollapsed($label = '', $className = '')
  {
    $this->createGroup($label, true, $className);
    return $this;
  }

  /**
   * Exits the current inline group in the console.
   *
   * @return Bcons
   */
  public function groupEnd()
  {
    array_pop($this->msgGroups);

    $extra = array('groupEnd' => true);
    $this->buildMessage(self::TYPE_LOG, ' ', self::CONTENT_AUTO, null, $extra);

    return $this;
  }

  /**
   * Sends a message indicating the script reached a certain file line.
   * @param string $caption Optional
   *
   * @return Bcons
   */
  public function ping($caption = '')
  {
    $extra = array('ping' => $caption);

    $this->buildMessage('l', ' ', self::CONTENT_AUTO, null, $extra);

    return $this;
  }

  /**
   * Same as log but the first parameter is a color identifier (see
   * createGroup() for details).
   *
   * @param mixed $className
   * @return Bcons
   */
  public function clog($className)
  {
    if (is_numeric($className))
      $className = 'group' . $className;

    $args = func_get_args();
    array_shift($args);
    $args = $this->parseMultipleParams($args);

    $extra = array('style' => $className);

    $this->buildMessage(
      self::TYPE_LOG,
      $args,
      self::CONTENT_AUTO,
      null,
      $extra
    );

    return $this;
  }

  /**
   * Aux function for group and groupCollapsed.
   *
   * @param string $label Label for the group
   * @param boolean $collapsed If true the group will be created collapsed
   * @param string $className CSS class name for the details HTML element.
   *                          Classes "group1" to "group22" are predefined in
   *                          the console with optimized colors for light and
   *                          dark themes. They are also available with the
   *                          named classes red, orange, amber, yellow, lime,
   *                          green, emerald, teal, cyan, sky, blue, indigo,
   *                          violet, purple, fuchsia, pink, rose, stone,
   *                          neutral, zinc, gray and slate.
   *                          If an int X is provided it will be expanded to
   *                          groupX.
   * @return Bcons
   */
  protected function createGroup($label = '', $collapsed = false, $className = '')
  {
    // Create the group and add it to the stack
    if (!$label)
      $label = 'Group '.(count($this->msgGroups) + 1);

    $currentGroup = end($this->msgGroups);
    $parentId = $currentGroup ? $currentGroup['id'] : '';

    if (is_numeric($className))
      $className = 'group' . $className;

    $this->msgGroups[] = array(
      'id' => bin2hex(openssl_random_pseudo_bytes(6)),
      'parentId' => $parentId,
      'label' => $label,
      'collapsed' => $collapsed,
      'style' => $className
    );

    return $this;
  }

  /**
   * Creates and sends a message to the bcons server, that will resend it to
   * all open consoles of the user that made the request.
   *
   * @param int $messageType The message type (indicates the console panel
   *                         where the message will appear).
   * @param mixed $data The message data.
   * @param int $contentType The data type of the message.
   * @param array $trace When capturing messages with the error handler the
   *                     backtrace is not available via debug_backtrace and
   *                     is provided by the error handler on this param.
   * @param array $extra Any extra data that will be sent on the x member of
   *                     the message.
   * @return void
   */
  public function buildMessage(
    $messageType,
    $data,
    $contentType = self::CONTENT_AUTO,
    $trace = null,
    $extra = null)
  {
    // If the class is disabled, or no bcons user or project is set we can't
    // send the message
    if (
      $this->options['disabled'] ||
      !$this->options['userToken'] ||
      !$this->options['projectToken']
    )
      return;

    // Set content type and format data accordingly
    $dataType = gettype($data);

    if ($contentType == self::CONTENT_AUTO)
      $contentType = $this->contentType($data);

    if ($dataType == 'boolean')
      $data = $data ? 'true' : 'false';

    if ($dataType == 'NULL')
      $data = 'NULL';

    if (
      $contentType == self::CONTENT_DATA ||
      $contentType == self::CONTENT_TABLE
    )
      $data = json_encode($data);

    // For the order we'll use the timestamp, but we'll add the number of
    // messages sent, since two consecutive calls may end up having the same
    // timestamp
    $ts = time();
    $count = ++$this->msgCount;
    $order = $ts . str_pad($count, 3, '0', STR_PAD_LEFT);

    // Get the backtrack info for this call (if not already provided)
    if (!$trace)
    {
      if (!defined('DEBUG_BACKTRACE_IGNORE_ARGS'))
        define('DEBUG_BACKTRACE_IGNORE_ARGS', 2);

      $trace = array_slice(
        debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS),
        $this->numSkipBt
      );
    }

    // Restore the default number of backtrace items to skip
    $this->numSkipBt = 1;

    // Add to each backtrace entry the code line
    foreach ($trace as $k => $v)
      if (isset($v['file']) && isset($v['line']))
        $trace[$k]['code'] = $this->lineFromFile($v['file'], $v['line']);

    $fileName = isset($trace[0]['file']) ? $trace[0]['file'] : '';
    $fileLine = isset($trace[0]['line']) ? $trace[0]['line'] : '';
    $url = $_SERVER['REQUEST_URI'];

    // Create message object
    $message = array(
      't' => $this->options['projectToken'],
      'u' => $this->options['userToken'],
      'ts' => $ts,
      'o' => $order,
      'm' => $data,
      'mt' => $messageType,
      'ct' => $contentType,
      'url' => $url,
      'v' => $_SERVER['REQUEST_METHOD'],
      'h' => $_SERVER['HTTP_HOST'],
      'fn' => $fileName,
      'fl' => $fileLine,
      'x' => array('phpBt' => $trace),
    );

    // Add extra data
    if ($extra && is_array($extra))
      foreach ($extra as $k => $v)
        $message['x'][$k] = $v;

    // Add the message group info, if any. This only applies to log messages,
    // any other message type must appear in its own panel.
    if (count($this->msgGroups) && $message['mt'] == 'l')
    {
      $message['x']['groupData'] = end($this->msgGroups);
      $message['x']['groupData']['mt'] = $message['mt'];

      // By definition, all grouped messages will appear in the "log" panel.
      $message['mt'] = 'l';
    }

    // Encrypt data if required
    if ($this->options['cryptKey'])
    {
      // Empty messages would throw an error when encrypting
      if (!$message['m'])
        $message['m'] = ' ';

      $message['e'] = 1;
      $message['m'] = $this->cryptAES256($message['m']);
      $message['fn'] = $this->cryptAES256($message['fn']);
      $message['fl'] = $this->cryptAES256($message['fl']);
      $message['url'] = $this->cryptAES256($message['url']);
      $message['v'] = $this->cryptAES256($message['v']);
      $message['h'] = $this->cryptAES256($message['h']);
      $message['x'] = $this->cryptAES256(json_encode($message['x']));
    }

    $dataToSend = json_encode($message);

    if (!function_exists('socket_create'))
      $this->sendTcpMessage($dataToSend);
    else $this->sendUdpMessage($dataToSend);
  }

  /**
   * Sends the message data via UDP. This is the preferred way since it is
   * much faster than a regular TCP connection.
   *
   * @param string $dataToSend Message data to send, JSON.
   * @return void
   */
  public function sendUdpMessage($dataToSend)
  {
    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

    // Split message into chunks
    $chunks = str_split($dataToSend, $this->maxMsgSize);
    $numChunks = count($chunks);
    $packetId = bin2hex(openssl_random_pseudo_bytes(4));
    for ($x = 0; $x < $numChunks; ++$x)
    {
      $packet = $packetId.'#'.($x + 1).'#'.$numChunks.'#'.$chunks[$x];
      socket_sendto(
        $socket,
        $packet,
        strlen($packet),
        0,
        $this->options['bconsHost'],
        $this->options['bconsPort']
      );

      usleep(5000);
    }

    socket_close($socket);
  }

  /**
   * Sends the message data via TCP. This has a TCP connection overhead and
   * is only used if the sockets extension is not available.
   *
   * @param string $dataToSend Message data to send, JSON.
   * @return void
   */
  public function sendTcpMessage($dataToSend)
  {
    $url = 'https://bcons.dev/api/bconsMessage';
    $data = array('message' => $dataToSend);
    $jsonData = json_encode($data);

    $options = array(
      'http' => array(
        'header'  => "Content-Type: application/json\r\n" .
                     "Content-Length: " . strlen($jsonData) . "\r\n",
        'method'  => 'POST',
        'content' => $jsonData,
      )
    );

    $context = stream_context_create($options);
    file_get_contents($url, false, $context);
  }

  /**
   * All methods that output data to the console admit multiple parameters. This
   * method checks those params and, if they are all strings or numbers,
   * returns a single string with the parameters concatenated, as the
   * console.log method of the devtools would do.
   * Otherwise, the provided array is returned and the default behaviour
   * applies.
   * String substitution placeholders %s, %i, %d, %f, %o, %c are allowed and
   * work as expected.
   *
   * @param array $params
   * @return string|array
   */
  protected function parseMultipleParams($params)
  {
    if (count($params) == 1)
      return $params[0];

    // Perform string substitution
    $params = $this->stringSubstitute($params);

    // Now, if all params are strings or numbers, concatenate them
    $concat = '';
    foreach ($params as $v)
    {
      if (!is_string($v) && !is_numeric($v))
        return $params;

      $concat .= $v.' ';
    }

    return substr($concat, 0, -1); // Remove last space
  }

  /**
   * Performs string substitution using an array of parameters. The first
   * parameter is the string where substitution is performed.
   *
   * @param array $params
   * @return array The array of parameters but with all strings substituted.
   */
  protected function stringSubstitute($params)
  {
    // Perform string substitution.
    $template = array_shift($params);
    $styleTagOpened = false;

    $template = preg_replace_callback(
      '/%[sdfoicSDFOIC]/',
      function($matches) use (&$count, &$params, &$template, &$styleTagOpened)
      {
        $type = strtolower($matches[0]);
        $out = '';

        // Do we have to close a previous style tag?
        if ($styleTagOpened)
        {
          $out .= '</span>';
          $styleTagOpened = false;
        }

        switch ($type)
        {
          // Strings
          case '%s':
            $out .= (string) array_shift($params);
            break;

            // Integers
          case '%d':
          case '%i':
            $out .= (int) array_shift($params);
            break;

            // Floats
          case '%f':
            $out .= (float) array_shift($params);
            break;

          // Objects
          case '%o':
            $out .= json_encode(array_shift($params));
            break;

          // Formatting
          case '%c':
            $style = array_shift($params);
            $styleTagOpened = true;
            $out .= "<span style=\"$style\">";
            break;

          default:
            $out .= array_shift($params);
        }
        return $out;
      },
      $template
    );

    // Close any style tag that may remain unclosed
    if ($styleTagOpened)
      $template .= "</span>";

    // Apply substitution to any remaining params
    if (count($params))
      $params = $this->stringSubstitute($params);

    // Put back the string with the substitution in the params array
    array_unshift($params, $template);

    return $params;
  }

  /**
   * Skips a number of function calls from the function call backtrace.
   *
   * @param integer $numCalls
   * @return void
   */
  public function skipBacktrace($numCalls = 1)
  {
    $this->numSkipBt += $numCalls;
  }

  /**
   * Returns the most suitable content type for the type of the provided param.
   *
   * @param mixed $data The message data
   * @return string
   */
  protected function contentType($data)
  {
    $type = gettype($data);

    switch ($type)
    {
      case 'array':
      case 'object':
        return self::CONTENT_DATA;

      case 'string':
        $noTags = strip_tags($data);
        return ($data != $noTags) ? self::CONTENT_HTML : self::CONTENT_TEXT;
    }

    return self::CONTENT_TEXT;
  }

  /**
   * Encrypts the given message using the defined passphrase.
   *
   * @param string $message Message to encrypt
   * @return string Encrypted message
   */
  protected function cryptAES256($message)
  {
    $method = 'AES-256-CBC';

    if (!defined('OPENSSL_RAW_DATA'))
		define('OPENSSL_RAW_DATA', 1);

    // Generate a secure IV based on the cipher method's requirements
    $ivLength = openssl_cipher_iv_length($method);
    $iv = openssl_random_pseudo_bytes($ivLength);

    // Derive the encryption key from the crypt key
    $key = hash('sha256', $this->options['cryptKey'], true);

    // Encrypt the plaintext
    $encrypted = openssl_encrypt(
      $message,
      $method,
      $key,
      OPENSSL_RAW_DATA,
      $iv
    );

    // Encode the IV and encrypted data with Base64 to ensure safe transit
    return base64_encode($iv . $encrypted);
  }

  /**
   * Sends a message for any error, warning or notice generated by PHP.
   *
   * @param int $errorNumber Error level number.
   * @param string $errorMsg Error message.
   * @param string $errorFile Filename where the error was raised.
   * @param int $errorLine Line number where the error was raised.
   * @return void|bool
   */
  public function errorHandler($errorNumber, $errorMsg, $errorFile, $errorLine)
  {
    // Should we send a message?
    if (
      in_array(E_ALL, $this->options['reportErrorLevels']) ||
      in_array($errorNumber, $this->options['reportErrorLevels'])
    )
    {
      // Avoid duplicates
      $errorMd5 = md5(
        serialize($errorNumber).
        serialize($errorMsg).
        serialize($errorFile).
        serialize($errorLine)
      );

      if ($this->lastError == $errorMd5)
        return;

      $this->lastError = $errorMd5;

      // Set the message type
      switch ($errorNumber)
      {
        // Errors
        case E_ERROR:
        case E_PARSE:
        case E_CORE_ERROR:
        case E_COMPILE_ERROR:
        case E_USER_ERROR:
        case E_RECOVERABLE_ERROR:
          $type = self::TYPE_ERROR;
          break;

          // Warnings
        case E_WARNING:
        case E_CORE_WARNING:
        case E_COMPILE_WARNING:
        case E_USER_WARNING:
        case E_DEPRECATED:
        case E_USER_DEPRECATED:
          $type = self::TYPE_WARN;
          break;

        // Notices
        case E_NOTICE:
        case E_USER_NOTICE:
        case E_STRICT:
          $type = self::TYPE_WARN;
          break;

        default:
          $type = self::TYPE_WARN;
      }

      $trace = array(array('file' => $errorFile, 'line' => $errorLine));
      $this->buildMessage($type, $errorMsg, self::CONTENT_TEXT, $trace);
    }

    // Return false so the standard PHP error handler is executed
    return false;
  }

  /**
   * Called when the script ends, it allows us to send an error message if the
   * script ended because of a fatal error.
   *
   * @return void
   */
  public function shutdown()
  {
    if ($error = error_get_last())
    {
      $this->skipBacktrace();

      $type = isset($error['type']) ? $error['type'] : '';
      $message = isset($error['message']) ? $error['message'] : '';
      $file = isset($error['file']) ? $error['file'] : '';
      $line = isset($error['line']) ? $error['line'] : '';

      $this->errorHandler($type, $message, $file, $line);
    }
  }

  /**
   * Returns the given line of a file
   *
   * @param string $file
   * @param int $lineNumber
   * @return string
   */
  protected function lineFromFile($file, $lineNumber)
  {
    $f = fopen($file, 'r');
    $count = 1;

    while (($line = fgets($f)) !== false)
    {
      if ($count == $lineNumber)
        break;
      ++$count;
    }
    return htmlspecialchars($line);
  }

  /**
   * Sends a message to the request panel with the data sent by the browser.
   *
   * @return Bcons
   */
  public function sendRequestPayload()
  {
    // Check $_GET and $_POST superglobals
    if (count($_GET) > 0 || count($_POST) > 0)
    {
      $request = array();

      foreach ($_GET as $k => $v)
        $request[$k] = $v;

      foreach ($_POST as $k => $v)
        $request[$k] = $v;

      $this->skipBacktrace();
      $this->buildMessage(self::TYPE_REQUEST, $request);
    }

    // Check the input stream for data not sent with
    // application/x-www-form-urlencoded or multipart/form-data content types
    $inputStream = file_get_contents("php://input");

    if ($inputStream && $inputStream != '{}')
    {
      // Data may come in many formats, but the most usual is application/json,
      // so we'll take care of that.
      if (
        isset($_SERVER['HTTP_CONTENT_TYPE']) &&
        $_SERVER['HTTP_CONTENT_TYPE'] == 'application/json'
      )
      {
        $this->skipBacktrace();

        $request = json_decode($inputStream, true);
        $this->buildMessage(self::TYPE_REQUEST, $request);
      }
    }

    return $this;
  }

  /**
   * Sends a message to the session panel with session data (if any).
   *
   * @return Bcons
   */
  public function sendSessionData()
  {
    if (isset($_SESSION) && count($_SESSION) > 0)
    {
      $this->skipBacktrace();
      $this->buildMessage(self::TYPE_SESSION, $_SESSION);
    }

    return $this;
  }

  /**
   * Sends a message to the cookies panel with cookies data (if any).
   *
   * @return Bcons
   */
  public function sendCookiesData()
  {
    if (isset($_COOKIE) && count($_COOKIE) > 0)
    {
      $this->skipBacktrace();
      $this->buildMessage(self::TYPE_COOKIE, $_COOKIE);
    }

    return $this;
  }

  public function errorName($errorCode)
  {
    $errors = array(
      E_ERROR => 'E_ERROR',
      E_PARSE => 'E_PARSE',
      E_CORE_ERROR => 'E_CORE_ERROR',
      E_COMPILE_ERROR => 'E_COMPILE_ERROR',
      E_USER_ERROR => 'E_USER_ERROR',
      E_RECOVERABLE_ERROR => 'E_RECOVERABLE_ERROR',
      E_WARNING => 'E_WARNING',
      E_CORE_WARNING => 'E_CORE_WARNING',
      E_COMPILE_WARNING => 'E_COMPILE_WARNING',
      E_USER_WARNING => 'E_USER_WARNING',
      E_DEPRECATED => 'E_DEPRECATED',
      E_USER_DEPRECATED => 'E_USER_DEPRECATED',
      E_NOTICE => 'E_NOTICE',
      E_USER_NOTICE => 'E_USER_NOTICE',
      E_STRICT => 'E_STRICT'
    );

    if (isset($errors[$errorCode]))
      return $errors[$errorCode];

    $errorName = 'UNKNOWN_ERROR: ';
    if ($errorCode)
      $errorName .= ": $errorCode";

    return $errorName;
  }
}
