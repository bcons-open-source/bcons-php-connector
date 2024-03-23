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
  const CONTENT_AUTO = 'auto';

  // Package version
  public $version = '1.0.7';

  // Default options
  protected $options = array(
    // The token of this project
    'projectToken' => null,
    // The token of the user who requested the URL that sends the debug message.
    // The browser extension sends this value in the HTTP request header
    // 'Bcons-User'.
    'userToken' => null,
    // The key used to encrypt the debug data. If null, data is sent
    // unencrypted.
    // You should never send any data through the Internet unencrypted, so we
    // strongly recommend setting a passphrase here.
    'cryptKey' => null,
    // bcons will send messages for the error codes listed in this array.
    'reportErrorCodes' => array(E_ALL),
    // The bcons server to which messages are sent
    'bconsHost' => 'apps.bcons.dev',
    'bconsPort' => 61947,
    // The key of the http request header that contains the bcons user token, as
    // appears in the $_SERVER superglobal. If, for example, the header is
    // "Bcons-User: XXXXX" the key will appear as HTTP_BCONS_USER
    'userTokenHttpHeader' => 'HTTP_BCONS_USER',
    // By default when creating a new instance request, session and cookies
    // messages will be sent.
    'sendRequestDataOnStart' => true,
    'sendSessionDataOnStart' => true,
    'sendCookiesDataOnStart' => true
  );

  // Sometimes, two consecutive messages may have the same timestamp.  In this
  // array, we'll track how many messages have been sent for each type and add
  // that count to the timestamp to ensure they are displayed in the correct
  // order.
  protected $msgCount = array();

  // The file name and line that are sent as the origin of the debug function
  // call are obtained by calling debug_backtrace. This value represents the
  // number of items we remove from the start of the returned array to get the
  // correct file name.
  protected $numSkipBt = 1;

  // Max size for a message in bytes; any message larger than this will be split
  protected $maxMsgSize = 1000;


  /**
   * The constructor may receive a string with the project token or a named
   * array where the keys set will overwrite its default values set in the
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
    $args = func_get_args();

    if (count($args) == 1)
      $this->buildMessage(self::TYPE_LOG, $args[0], self::CONTENT_AUTO);
    else $this->buildMessage(self::TYPE_LOG, $args, self::CONTENT_AUTO);

    return $this;
  }

  /**
   * Same as log, but for the warnings panel
   *
   * @param mixed $data
   * @return Bcons
   */
  public function warn($data)
  {
    $args = func_get_args();

    if (count($args) == 1)
      $this->buildMessage(self::TYPE_WARN, $args[0], self::CONTENT_AUTO);
    else $this->buildMessage(self::TYPE_WARN, $args, self::CONTENT_AUTO);

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
    $args = func_get_args();

    if (count($args) == 1)
      $this->buildMessage(self::TYPE_ERROR, $args[0], self::CONTENT_AUTO);
    else $this->buildMessage(self::TYPE_ERROR, $args, self::CONTENT_AUTO);

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
    $args = func_get_args();

    if (count($args) == 1)
      $this->buildMessage(self::TYPE_REQUEST, $args[0], self::CONTENT_AUTO);
    else $this->buildMessage(self::TYPE_REQUEST, $args, self::CONTENT_AUTO);

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
    $args = func_get_args();

    if (count($args) == 1)
      $this->buildMessage(self::TYPE_SESSION, $args[0], self::CONTENT_AUTO);
    else $this->buildMessage(self::TYPE_SESSION, $args, self::CONTENT_AUTO);

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
    $args = func_get_args();

    if (count($args) == 1)
      $this->buildMessage(self::TYPE_COOKIE, $args[0], self::CONTENT_AUTO);
    else $this->buildMessage(self::TYPE_COOKIE, $args, self::CONTENT_AUTO);

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
   *                     is provided by the error handler.
   * @return void
   */
  public function buildMessage(
    $messageType,
    $data,
    $contentType = self::CONTENT_AUTO,
    $trace = null)
  {
    // If no bcons user or project is set we can't send the message
    if (!$this->options['userToken'] || !$this->options['projectToken'])
      return;

    // Set content type and format data accordingly
    $dataType = gettype($data);

    if ($contentType == self::CONTENT_AUTO)
      $contentType = $this->getContentType($data);

    if ($dataType == 'boolean')
      $data = $data ? 'true' : 'false';

    if ($dataType == 'NULL')
      $data = 'NULL';

    if ($contentType == self::CONTENT_DATA)
      $data = json_encode($data);

    // For the order we'll use the timestamp but we'll add the number of
    // messages sent, since two consecutive calls may end up having the same
    // timestamp
    $ts = time();
    if (!isset($this->msgCount[$messageType]))
      $this->msgCount[$messageType] = 0;
    $count = ++$this->msgCount[$messageType];
    $order = $ts . str_pad($count, 3, '0', STR_PAD_LEFT);

    // Get the backtack info for this call (if not already provided)
    if (!$trace)
    {
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
        $trace[$k]['code'] = $this->getLineFromFile($v['file'], $v['line']);

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
      'fn' => $fileName,
      'fl' => $fileLine,
      'x' => ['phpBt' => $trace],
    );

    // Encrypt data if required
    if ($this->options['cryptKey'])
    {
      $message['e'] = 1;
      $message['m'] = $this->cryptAES256($message['m']);
      $message['fn'] = $this->cryptAES256($message['fn']);
      $message['fl'] = $this->cryptAES256($message['fl']);
      $message['url'] = $this->cryptAES256($message['url']);
      $message['v'] = $this->cryptAES256($message['v']);
      $message['x'] = $this->cryptAES256(json_encode($message['x']));
    }

    $dataToSend = json_encode($message);

    // Create socket
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
      if ($x && $x % 10 == 0)
        usleep(100000);
    }

    socket_close($socket);
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
   * @return int
   */
  protected function getContentType($data)
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
    $output = base64_encode($iv . $encrypted);

    return $output;
  }

  /**
   * Sends a message for any error, warning or notice generated by PHP.
   *
   * @param int $errorNumber Error level number.
   * @param string $errorMsg Error message.
   * @param string $errorFile Filename where the error was raised.
   * @param int $errorLine Line numnber where the error was raised.
   * @return void
   */
  public function errorHandler($errorNumber, $errorMsg, $errorFile, $errorLine)
  {
    // Should we send a message?
    if (
      in_array(E_ALL, $this->options['reportErrorCodes']) ||
      in_array($errorNumber, $this->options['reportErrorCodes'])
    )
    {
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
          $type = self::TYPE_LOG;
          break;

        default:
          $type = self::TYPE_LOG;
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
  protected function getLineFromFile($file, $lineNumber)
  {
    $f = fopen($file, 'r');
    $count = 1;
    $line = null;
    while (($line = fgets($f)) !== false)
    {
      if ($count == $lineNumber)
        break;
      ++$count;
    }
    return $line;
  }

  /**
   * Sends a message to the request panel with the data sent by the browser.
   *
   * @return void
   */
  protected function sendRequestPayload()
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
      // Data may come in many formats, but the most usual is application/json
      // so we'll take care of that.
      if (
        isset($_SERVER['HTTP_CONTENT_TYPE']) &&
        $_SERVER['HTTP_CONTENT_TYPE'] == 'application/json'
      )
      {
        $request = json_decode($inputStream, true);
        $this->buildMessage(self::TYPE_REQUEST, $request);
      }
    }
  }

  /**
   * Sends a message to the session panel with session data (if any).
   *
   * @return void
   */
  protected function sendSessionData()
  {
    if (isset($_SESSION) && count($_SESSION) > 0)
    {
      $this->skipBacktrace();
      $this->buildMessage(self::TYPE_SESSION, $_SESSION);
    }
  }

  /**
   * Sends a message to the cookies panel with cookies data (if any).
   *
   * @return void
   */
  protected function sendCookiesData()
  {
    if (isset($_COOKIE) && count($_COOKIE) > 0)
    {
      $this->skipBacktrace();
      $this->buildMessage(self::TYPE_COOKIE, $_COOKIE);
    }
  }

  public function getErrorName($errorCode)
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

    return 'UNKNOWN_ERROR';
  }
}
