# Qbix PHP Conventions — Addendum

## Plugin entry point  (MyPlugin.php)
```php
class MyPlugin {
    static $loaded = false;
    static function Q_init() {         // called when plugin loads
        Q_Config::load(PLUGINS_DIR . DS . 'MyPlugin' . DS . 'config' . DS . 'app.json');
        self::$loaded = true;
    }
    static function Q_responseExtras() {   // called on every request
        Q_Response::addScript('{{MyPlugin}}/js/MyPlugin.js', 'head');
        Q_Response::addStylesheet('{{MyPlugin}}/css/MyPlugin.css');
    }
}
```

## Page handler  (handlers/MyPlugin/action/response.php)
```php
function MyPlugin_action_response($params) {
    // Add assets
    Q_Response::addScript('{{MyPlugin}}/js/pages/action.js');
    Q_Response::addStylesheet('{{MyPlugin}}/css/pages/action.css');

    // Pass data to JS
    $jetUrl = Q_Config::get('MyPlugin', 'jetUrl', Q_Request::baseUrl());
    Q_Response::setScriptData('Q.plugins.MyPlugin.action.jetUrl', $jetUrl);

    // i18n
    $text = Q_Text::get('MyPlugin/content');
    Q_Response::setSlot('title', Q::ifset($text, 'action', 'PageTitle', 'My Page'));

    // Fill content slot
    if (Q_Request::slotName('content')) {
        Q_Response::setSlot('content',
            Q::view('MyPlugin/content/action.php', compact('text', 'jetUrl'))
        );
    }
    return true;
}
```
Naming: `PluginName_action_response`. Always return `true`.

## View  (views/MyPlugin/content/action.php)
```php
<div id="MyPlugin_action_page">
<?php
// Activate a tool via Q_Html::toolAttributes
echo Q_Html::tag('div', Q_Html::toolAttributes('MyPlugin/widget', array(
    'jetUrl' => $jetUrl,
    'option' => 'value'
)));
?>
</div>
```
`Q_Html::toolAttributes('ToolName', $options)` emits `data-q-tools='…'` that Q activates.

## Q_Config
```php
Q_Config::get('Plugin', 'key', 'default')
Q_Config::get('Plugin', 'nested', 'key', 'default')  // variadic path
```
Set in `config/app.json` (plugin defaults) or `local/app.json` (deployment overrides).

## Q_Text / i18n
```php
$text = Q_Text::get('MyPlugin/content');   // loads text/content/en.json
$label = Q::ifset($text, 'widget', 'Title', 'My Widget');
echo Q_Html::text($label);   // HTML-escaped output
```
JSON path: `text/content/en.json` → key `widget.Title`.

## Q_Response slots
```php
Q_Response::setSlot('content', $html);  // main page content
Q_Response::setSlot('title',   $str);   // <title> tag
Q_Response::addScript('{{Plugin}}/js/file.js');
Q_Response::addStylesheet('{{Plugin}}/css/file.css');
Q_Response::setScriptData('Q.plugins.Plugin.key', $value); // → JS as object path
```
Check if a slot was requested: `if (Q_Request::slotName('content')) { … }`.

## Routes
Defined in the **app's** `APP_DIR/config/app.json` — plugins do **not** ship routes.
Checked last-to-first; three buckets: `Q/routes@start`, `Q/routes`, `Q/routes@end`.
```json
{ "Q": { "routes": {
  "myplugin/action":              { "module": "MyPlugin", "action": "action" },
  "myplugin/:action":             { "module": "MyPlugin" },
  "myplugin/:publisherId/:name":  { "module": "MyPlugin", "action": "stream" },
  ":module/:action.html":         {}
}}}
```
- Literal segments match exactly; `:variable` matches any segment → sets `$uri->variable`
- `:var.literal` matches anything ending in `.literal`
- Last segment `:var[]` captures all remaining segments as array
- Value `null` skips the route; `{"": "Event/name"}` runs extra processing, return `false` to reject
- Route succeeds only if `$uri->module` and `$uri->action` are set
- Read in PHP: `$uri = Q_Dispatcher::uri(); $id = $uri->id;`
- Unroute: `Q_Uri::url("MyPlugin/action ".json_encode(["id"=>$id]))` → URL string

## URI params
```php
$uri = Q_Dispatcher::uri();
$id  = Q::ifset($uri, 'id', null);
// or
$id  = Q::ifset($_GET, 'id', null);
```

## Q_Html helpers
```php
Q_Html::text($str)                  // HTML-escape
Q_Html::tag('div', $attrs, $inner)  // build tag
Q_Html::toolAttributes('MyPlugin/tool', $opts)  // data-q-tools attr
Q_Html::tag('div', Q_Html::toolAttributes('MyPlugin/widget', $opts))
```

## Q:: helpers
```php
Q::ifset($arr, 'key', 'default')         // safe array/object get
Q::ifset($arr, 'a', 'b', 'default')      // nested: $arr['a']['b']
Q::event('MyPlugin/something', $params)  // fire Q event (hook system)
Q::view('MyPlugin/content/file.php', $vars)  // render view, return HTML
```

## Streams (if plugin uses social streams)
```php
$stream = Streams_Stream::fetch($userId, $publisherId, $streamName);
Streams::join($userId, $publisherId, [$streamName]);
$stream->testReadLevel('content')  // bool
$stream->getAttribute('key', $default)
$stream->setAttribute('key', $value); $stream->save();
```

## CSS prefix convention
All CSS classes: `PluginName_toolname_elementname`.
States append as extra classes: `.working`, `.ok`, `.error`, `.Q_working`, `.Q_current`.
