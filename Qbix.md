# Qbix Platform — JS Conventions Reference

## Plugin Structure
`MyPlugin.php` (PHP class), `classes/MyPlugin.js` (Node entry), `classes/MyPlugin/Sub.js` (sub-modules), `config/app.json` (defaults), `handlers/MyPlugin/action/response.php` (pages), `views/MyPlugin/content/page.php` (HTML), `text/content/en.json` (i18n), `web/js/MyPlugin.js` (browser bootstrap), `web/js/tools/name.js` (tools), `web/js/pages/name.js` (pages), `web/js/methods/MyPlugin/NS/method.js` (Q.Method), `web/css/tools/name.css`.


## web/js/MyPlugin.js  (browser bootstrap)
IIFE `(function(Q,$){…})(Q,Q.jQuery)`. Calls `Q.Text.addFor`, `Q.Tool.define({name:{js,css,text}})`, sets `Q.MyPlugin=Q.plugins.MyPlugin={}`, loads text in `Q.onInit`. `{{MyPlugin}}` resolves to `web/` root.

## Q.Method.define  (lazy namespace API)
```js
Q.MyPlugin.Client = Q.Method.define(
  { store:new Q.Method(), fetch:new Q.Method() },
  "{{MyPlugin}}/js/methods/MyPlugin/Client",
  function(){ return [Q]; },    // extra args injected
  { require:"_internal" }       // _internal.js loaded first, passed as _
);
// Each method file: Q.exports(function(Q,_){ return function Q_…(opts,cb){…}; });
// Supports both Promise and callback. _internal.js provides shared state _.
```

## Q.Tool.define  (UI components)
Three arguments: constructor, default-state object, methods object. Template inline.
```js
(function(Q,$){
Q.Tool.define('MyPlugin/widget', function(options){
  var tool=this, state=tool.state;
  tool.text.widget = Q.extend({Title:'Widget',Btn:'Go'}, tool.text.widget||{});
  tool.refresh();
},{
  myOption: null,
  onDone:  new Q.Event(),
  onError: new Q.Event(function(e){ console.warn(e); })
},{
  refresh: function(){
    var tool=this;
    Q.Template.render('MyPlugin/widget',{text:tool.text},function(err,html){
      $(tool.element).html(html,true).activate(function(){ tool.addEvents(); });
    });
  },
  addEvents: function(){
    $(this.element).on(Q.Pointer.fastclick,'.MyPlugin_widget_btn',function(){
      Q.handle(this.state.onDone,this,[]);
    }.bind(this));
  },
  Q:{ beforeRemove:function(){ /* cleanup timers/handles */ } }
});
Q.Template.set('MyPlugin/widget',
  '<div class="MyPlugin_widget_tool">'+
  '<button class="MyPlugin_widget_btn Q_button">{{text.widget.Btn}}</button>'+
  '<div class="MyPlugin_widget_status"></div></div>'
);
})(Q,Q.jQuery);
```

## Tool conventions
- `tool.state`: options + Q.Events. `tool.text`: from `text:` decl + file; **always seed defaults**.
- Safe access: `Q.getObject('widget.Title', tool.text) || 'fallback'` — direct `tool.text.widget.Title` throws if `tool.text.widget` undefined.
- `tool.element`: root DOM node. Scope: `$(tool.element).find('.ClassName')`.
- Activate: `Q.activate(Q.Tool.setUpElement(el, 'MyPlugin/widget', opts), {}, cb)`.
- Get: `Q.Tool.from(el, 'MyPlugin/widget')`.

**CSS**: `PluginName_toolname_childname`. States: `.working` `.ok` `.error`.

## Q.page()  (page scripts)
```js
Q.page('MyPlugin/pagename', function(){
  var n=0;
  (function wire(){ // tools activate async — poll until ready
    var t=Q.Tool.from(document.querySelector('.MyPlugin_widget_tool'),'MyPlugin/widget');
    if(!t&&++n<20) return setTimeout(wire,200);
    if(t) t.state.onDone.add(handler,'MyPlugin/pagename');
  }());
  return function(){ /* teardown */ };
},'MyPlugin/pagename');
```

**`text/content/en.json`**: `{ "widget":{ "Title":"My Widget","ConnectButton":"Connect" } }`. All leaves Capitalized. Nested by tool name. Access via `Q.getObject('widget.Title', tool.text)`.

## Config
`config/app.json`: `{ "MyPlugin": { "key": "default" } }`.
Read in JS: `Q.Config.get(['MyPlugin','key'], fallback)`.
From PHP to JS: `Q_Response::setScriptData('Q.plugins.MyPlugin.page.key', $v)` → `Q.getObject('MyPlugin.page.key', Q.plugins)`.

## Q.Events
Declared in default state: `onDone: new Q.Event()` or with default: `new Q.Event(function(e){})`.
Fire: `Q.handle(state.onDone, tool, [args])`.
Listen: `state.onDone.add(fn, 'MyKey')`. Remove: `state.onDone.remove('MyKey')`.
Always pass a string key to `.add()` for removability (especially in Q.page).

**Events**: use `Q.Pointer.fastclick` for all button clicks (handles touch + mouse).

## Utility
`Q.extend(dest, src)` shallow, `Q.extend(true, dest, src)` deep.
`Q.getObject('a.b.c', obj)` safe deep get (never throws).
`Q.handle(event, ctx, [args])` fire Q.Event or function.
`Q.nodeUrl()` Node server URL. `Q.url('{{Plugin}}/path')` resolve plugin URL.

**Node.js**: `require('Q')`, no IIFE, `module.exports`. Entry `classes/MyPlugin.js` sets `Q.MyPlugin = {}`, calls `Q.makeEventEmitter(Q.MyPlugin)`, requires sub-modules, exports.

## Routes
App's `APP_DIR/config/app.json`, not plugins. `:var` captures segment, `:var[]` captures rest, `:var.ext` matches `anything.ext`. Buckets: `@start`→`routes`→`@end` (last-to-first). Needs `module`+`action`. Handler: `handlers/MyPlugin/action/response.php` → `MyPlugin_action_response($params)`. Unroute: `Q_Uri::url("MyPlugin/action ".json_encode($fields))`.
