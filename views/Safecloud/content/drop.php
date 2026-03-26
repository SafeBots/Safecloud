<?php
/**
 * View for safecloud/drop page.
 * Activates the Safecloud/drop tool; drop.js wires it up.
 */
?>
<div id="Safecloud_drop_page">
<?php
// Activate the Safecloud/drop tool
echo Q_Html::tag('div', Q_Html::toolAttributes('Safecloud/drop', array(
    'jetUrl' => $jetUrl
)));
?>
</div>
