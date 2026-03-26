<?php
/**
 * View for safecloud/demo page.
 * Activates Safecloud/upload + Safecloud/video tools side by side.
 * demo.js connects them: after upload fires onStore, video starts streaming.
 */
?>
<div id="Safecloud_demo_page">

  <div class="Safecloud_demo_header">
    <h1><?php echo Q_Html::text(Q::ifset($text, 'demo', 'heading',
        'Safecloud Encrypted Storage')) ?></h1>
    <p><?php echo Q_Html::text(Q::ifset($text, 'demo', 'subheading',
        'Upload a file. It is encrypted in your browser and streamed back only to you.')) ?></p>
  </div>

  <div class="Safecloud_demo_columns">

    <div class="Safecloud_demo_upload_col">
      <?php echo Q_Html::tag('div', Q_Html::toolAttributes('Safecloud/upload', array(
          'jetUrl' => $jetUrl,
          'accept' => 'video/*,audio/*,image/*'
      ))); ?>
    </div>

    <div class="Safecloud_demo_video_col">
      <?php
      // Pre-populate the player if rootCid was passed in the URL
      $videoAttrs = array('jetUrl' => $jetUrl);
      if ($rootCid) {
          $videoAttrs['rootCid'] = $rootCid;
          // rootKey lives in JS (URL hash), not PHP
      }
      echo Q_Html::tag('div', Q_Html::toolAttributes('Safecloud/video', $videoAttrs));
      ?>
    </div>

  </div>

  <div id="Safecloud_demo_share" style="display:none">
    <label><?php echo Q_Html::text(Q::ifset($text, 'demo', 'shareLabel', 'Share link:')) ?></label>
    <input type="text" id="Safecloud_demo_share_url" readonly>
    <button id="Safecloud_demo_copy_btn" class="Q_button">
      <?php echo Q_Html::text(Q::ifset($text, 'demo', 'copyButton', 'Copy')) ?>
    </button>
  </div>

</div>
