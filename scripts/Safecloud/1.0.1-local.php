<?php

function Safecloud_1_0_1_local()
{
    Q_Utils::symlink(
        SAFECLOUD_PLUGIN_WEB_DIR . DS . 'js' . DS . 'Safecloud' . DS . 'sw.js',
        APP_WEB_DIR . DS . 'SafecloudServiceWorker.js'
    );
}

Safecloud_1_0_1_local();