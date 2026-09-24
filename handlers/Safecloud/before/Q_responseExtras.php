<?php
/**
 * Loads the Safecloud browser plugin on every page, not just the handful of
 * response handlers that happen to know in advance a Safecloud video/file
 * will be shown (Media/clip's column, Media/dropVideo, Media/episodeEdit,
 * Safecloud/demo, Safecloud/drop).
 *
 * Those handlers' own Q_Response::addScript(...) calls used to be the only
 * way this ever loaded, tagged under a 'head' slot — which silently never
 * reaches the browser during a normal Q/columns AJAX navigation (Q/columns'
 * push() doesn't request "loadExtras", and even the loadExtras response
 * branch only serializes scripts for slots in Q_Response::allSlotNames(),
 * which 'head' isn't a member of). Confirmed live: playing one Safecloud
 * clip, navigating to a category listing, then opening a second Safecloud
 * clip failed with "Q: Missing tool constructor for safecloud_video",
 * because Safecloud.js was never loaded for a page whose first video
 * happened not to be Safecloud-sourced.
 *
 * Loading it here instead means it's present from the very first full page
 * load of a session (a real page load always includes every registered
 * script regardless of slot, per Q_Response::scripts()), so every later
 * SPA-navigated column reuses that same already-loaded script and its
 * Q.Tool.define registrations, regardless of navigation order. The
 * per-handler addScript() calls are left in place as a harmless,
 * already-deduped (Q_Response::addScript() skips an exact src+type already
 * added this request) fallback.
 */
function Safecloud_before_Q_responseExtras()
{
	Q_Response::addScript('{{Safecloud}}/js/Safecloud.js', 'Safecloud');
	Q_Response::addScript('{{Safecloud}}/js/Safecloud/DataTrees.js', 'Safecloud');
	Q_Response::addStylesheet('{{Safecloud}}/css/Safecloud.css', 'Safecloud');
}
