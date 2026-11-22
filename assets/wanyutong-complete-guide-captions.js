(function () {
  'use strict';

  const video = document.querySelector('#complete-guide video[data-guide-captions]');
  if (!video) return;
  const preferred = video.querySelector('track[default]');
  if (!preferred) return;

  // The website locale takes precedence on entry. Native video controls can
  // still change or turn off subtitles after the initial selection.
  for (const track of video.querySelectorAll('track[kind="subtitles"]')) {
    track.track.mode = track === preferred ? 'showing' : 'disabled';
  }
})();
