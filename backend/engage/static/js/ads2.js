// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

let adsManager;
let adsLoader;
let adDisplayContainer;
let playButton;
let videoContent;
let adsInitialized;
let autoplayAllowed;
let autoplayRequiresMuted;

/**
 * Initializes IMA setup.
 */
function initDesktopAutoplayExample() {
  videoContent = document.getElementById('contentElement');
  playButton = document.getElementById('playButton');
  playButton.addEventListener('click', () => {
    // Initialize the container. Must be done through a user action where
    // autoplay is not allowed.
    adDisplayContainer.initialize();
    adsInitialized = true;
    videoContent.load();
    playAds();
  });
  setUpIMA();
  // Check if autoplay is supported.
  checkAutoplaySupport();
}

/**
 * Attempts autoplay and handles success and failure cases.
 */
function checkAutoplaySupport() {
  // Test for autoplay support with our content player.
  const playPromise = videoContent.play();
  if (playPromise !== undefined) {
    playPromise.then(onAutoplayWithSoundSuccess).catch(onAutoplayWithSoundFail);
  }
}

/**
 * Handles case where autoplay succeeded with sound.
 */
function onAutoplayWithSoundSuccess() {
  // If we make it here, unmuted autoplay works.
  videoContent.pause();
  autoplayAllowed = true;
  autoplayRequiresMuted = false;
  autoplayChecksResolved();
}

/**
 * Handles case where autoplay fails with sound.
 */
function onAutoplayWithSoundFail() {
  // Unmuted autoplay failed. Now try muted autoplay.
  checkMutedAutoplaySupport();
}

/**
 * Checks if video can autoplay while muted.
 */
function checkMutedAutoplaySupport() {
  videoContent.volume = 0;
  videoContent.muted = true;
  const playPromise = videoContent.play();
  if (playPromise !== undefined) {
    playPromise.then(onMutedAutoplaySuccess).catch(onMutedAutoplayFail);
  }
}

/**
 * Handles case where autoplay succeeded while muted.
 */
function onMutedAutoplaySuccess() {
  // If we make it here, muted autoplay works but unmuted autoplay does not.
  videoContent.pause();
  autoplayAllowed = true;
  autoplayRequiresMuted = true;
  autoplayChecksResolved();
}

/**
 * Handles case where autoplay failed while muted.
 */
function onMutedAutoplayFail() {
  // Both muted and unmuted autoplay failed. Fall back to click to play.
  videoContent.volume = 1;
  videoContent.muted = false;
  autoplayAllowed = false;
  autoplayRequiresMuted = false;
  autoplayChecksResolved();
}

/**
 * Sets up IMA ad display container, ads loader, and makes an ad request.
 */
function setUpIMA() {
  // Create the ad display container.
  createAdDisplayContainer();
  // Create ads loader.
  
  adsLoader = new google.ima.AdsLoader(adDisplayContainer);
  // Listen and respond to ads loaded and error events.
  adsLoader.addEventListener(
      google.ima.AdsManagerLoadedEvent.Type.ADS_MANAGER_LOADED,
      onAdsManagerLoaded, false);
  adsLoader.addEventListener(
      google.ima.AdErrorEvent.Type.AD_ERROR, onAdError, false);

  // An event listener to tell the SDK that our content video
  // is completed so the SDK can play any post-roll ads.
  videoContent.onended = contentEndedListener;
}

/**
 * Handles content ending and calls adsLoader.contentComplete()
 */
function contentEndedListener() {
  videoContent.onended = null;
  if (adsLoader) {
    adsLoader.contentComplete();
  }
}

/**
 * Builds an ad request and uses it to request ads.
 */
function autoplayChecksResolved() {
  // Request video ads.
  const adsRequest = new google.ima.AdsRequest();
  adsRequest.adTagUrl = 'https://pubads.g.doubleclick.net/gampad/live/ads?'+
  'iu=/22827186738/ca-video-pub-7030138158031630-tag&description_url='+
  'http%3A%2F%2Fengage.devapp.co&tfcd=0&npa=0&sz=400x300%7C640x480&gdfp_req=1'+
  '&output=vast&unviewed_position_start=1&env=vp&impl=s&correlator=';

  // Specify the linear and nonlinear slot sizes. This helps the SDK to
  // select the correct creative if multiple are returned.
  adsRequest.linearAdSlotWidth = 640;
  adsRequest.linearAdSlotHeight = 480;

  adsRequest.nonLinearAdSlotWidth = 640;
  adsRequest.nonLinearAdSlotHeight = 480;

  adsRequest.setAdWillAutoPlay(autoplayAllowed);
  adsRequest.setAdWillPlayMuted(autoplayRequiresMuted);
  adsLoader.requestAds(adsRequest);
}

/**
 * Sets the 'adContainer' div as the IMA ad display container.
 */
function createAdDisplayContainer() {
  // We assume the adContainer is the DOM id of the element that will house
  // the ads.
  adDisplayContainer = new google.ima.AdDisplayContainer(
      document.getElementById('adContainer'), videoContent);
}

/**
 * Loads the video content and initializes IMA ad playback.
 */
function playAds() {
  try {
    if (!adsInitialized) {
      adDisplayContainer.initialize();
      adsInitialized = true;
    }
    // Initialize the ads manager. Ad rules playlist will start at this time.
    adsManager.init(640, 360, google.ima.ViewMode.NORMAL);
    // Call play to start showing the ad. Single video and overlay ads will
    // start at this time; the call will be ignored for ad rules.
    adsManager.start();
  } catch (adError) {
    // An error may be thrown if there was a problem with the VAST response.
    videoContent.play();
  }
}

/**
 * Handles the ad manager loading and sets ad event listeners.
 * @param {!google.ima.AdsManagerLoadedEvent} adsManagerLoadedEvent
 */
function onAdsManagerLoaded(adsManagerLoadedEvent) {
  // Get the ads manager.
  const adsRenderingSettings = new google.ima.AdsRenderingSettings();
  adsRenderingSettings.restoreCustomPlaybackStateOnAdBreakComplete = true;
  adsRenderingSettings.loadVideoTimeout = 100000;
  adsRenderingSettings.enablePreloading = true;

  // videoContent should be set to the content video element.
  adsManager =
      adsManagerLoadedEvent.getAdsManager(videoContent, adsRenderingSettings);
  // Mute the ad if doing muted autoplay.
  const adVolume = (autoplayAllowed && autoplayRequiresMuted) ? 0 : 1;
  adsManager.setVolume(adVolume);

  // Add listeners to the required events.
  adsManager.addEventListener(google.ima.AdErrorEvent.Type.AD_ERROR, onAdError);
  adsManager.addEventListener(
      google.ima.AdEvent.Type.CONTENT_PAUSE_REQUESTED, onContentPauseRequested);
  adsManager.addEventListener(
      google.ima.AdEvent.Type.CONTENT_RESUME_REQUESTED,
      onContentResumeRequested);
  adsManager.addEventListener(
      google.ima.AdEvent.Type.ALL_ADS_COMPLETED, onAdEvent);

  // Listen to any additional events, if necessary.
  adsManager.addEventListener(google.ima.AdEvent.Type.LOADED, onAdEvent);
  adsManager.addEventListener(google.ima.AdEvent.Type.STARTED, onAdEvent);
  adsManager.addEventListener(google.ima.AdEvent.Type.COMPLETE, onAdEvent);
  adsManager.addEventListener(google.ima.AdEvent.Type.CLICK, onAdEvent);
  adsManager.addEventListener(google.ima.AdEvent.Type.VIDEO_CLICKED, onAdEvent);
  
  if (autoplayAllowed) {
    playButton.style.display = 'none';
    playAds();
  } else {
    playButton.style.display = 'block';
  }
}

/**
 * Handles actions taken in response to ad events.
 * @param {!google.ima.AdEvent} adEvent
 */
function onAdEvent(adEvent) {
  // Retrieve the ad from the event. Some events (for example,
  // ALL_ADS_COMPLETED) don't have ad object associated.
  const ad = adEvent.getAd();
  console.log("Ad event detected "+adEvent.type);
  switch (adEvent.type) {
    case google.ima.AdEvent.Type.LOADED:
      // This is the first event sent for an ad - it is possible to
      // determine whether the ad is a video ad or an overlay.
      console.log("Ad uni Id: "+ad.getUniversalAdIdValue()); 
      // console.log("Ad creative Id: "+ad.getCreativeAdId());
      console.log("Ad ID: "+ad.getAdId());
      $("#mainContainer,.close_video_ad").show();
      if (!ad.isLinear()) {
        videoContent.play();
      }
      break;
    case google.ima.AdEvent.Type.ALL_ADS_COMPLETED:
      // This is triggered when all ads have done playing
      // Hide ad
      $("#mainContainer,#playButton,.close_video_ad").hide();
      break;
    case google.ima.AdEvent.Type.CLICK:
      // This is triggered when the visit site button is clicked
      // Hide ad we can use ad.getUniversalAdIdValue() for unique ad value (make sure button is not clicked several times)
      postReward("click", ad.getAdId()).then(res => {
        //form.trigger("reset");
        console.log("Click event reward success");
        console.log(res);
      }).catch(e => {
        console.log("Click event reward failed");
        console.log(e);
      });
      break;
    case google.ima.AdEvent.Type.COMPLETE:
      // This is triggered when one ad is completed
      postReward("view", ad.getAdId()).then(res => {
        //form.trigger("reset");
        console.log("View event reward success");
        console.log(res);
      }).catch(e => {
        console.log("View event reward failed");
        console.log(e);
      });
      break;
  }
}

/**
 * Handles ad errors.
 * @param {!google.ima.AdErrorEvent} adErrorEvent
 */
function onAdError(adErrorEvent) {
  // Handle the error logging.
  console.log(adErrorEvent.getError());
  console.log("ad error detected");
  try {

    adsManager.destroy();

  } catch (err) {
  
    // error handling
  
  }
  $("#mainContainer,#playButton,.close_video_ad").hide();
  // Fall back to playing content.
  //videoContent.play();
}

/**
 * Pauses video content and sets up ad UI.
 */
function onContentPauseRequested() {
  videoContent.pause();
  videoContent.onended = null;
}

/**
 * Resumes video content and removes ad UI.
 */
function onContentResumeRequested() {
  videoContent.play();
  videoContent.onended = contentEndedListener;
}

function closeVideoAd(){
  try {

  videoContent.pause();

  } catch (err) {
  
    // error handling
  
  }
  
   $("#mainContainer,#playButton,.close_video_ad").hide();
}

function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
      const cookies = document.cookie.split(';');
      for (let i = 0; i < cookies.length; i++) {
          const cookie = cookies[i].trim();
          // Does this cookie string begin with the name we want?
          if (cookie.substring(0, name.length + 1) === (name + '=')) {
              cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
              break;
          }
      }
  }
  return cookieValue;
}
function postReward(reward_type, adidd) {
  const apiurl = window.location.origin+'/api/users/get_ad_reward/';
  const xtoken = getCookie('csrftoken');
  console.log("reward_type"+reward_type+"ad id "+ adidd);
  return new Promise((resolve, reject) => {
      $.ajax({
          url: apiurl,
          headers: {
              "X-CSRFToken": xtoken,
          },
          type: "post",
          data: {
              reward_type: reward_type,
              adid: adidd,
          },
          error: function (value) {
              reject(value);
          },
          success: function (value) {
              resolve(value);
          },
      });
  });
}