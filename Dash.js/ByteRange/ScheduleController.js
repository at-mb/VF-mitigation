/**
 * The copyright in this software is being made available under the BSD License,
 * included below. This software may be subject to other third party and contributor
 * rights, including patent rights, and no such rights are granted under this license.
 *
 * Copyright (c) 2013, Dash Industry Forum.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *  * Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *  * Neither the name of Dash Industry Forum nor the names of its
 *  contributors may be used to endorse or promote products derived from this software
 *  without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY
 *  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */
import Constants from '../constants/Constants.js';
import FragmentModel from '../models/FragmentModel.js';
import EventBus from '../../core/EventBus.js';
import Events from '../../core/events/Events.js';
import FactoryMaker from '../../core/FactoryMaker.js';
import Debug from '../../core/Debug.js';
import MetricsConstants from '../constants/MetricsConstants.js';
import MediaPlayerEvents from '../MediaPlayerEvents.js';

// --- Fingerprint Mitigation: Shared Handshake State ---
// One entry per player context: { sharedDecision: -1 = empty | 0/1/2, decisionMaker: null | type }
const _mitigationShared = new Map();

const MITIGATION_UNDERFLOW_THRESHOLD = 8;   // s  — refill zone
const MITIGATION_OVERFLOW_THRESHOLD = 24;   // s  — drain zone
const MITIGATION_HARD_CAP_THRESHOLD = 28;   // s  — stop zone

function ScheduleController(config) {

    config = config || {};
    const abrController = config.abrController;
    const bufferController = config.bufferController;
    const context = this.context;
    const dashMetrics = config.dashMetrics;
    const eventBus = EventBus(context).getInstance();
    const fragmentModel = config.fragmentModel;
    const mediaPlayerModel = config.mediaPlayerModel;
    const playbackController = config.playbackController;
    const representationController = config.representationController
    const settings = config.settings;
    const textController = config.textController;
    const type = config.type;

    let hasVideoTrack,
        initSegmentRequired,
        instance,
        lastFragmentRequest,
        lastInitializedRepresentationId,
        logger,
        managedMediaSourceAllowsRequest,
        scheduleTimeout,
        streamInfo,
        streamProcessor_,
        switchTrack,
        timeToLoadDelay,
        shouldCheckPlaybackQuality,
        // --- Fingerprint Mitigation State ---
        mitigation_burstActive,
        mitigation_burstSegmentsLeft,
        mitigation_heartbeatMs,
        mitigation_byteRangeActive_,
        mitigation_generation_;

    function setup() {
        logger = Debug(context).getInstance().getLogger(instance);
        resetInitialSettings();
        streamInfo = config.streamInfo;
    }

    function initialize(_hasVideoTrack) {
        hasVideoTrack = _hasVideoTrack;

        // Register shared handshake mailbox for this player context (once per context)
        if (!_mitigationShared.has(context)) {
            _mitigationShared.set(context, { sharedDecision: -1, decisionMaker: null });
        }

        eventBus.on(Events.URL_RESOLUTION_FAILED, _onURLResolutionFailed, instance);
        eventBus.on(MediaPlayerEvents.PLAYBACK_STARTED, _onPlaybackStarted, instance);
        eventBus.on(MediaPlayerEvents.PLAYBACK_RATE_CHANGED, _onPlaybackRateChanged, instance);
        eventBus.on(MediaPlayerEvents.PLAYBACK_TIME_UPDATED, _onPlaybackTimeUpdated, instance);
        eventBus.on(MediaPlayerEvents.MANAGED_MEDIA_SOURCE_START_STREAMING, _onManagedMediaSourceStartStreaming, instance);
        eventBus.on(MediaPlayerEvents.MANAGED_MEDIA_SOURCE_END_STREAMING, _onManagedMediaSourceEndStreaming, instance);
    }

    function _onManagedMediaSourceStartStreaming() {
        managedMediaSourceAllowsRequest = true;
    }

    function _onManagedMediaSourceEndStreaming() {
        managedMediaSourceAllowsRequest = false;
    }

    function getType() {
        return type;
    }

    function getStreamId() {
        return streamInfo.id;
    }

    function startScheduleTimer(value) {
        //return if both buffering and playback have ended
        if (bufferController.getIsBufferingCompleted()) {
            return;
        }

        // Only cancel the pending timer — do NOT touch mitigation burst state.
        // Mitigation state is reset explicitly by mitigationBurstLoopDone /
        // mitigationNotifyAppend, and aborted by clearScheduleTimer on seeks.
        if (scheduleTimeout) {
            clearTimeout(scheduleTimeout);
            scheduleTimeout = null;
        }
        const timeoutValue = !isNaN(value) ? value : 0;
        scheduleTimeout = setTimeout(_schedule, timeoutValue);
    }

    function clearScheduleTimer() {
        if (scheduleTimeout) {
            clearTimeout(scheduleTimeout);
            scheduleTimeout = null;
        }
        // Full abort: reset burst state and invalidate any running async byte-range loop.
        // Called on seeks, quality switches, URL failures, and destroy — NOT from startScheduleTimer.
        mitigation_burstActive = false;
        mitigation_burstSegmentsLeft = 0;
        mitigation_byteRangeActive_ = false;
        mitigation_generation_++;
        if (streamProcessor_) streamProcessor_.abortMitigationFetch();
    }

    /**
     * Schedule the request for an init or a media segment.
     * Implements the Randomised Heartbeat fingerprint mitigation:
     *   – Fixed inter-burst interval destroys the timing side-channel
     *   – Randomised 0/1/2 segments per cycle based on buffer health
     *   – Handshake keeps audio and video in lockstep
     */
    function _schedule() {
        const scheduleTimeout = mediaPlayerModel.getScheduleTimeout();
        try {
            if (_shouldClearScheduleTimer()) {
                clearScheduleTimer();
                return;
            }

            if (mitigation_burstActive) {
                if (mitigation_byteRangeActive_) {
                    return;  // async byte-range loop is running; don't interfere
                }
                // Called via _noValidRequest() retry — re-issue without changing burst state
                if (_mitigationShouldSchedule()) {
                    _scheduleNextRequest();
                } else {
                    startScheduleTimer(scheduleTimeout);
                }
                return;
            }

            // New cycle: decide burst size and heartbeat interval
            if (!_mitigationShouldSchedule()) {
                startScheduleTimer(scheduleTimeout);
                return;
            }

            const bufferLevel = bufferController ? bufferController.getBufferLevel() : 0;
            const rep = representationController ? representationController.getCurrentRepresentation() : null;
            const maxSegDur = (rep && !isNaN(rep.segmentDuration) && rep.segmentDuration > 0)
                ? rep.segmentDuration : 4;
            mitigation_heartbeatMs = bufferLevel < MITIGATION_UNDERFLOW_THRESHOLD
                ? 0 : maxSegDur * 1000;

            // Carry-over priority: if a partial segment was stored in a previous burst,
            // complete it NOW regardless of the current buffer zone.  Without this guard,
            // dropping below the underflow threshold while carry-over is pending would fire
            // _scheduleNextRequest() for the next segment, creating a gap in the MSE buffer
            // (the carry-over segment was never injected) and causing the video to skip.
            //
            // In the underflow zone we pass f=0 so only Part A (carry-over completion) runs
            // and Part B is skipped entirely.  The immediately-rescheduled burst (heartbeat=0)
            // then downloads 1 or 2 whole segments via the normal underflow path.
            //
            // In the buffered zone carry-over is already handled correctly by runMitigationBurstLoop
            // Part A, so we fall through to the normal buffered-zone branch below.
            if (bufferLevel < MITIGATION_UNDERFLOW_THRESHOLD &&
                    streamProcessor_ && streamProcessor_.hasMitigationCarryOver()) {
                mitigation_burstActive = true;
                mitigation_byteRangeActive_ = true;
                streamProcessor_.runMitigationBurstLoop(0, 0);  // Part A only; heartbeat=0 → immediate reschedule
                return;
            }

            if (bufferLevel < MITIGATION_UNDERFLOW_THRESHOLD) {
                // Refill zone: discrete 1 or 2 whole segments (fast-start, no carry-over)
                const n = _mitigationDecideUnderflow();
                console.log(`[mitigation][${type}] UNDERFLOW zone: bufferLevel=${bufferLevel.toFixed(2)}s, burst=${n} segments`);
                mitigation_burstActive = true;
                mitigation_burstSegmentsLeft = n - 1;
                _scheduleNextRequest();
            } else {
                // Buffered zone: continuous byte-range strategy
                const f = _mitigationDecideBuffered(bufferLevel);
                console.log(`[mitigation][${type}] BUFFERED zone: bufferLevel=${bufferLevel.toFixed(2)}s, f=${f.toFixed(3)}, heartbeat=${mitigation_heartbeatMs}ms`);
                if (f === 0 || !streamProcessor_) {
                    startScheduleTimer(mitigation_heartbeatMs);
                    return;
                }
                mitigation_burstActive = true;
                mitigation_byteRangeActive_ = true;
                streamProcessor_.runMitigationBurstLoop(f, mitigation_heartbeatMs);
            }
        } catch (e) {
            startScheduleTimer(scheduleTimeout);
        }
    }

    /**
     * Underflow zone decision: always 1 or 2 segments (fast-start path).
     * Leader rolls; Follower copies via the shared mailbox.
     * @return {number} 1 or 2
     */
    function _mitigationDecideUnderflow() {
        const shared = _mitigationShared.get(context);
        if (!shared) return 1;
        let n;
        if (shared.sharedDecision >= 0 && shared.decisionMaker !== type) {
            n = shared.sharedDecision;
            shared.sharedDecision = -1;
            shared.decisionMaker = null;
        } else {
            n = Math.random() < 0.5 ? 1 : 2;
            shared.sharedDecision = n;
            shared.decisionMaker = type;
        }
        return n;
    }

    /**
     * Buffered zone decision: a float f from a Uniform distribution.
     * f * segmentSize gives the byte budget for the cycle.
     * Leader rolls; Follower copies via the shared mailbox.
     * @param {number} bufferLevel
     * @return {number} float in [0, 2]
     */
    function _mitigationDecideBuffered(bufferLevel) {
        const shared = _mitigationShared.get(context);
        if (!shared) return 1;
        let f;
        if (shared.sharedDecision >= 0 && shared.decisionMaker !== type) {
            f = shared.sharedDecision;
            shared.sharedDecision = -1;
            shared.decisionMaker = null;
        } else {
            if (bufferLevel >= MITIGATION_HARD_CAP_THRESHOLD) {
                f = 0;                     // Hard cap: skip cycle entirely
            } else if (bufferLevel >= MITIGATION_OVERFLOW_THRESHOLD) {
                f = Math.random();         // Drain: Uniform[0, 1], expected 0.5 × segSize
            } else {
                f = Math.random() * 2;     // Obfuscation: Uniform[0, 2], expected 1.0 × segSize
            }
            shared.sharedDecision = f;
            shared.decisionMaker = type;
        }
        return f;
    }

    /**
     * Returns true if it is safe to schedule a segment request right now.
     */
    function _mitigationShouldSchedule() {
        try {
            return managedMediaSourceAllowsRequest &&
                representationController &&
                !!representationController.getCurrentRepresentation();
        } catch (e) {
            return false;
        }
    }

    /**
     * Called by StreamProcessor when a media segment has been appended to the buffer.
     * Drives burst continuation and the fixed heartbeat after the last segment of a burst.
     * For non-burst mode, falls back to the original immediate reschedule.
     */
    function mitigationNotifyAppend() {
        if (mitigation_byteRangeActive_) {
            return;  // byte-range burst loop manages its own scheduling
        }
        if (!mitigation_burstActive) {
            // Not in a burst — reschedule immediately, but only if no timer is already pending.
            // A pending timer means mitigationBurstLoopDone already set the heartbeat; a stale
            // BYTES_APPENDED_END_FRAGMENT from the injected segment must not cancel it.
            if (!scheduleTimeout) {
                startScheduleTimer(0);
            }
            return;
        }

        if (mitigation_burstSegmentsLeft > 0) {
            mitigation_burstSegmentsLeft--;
            if (_mitigationShouldSchedule()) {
                _scheduleNextRequest();  // fire next segment in burst directly
            } else {
                // Temporarily can't schedule; end burst and wait
                mitigation_burstActive = false;
                mitigation_burstSegmentsLeft = 0;
                startScheduleTimer(mediaPlayerModel.getScheduleTimeout());
            }
        } else {
            // Last segment of burst appended — wait exactly one heartbeat before next cycle
            mitigation_burstActive = false;
            startScheduleTimer(mitigation_heartbeatMs);
        }
    }

    function setStreamProcessor(sp) {
        streamProcessor_ = sp;
    }

    function getMitigationGeneration() {
        return mitigation_generation_;
    }

    /**
     * Called by StreamProcessor when the async byte-range burst loop finishes.
     * Resets burst state then fires the fixed heartbeat timer.
     * Must reset flags HERE because startScheduleTimer no longer touches mitigation state.
     */
    function mitigationBurstLoopDone(heartbeatMs) {
        mitigation_burstActive = false;
        mitigation_burstSegmentsLeft = 0;
        mitigation_byteRangeActive_ = false;
        startScheduleTimer(heartbeatMs);
    }

    function getInitSegmentRequired() {
        return initSegmentRequired;
    }

    function getLastInitializedRepresentationId() {
        return lastInitializedRepresentationId;
    }

    function _scheduleNextRequest() {
        const hasTriggeredManualQualitySwitch = abrController.handlePendingManualQualitySwitch(streamInfo.id, type);

        if (hasTriggeredManualQualitySwitch) {
            return
        }

        let qualityChange = false;
        if (shouldCheckPlaybackQuality) {
            // in case the playback quality is supposed to be changed, the corresponding StreamProcessor will update the currentRepresentation.
            // The StreamProcessor will also start the schedule timer again once the quality switch has been prepared. Consequently, we only call _getNextFragment if the quality is not changed.
            qualityChange = abrController.checkPlaybackQuality(type, streamInfo.id);
        }
        if (!qualityChange) {
            _getNextFragment();
        }
    }

    /**
     * Triggers the events to start requesting an init or a media segment. This will be picked up by the corresponding StreamProcessor.
     * @private
     */
    function _getNextFragment() {
        const currentRepresentation = representationController.getCurrentRepresentation();

        // A quality changed occured or we are switching the AdaptationSet. In that case we need to load a new init segment
        if (initSegmentRequired || currentRepresentation.id !== lastInitializedRepresentationId || switchTrack) {
            _initFragmentNeeded(currentRepresentation)
        } else {
            _mediaFragmentNeeded()
        }
    }

    function _initFragmentNeeded(currentRepresentation) {
        if (switchTrack) {
            logger.debug('Switch track for ' + type + ', representation id = ' + currentRepresentation.id);
            switchTrack = false;
        } else {
            logger.debug('Quality has changed, get init request for representationid = ' + currentRepresentation.id);
        }
        eventBus.trigger(Events.INIT_FRAGMENT_NEEDED,
            { representationId: currentRepresentation.id, sender: instance },
            { streamId: streamInfo.id, mediaType: type }
        );
        shouldCheckPlaybackQuality = false;
        initSegmentRequired = false;
    }

    function _mediaFragmentNeeded() {
        logger.debug(`Media segment needed for ${type} and stream id ${streamInfo.id}`);
        eventBus.trigger(Events.MEDIA_FRAGMENT_NEEDED,
            {},
            { streamId: streamInfo.id, mediaType: type }
        );
        shouldCheckPlaybackQuality = true;
    }

    /**
     * Check if we need to stop scheduling for now.
     * @return {boolean}
     * @private
     */
    function _shouldClearScheduleTimer() {
        try {
            return (((type === Constants.TEXT) && !textController.isTextEnabled()) ||
                (playbackController.isPaused() && (!playbackController.getStreamController().getInitialPlayback() || !playbackController.getStreamController().getAutoPlay()) && !settings.get().streaming.scheduling.scheduleWhilePaused));
        } catch (e) {
            return false;
        }
    }

    /**
     * Check if we can start scheduling the next request
     * @return {boolean}
     * @private
     */
    function _shouldScheduleNextRequest() {
        try {
            if (!managedMediaSourceAllowsRequest) {
                return false;
            }
            const currentRepresentation = representationController.getCurrentRepresentation();
            return currentRepresentation && (lastInitializedRepresentationId == null || switchTrack || _shouldBuffer());
        } catch (e) {
            return false;
        }
    }

    /**
     * Check if the current buffer level is below our buffer target.
     * @return {boolean}
     * @private
     */
    function _shouldBuffer() {
        const currentRepresentation = representationController.getCurrentRepresentation();
        if (!type || !currentRepresentation) {
            return true;
        }
        let segmentDurationToAddToBufferLevel = currentRepresentation && currentRepresentation.segmentDuration && !isNaN(currentRepresentation.segmentDuration) ? currentRepresentation.segmentDuration : 0;
        const bufferLevel = dashMetrics.getCurrentBufferLevel(type);
        const bufferTarget = getBufferTarget();

        // If the buffer target is smaller than the segment duration we do not take it into account. For low latency playback do not delay the buffering.
        if (bufferTarget <= segmentDurationToAddToBufferLevel || playbackController.getLowLatencyModeEnabled() || (type === Constants.AUDIO && hasVideoTrack)) {
            segmentDurationToAddToBufferLevel = 0;
        }

        return bufferLevel + segmentDurationToAddToBufferLevel < bufferTarget;
    }

    /**
     * Determine the buffer target depending on the type and whether we have audio and video AdaptationSets available
     * @return {number}
     */
    function getBufferTarget() {
        let bufferTarget = NaN;
        const currentRepresentation = representationController.getCurrentRepresentation();

        if (!type || !currentRepresentation) {
            return bufferTarget;
        }

        if (type === Constants.TEXT) {
            bufferTarget = _getBufferTargetForFragmentedText();
        } else if (type === Constants.AUDIO && hasVideoTrack) {
            bufferTarget = _getBufferTargetForAudio();
        } else {
            bufferTarget = _getGenericBufferTarget();
        }

        return bufferTarget;
    }

    /**
     * Returns the buffer target for fragmented text tracks
     * @return {number}
     * @private
     */
    function _getBufferTargetForFragmentedText() {
        try {
            if (textController.isTextEnabled()) {
                const currentRepresentation = representationController.getCurrentRepresentation();
                if (isNaN(currentRepresentation.fragmentDuration)) {
                    // call metrics function to have data in the latest scheduling info...
                    // if no metric, returns 0. In this case, rule will return false.
                    const schedulingInfo = dashMetrics.getCurrentSchedulingInfo(MetricsConstants.SCHEDULING_INFO);
                    return schedulingInfo ? schedulingInfo.duration : 0;
                } else {
                    return currentRepresentation.fragmentDuration;
                }
            } else { // text is disabled, rule will return false
                return 0;
            }
        } catch (e) {
            return 0;
        }
    }

    /**
     * Returns the buffer target for audio tracks in case we have a video track available as well
     * @return {number}
     * @private
     */
    function _getBufferTargetForAudio() {
        try {
            const videoBufferLevel = dashMetrics.getCurrentBufferLevel(Constants.VIDEO);
            const currentRepresentation = representationController.getCurrentRepresentation();
            // For multiperiod we need to consider that audio and video segments might have different durations.
            // This can lead to scenarios in which we completely buffered the video segments and the video buffer level for the current period is not changing anymore. However we might still need a small audio segment to finish buffering audio as well.
            // If we set the buffer time of audio equal to the video buffer time scheduling for the remaining audio segment will only be triggered when audio fragmentDuration > videoBufferLevel. That will delay preloading of the upcoming period.
            // Should find a better solution than just adding 1
            if (isNaN(currentRepresentation.fragmentDuration)) {
                return videoBufferLevel + 1;
            } else {
                return Math.max(videoBufferLevel + 1, currentRepresentation.fragmentDuration);
            }
        } catch (e) {
            return 0;
        }
    }

    /**
     * Determines the generic buffer target, for instance for video tracks or when we got an audio only stream
     * @return {number}
     * @private
     */
    function _getGenericBufferTarget() {
        try {
            const currentRepresentation = (settings.get().streaming.enhancement.enabled) ?
                representationController.getCurrentCompositeRepresentation() :
                representationController.getCurrentRepresentation();
            const streamInfo = currentRepresentation.mediaInfo.streamInfo;
            if (abrController.isPlayingAtTopQuality(currentRepresentation)) {
                const isLongFormContent = streamInfo.manifestInfo.duration >= settings.get().streaming.buffer.longFormContentDurationThreshold;
                return isLongFormContent ? settings.get().streaming.buffer.bufferTimeAtTopQualityLongForm : settings.get().streaming.buffer.bufferTimeAtTopQuality;
            } else {
                return mediaPlayerModel.getBufferTimeDefaultUnadjusted();
            }
        } catch (e) {
            return mediaPlayerModel.getBufferTimeDefaultUnadjusted();
        }
    }

    function setSwitchTrack(value) {
        switchTrack = value;
    }

    function getSwitchTrack() {
        return switchTrack;
    }

    function _onPlaybackTimeUpdated() {
        _completeQualityChange(true);
    }

    function _completeQualityChange(triggerQualityChangeRenderedEvent) {
        if (playbackController && fragmentModel) {
            const item = fragmentModel.getRequests({
                state: FragmentModel.FRAGMENT_MODEL_EXECUTED,
                time: playbackController.getTime(),
                threshold: 0
            })[0];

            if (item && playbackController.getTime() >= item.startTime) {
                if ((!lastFragmentRequest.representation || (item.representation.mediaInfo.type === lastFragmentRequest.representation.mediaInfo.type && item.representation.mediaInfo.index !== lastFragmentRequest.representation.mediaInfo.index)) && triggerQualityChangeRenderedEvent) {
                    _triggerTrackChangeRendered(item);
                }
                if ((!lastFragmentRequest.representation || (item.representation.id !== lastFragmentRequest.representation.id)) && triggerQualityChangeRenderedEvent) {
                    _triggerQualityChangeRendered(item);
                }
                lastFragmentRequest.representation = item.representation
            }
        }
    }

    function _triggerTrackChangeRendered(item) {
        logger.debug(`Track change rendered for streamId ${streamInfo.id} and type ${type}`);
        eventBus.trigger(Events.TRACK_CHANGE_RENDERED, {
            mediaType: type,
            oldMediaInfo: lastFragmentRequest && lastFragmentRequest.representation && lastFragmentRequest.representation.mediaInfo ? lastFragmentRequest.representation.mediaInfo : null,
            newMediaInfo: item.representation.mediaInfo,
            streamId: streamInfo.id
        });
    }

    function _triggerQualityChangeRendered(item) {
        logger.debug(`Quality change rendered for streamId ${streamInfo.id} and type ${type}`);
        eventBus.trigger(Events.QUALITY_CHANGE_RENDERED, {
            mediaType: type,
            oldRepresentation: lastFragmentRequest.representation ? lastFragmentRequest.representation : null,
            newRepresentation: item.representation,
            streamId: streamInfo.id
        });
    }

    function _onURLResolutionFailed() {
        fragmentModel.abortRequests();
        clearScheduleTimer();
    }

    function _onPlaybackStarted() {
        if (!settings.get().streaming.scheduling.scheduleWhilePaused) {
            startScheduleTimer();
        }
    }

    function _onPlaybackRateChanged(e) {
        dashMetrics.updatePlayListTraceMetrics({ playbackspeed: e.playbackRate.toString() });
    }

    function setTimeToLoadDelay(value) {
        timeToLoadDelay = value;
    }

    function getTimeToLoadDelay() {
        return timeToLoadDelay;
    }

    function setShouldCheckPlaybackQuality(value) {
        shouldCheckPlaybackQuality = value;
    }

    function setInitSegmentRequired(value) {
        initSegmentRequired = value;
    }

    function setLastInitializedRepresentationId(value) {
        lastInitializedRepresentationId = value;
    }

    function resetInitialSettings() {
        shouldCheckPlaybackQuality = true;
        timeToLoadDelay = 0;
        lastInitializedRepresentationId = null;
        lastFragmentRequest = {
            representation: null,
        };
        switchTrack = false;
        initSegmentRequired = false;
        managedMediaSourceAllowsRequest = true;
        mitigation_burstActive = false;
        mitigation_burstSegmentsLeft = 0;
        mitigation_heartbeatMs = 0;
        mitigation_byteRangeActive_ = false;
        mitigation_generation_ = 0;
    }

    function reset() {
        eventBus.off(Events.URL_RESOLUTION_FAILED, _onURLResolutionFailed, instance);
        eventBus.off(MediaPlayerEvents.PLAYBACK_STARTED, _onPlaybackStarted, instance);
        eventBus.off(MediaPlayerEvents.PLAYBACK_RATE_CHANGED, _onPlaybackRateChanged, instance);
        eventBus.off(MediaPlayerEvents.PLAYBACK_TIME_UPDATED, _onPlaybackTimeUpdated, instance);
        eventBus.off(MediaPlayerEvents.MANAGED_MEDIA_SOURCE_START_STREAMING, _onManagedMediaSourceStartStreaming, instance);
        eventBus.off(MediaPlayerEvents.MANAGED_MEDIA_SOURCE_END_STREAMING, _onManagedMediaSourceEndStreaming, instance);

        clearScheduleTimer();
        _completeQualityChange(false);
        resetInitialSettings();
        streamInfo = null;
    }

    function getPlaybackController() {
        return playbackController;
    }

    instance = {
        clearScheduleTimer,
        getBufferTarget,
        getInitSegmentRequired,
        getLastInitializedRepresentationId,
        getMitigationGeneration,
        getPlaybackController,
        getStreamId,
        getSwitchTrack,
        getTimeToLoadDelay,
        getType,
        initialize,
        mitigationBurstLoopDone,
        mitigationNotifyAppend,
        reset,
        setShouldCheckPlaybackQuality,
        setInitSegmentRequired,
        setLastInitializedRepresentationId,
        setStreamProcessor,
        setup,
        setSwitchTrack,
        setTimeToLoadDelay,
        startScheduleTimer,
    };

    setup();

    return instance;
}

ScheduleController.__dashjs_factory_name = 'ScheduleController';
export default FactoryMaker.getClassFactory(ScheduleController);
