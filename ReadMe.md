CLOSING THE VIDEO FINGERPRINTING LOOPHOLE ONCE AND FOR ALL!

--------------------------------------------------------------------------------
  1. BACKGROUND: HOW ADAPTIVE BITRATE (ABR) STREAMING WORKS
--------------------------------------------------------------------------------

Modern video platforms (YouTube, Netflix, DASH-based players) use MPEG-DASH or
HLS: the video is encoded ahead of time at multiple bitrate/quality levels, then
sliced into fixed-duration "segments" (typically 2–6 seconds each). A segment is
a self-contained ISOBMFF (MP4) or MPEG-TS chunk that the browser can decode and
play independently.

During playback, the player maintains an in-memory media buffer. The ABR
algorithm continuously monitors the buffer level and available bandwidth, then
decides which quality representation to download next. Segments are fetched on
demand: when the buffer gets low the player downloads more; when the buffer is
full enough it waits.

The result is a distinctive DOWNLOAD PATTERN on the network:

  - Segments arrive in discrete bursts separated by idle periods.
  - Each burst carries N consecutive segment files.
  - Segment file sizes are DETERMINISTIC: the same video, encoded at the same
    quality, always produces identical byte-size sequences.
  - The timing of bursts is semi-deterministic: buffer dynamics are driven by
    real-time playback, so the player re-downloads at roughly the same wall-clock
    moments regardless of who is watching.

This combination — fixed sizes, predictable timing — is what makes the attack
possible.


--------------------------------------------------------------------------------
  2. THE FINGERPRINTING ATTACK
--------------------------------------------------------------------------------

2.1  THREAT MODEL
-----------------
An adversary is a PASSIVE OBSERVER on the network path: a Wi-Fi access point
operator, a network ISP, a malicious router, or even a side-channel observer
who can infer traffic volume via power consumption or electromagnetic leakage.

The adversary can see:
  - Timestamps of HTTP requests and responses
  - Size (in bytes) of each response
  - Inter-request intervals

The adversary CANNOT see:
  - Content of the payload (TLS protects it)
  - The URL if using HTTPS (SNI reveals the domain, not the video ID)

2.2  HOW THE ATTACK WORKS
--------------------------
  Step 1 — BUILD A FINGERPRINT DATABASE
  The adversary downloads every video they want to identify and records the
  exact sequence of segment byte-sizes at each quality level. This is the
  "fingerprint library". For a library of V videos, each with Q quality levels
  and S segments:
    fingerprints = V × Q sequences, each of length S

  Step 2 — OBSERVE THE VICTIM
  The adversary passively records the victim's download events: a time series
  of (timestamp, bytes_received) pairs.

  Step 3 — CLASSIFY VIA PATTERN MATCHING
  The observed sequence is matched against the fingerprint library using
  similarity metrics (edit distance, DTW, k-NN classifiers). Because segment
  sizes are unique and deterministic, classification accuracy in academic
  studies exceeds 99% for unprotected streams.

2.3  WHY IT IS HARD TO PREVENT NAIVELY
---------------------------------------
Simply using HTTPS is not enough — the attack exploits metadata (sizes and
timing), not content. Constant-rate streaming (padding every response to the
same size) would destroy the fingerprint but wastes enormous bandwidth. The
challenge is to obfuscate the observable pattern while adding minimal overhead.


--------------------------------------------------------------------------------
  3. MITIGATION STRATEGY 1 — RANDOMISED HEARTBEAT  (n ∈ {0, 1, 2})
--------------------------------------------------------------------------------

3.1  CORE IDEA
--------------
Replace the ABR algorithm's natural download schedule with a FIXED-INTERVAL
BURST CLOCK (the "heartbeat"). At each tick of the clock, the player downloads
n segments, where n is drawn uniformly at random from {0, 1, 2}. The heartbeat
period equals one segment duration (e.g., 4 seconds), so in expectation the
player downloads 1 segment per period — matching the real-time playback rate.

3.2  LOGIC
----------
  Every heartbeat_interval seconds:
    n ← random choice from {0, 1, 2}  
    n consecutive segments

  The buffer is managed with four zones:
    buffer < threshold_low  (e.g. 8s):  UNDERFLOW — must download; n ∈ {1, 2},
                                         heartbeat = 0 (immediate reschedule)
    threshold_low  ≤ buffer < threshold_high (8–24s): NORMAL — full {0,1,2}, 25% chance of 0, 50% chance of 1, 25% chance of 2.
    threshold_high ≤ buffer < hard_cap  (24–28s): DRAIN — n ∈ {0, 1}
    buffer ≥ hard_cap (28s):             STOP — no download until buffer drains (n=0)

  The heartbeat interval is fixed, so the TIMING of bursts is uniform and
  carries no information. The only observable signal is the SIZE of each burst:
  0, 1, or 2 consecutive segments concatenated.

3.3  BANDWIDTH OVERHEAD
------------------------
  Expected segments per burst:
    E[n] = 1

  This exactly matches the average consumption rate (1 segment per period).
  Over the full video duration, the total bytes downloaded equals the unmitigated
  total — ZERO average overhead.

  Instantaneous overhead: up to +100% in a burst-of-2 interval, offset by -100%
  in a burst-of-0 interval.

  In the underflow zone (n ∈ {1, 2} only):
    E[n] = 1.5 → 50% overhead while buffer < 8s (only during fast-start)
 In the overflow zone (n ∈ {0, 1} only):
    E[n] = 0.5 → -50% overhead while buffer >= 24s and < 28s
    Once buffer is between 8s and 24s the full {0,1,2} distribution restores E[n]=1.

  Peak scenario: two consecutive n=2 bursts = 4 segments in 2 heartbeat
  intervals. This builds buffer headroom consumed by subsequent n=0 intervals.

3.4  NUMBER OF POSSIBLE FINGERPRINTS
--------------------------------------
  For a video with S total segments, the observable is an ordered sequence of
  burst sizes (n_1, n_2, ..., n_B) such that sum(n_i) = S and each n_i ∈ {0,1,2}.

  The number of distinct patterns (ignoring n=0 bursts, which add no information)
  is the number of compositions of S using parts {1, 2} — a Fibonacci sequence:
    count(S) = Fib(S + 1)

  Examples:
    S =  10 segments (40s video):    Fib(11)   ≈  89 patterns
    S =  50 segments ( ~3 min):      Fib(51)   ≈  2.0 × 10^10
    S = 150 segments (~10 min):      Fib(151)  ≈  9.9 × 10^30
    S = 900 segments ( ~1 hour):     Fib(901)  ≈  10^187

  Each distinct pattern is a different observable fingerprint. The real video
  fingerprint is buried among ~Fib(S+1) possible patterns — all generated by
  the same video. An attacker must distinguish the victim's video from all others
  while knowing that ANY of those patterns might have been generated.
  
  The attack only requires 8 segments to identify the video, so the attacker needs to multiply the size of his database by Fib(9)=34. 

  Limitation: since segment sizes are known, an attacker who knows individual
  segment byte-sizes can sometimes "de-group" a burst-of-2 back into its two
  constituent segments and partially reconstruct the original fingerprint.
  The protection is strongest when segment sizes are similar across a video.


--------------------------------------------------------------------------------
  4. MITIGATION STRATEGY 2 — RANDOMISED HEARTBEAT + DECOY DOWNLOAD
--------------------------------------------------------------------------------

4.1  CORE IDEA
--------------
Augment Strategy 1 with an additional "decoy" or "dummy" download per burst.
The decoy fetches bytes that are NOT appended to the media buffer — they are
discarded after receipt. From the adversary's perspective, both the real segments
and the decoy are indistinguishable, because both appear as ordinary HTTPS
response bodies of some byte size.

4.2  LOGIC
----------
  Every heartbeat_interval seconds:
    n     ← random from {0, 1, 2}       (real segments to play)
    d     ← random from {0, 1}          (decoy segments to fetch and discard with a probability of 20% to happen)
    download (n real segments) + (d decoy segments)

  The decoy can be:
    a)  A segment from the same video at a DIFFERENT quality level.
    b)  A segment from a DIFFERENT video entirely (requires a secondary stream).
    c)  A synthetic random byte range from any URL with CORS permission.

  In all cases the decoy bytes transit the network and are visible to the
  observer, but are never decoded or played.

4.3  BANDWIDTH OVERHEAD
------------------------
  With d uniform on {0.3, 0.7}:
    E[decoy] = P(decoy occurs) × E[decoy size | occurs]
         = 0.20 × 0.5
         = 0.10 segments per burst

  This is a 20% chance of having 50% bandwidth overhead in a burst, which means a 10% additional bandwidth overhead. 
  
  However, the choice of 20% is only an assumption, it could be more or less. Since the attack needs 8 segments to identify a video, a decoy every 8 segments is enough in theory. Therefore, the total bandwidth overhead will be reduced to 6.25%.
  
  Unlike Strategy 1, the decoy bytes are wasted: they do not reduce future downloads. The player still needs to download all S real segments.

  The overhead is always "pure waste" — decoy bytes are never reused. This
  makes Strategy 2 the most expensive mitigation in terms of bandwidth.

4.4  NUMBER OF POSSIBLE FINGERPRINTS 
--------------------------------------
  For each burst, the observable is the sum (n_i + d_i) bytes. The adversary
  sees a total burst size but cannot easily separate real from decoy.

  If d can take values from a library of D possible decoy segment sizes, then
  each burst (n ∈ {0,1,2}, d ∈ D) produces a combined size that could
  correspond to many (n, d) pairs.

  In theory, d is a real number between [0.3, 0.7], which gives an infinite number of possibilities. But if we prefer to limit it to one digit after the coma (floor) {0.3, 0.4, 0.5, 0.6, 0.7] we will have |D| = 5 possible decoy sizes. Therefore, at each burst, we have 17 different possibilities:
  - Case 1: downloading 0 segment without decoy (not counted as a burst and not counted in the fingerprint)
  - Case 2: downloading 0 segments + decoy (5 options)
  - Case 3: downloading 1 segment without decoy (1 option)
  - Case 4: downloading 1 segment + decoy (5 options) 
  - Case 5: downloading 2 segments without decoy (1 option)
  - Case 6: downloading 2 segments + decoy (5 options) 
  
  Let S be the total number of segments.
  We assume that the total number of bursts (B) is finite, otherwise the fingerprint can have an infinite number of (0 segments + decoy).
  
  let k0 be the number of 0-segment downloads (with and without decoy), 
  let k1 be the number of 1-segment downloads (with and without decoy), 
  and k2 the number of 2-segments downloads (with and without decoy).
  
  We have these constraints: 
  c1: k1 + 2k2 = S
  c2: k0 + k1 + k2 = B
  c3: k0 = B - S, with k0 = 0 if B <= S
  
  from c1 and c2 we have that the total possible combinations of bursts is a permutation with repetitions problem, so the total count is: eq1: (B!)/(k0!*k1!*k2!)
  e.g: If we have 3 bursts, with k0=1, k1=1, and k2=1; then we have 3!/1!1!1! = 6 possible permutations: (0,1,2), (0,2,1), (1,0,2), (1,2,0), (2,0,1), (2,1,0).
  
  Now independently, for each burst, we have 6 options: no decoy, or decoy (with 5 sizes).
  Since the probability of decoying is independent from the burst, so the total possibilities of decoys in B bursts is: eq2: 6*6*..*6 = 6^B.
  e.g: for two bursts (1, 2), we have 6*6=36 possibilities.
  
  Since the two events are independent, we combine eq1 and eq2 by multiplying them:
  so all possible combinations of bursts are, eq3: (B! * 6^B)/(k0!*k1!*k2!)
  However, since we are constrained by c1, then the total combinations is the sum over all valid (k1, k2). 
Therefore, the total number of fingerprints, let it be T(S,B) is:
T(N,B) = Sum_{k1+2k2=S} (6^B * ((B!)/(k0!*k1!*k2!)))

simplified to: T(S,B) ≈ 6^B * (polynomial in B), and lower bounded to 6^B because (B!)/(k0!*k1!*k2!) is >= 1. (can be proven)

This might further be approximated assymptotically if we show the generating function. 

Final E.g:
Since we download 1 segment in average, than B ≈ S. And since the attack requires only S = 8 (B ≈ 8 bursts), we get:
    fingerprint space ≈ 6^8 = 1.679.616 

  Compared to Strategy 1 (multiplied by 34 for S=8), the decoy multiplies the
  fingerprint space exponentially by roughly 6^8, a large improvement in obfuscation
  depth, at the cost of permanent bandwidth waste.


--------------------------------------------------------------------------------
  5. MITIGATION STRATEGY 3 — CONTINUOUS BYTE-RANGE (HTTP Range Requests)
--------------------------------------------------------------------------------

5.1  CORE IDEA
--------------
Instead of downloading whole segments, the player issues HTTP Range requests
(byte offsets within a segment URL). This allows downloading a CONTINUOUS,
non-integer amount of data per burst. The burst size f is drawn from a
continuous uniform distribution over [0, 2] (measured in "segment equivalents"),
so the adversary observes byte counts that never align with segment boundaries.

The key insight is that by splitting along ARBITRARY BYTE OFFSETS rather than
segment boundaries, the observable sequence becomes a continuous-valued signal
with no discrete structure for a classifier to anchor on.

5.2  LOGIC
----------
  Every heartbeat_interval:
    f ← Uniform[0, 2]       (continuous float, e.g. 1.3 means "1 full + 30%")
    n ← floor(f)            (number of complete segments)
    r ← f − n               (fractional portion of the next segment)

  Burst execution:
    1. If a CARRY-OVER exists (partial segment from previous burst), COMPLETE it
       first by fetching its remaining bytes (byte offset B_prev to end).
       This takes priority over everything — it ensures no MSE buffer gap.

    2. Download n complete segments using Range: bytes=0- (full file).

    3. If r > 0, fetch the FIRST (r × segment_size_bytes) bytes of the next
       segment using Range: bytes=0-(r × size − 1).
       Store these bytes as carry-over. Do NOT inject into the media buffer yet.

  Next burst: step 1 injects the previously stored carry-over before rolling
  a new f. The segment is ALWAYS completed within the next single burst, so
  no segment is ever split across more than two bursts.

  Audio and video streams share the SAME f value per cycle (via a handshake
  mechanism: whichever stream's ScheduleController fires first becomes "leader"
  and stores f; the other reads it). Both streams then apply n and r
  independently to their own segment sizes:
    Video: injects r × video_segment_size bytes
    Audio: injects r × audio_segment_size bytes
  The fractional split r is IDENTICAL for both streams, achieving synchronised
  partial injection even though audio and video segments differ in byte size.

5.3  BANDWIDTH OVERHEAD
------------------------
  E[f] = E[Uniform[0,2]] = 1

  Over the full video, the player downloads exactly S segments worth of bytes
  in expectation — ZERO average overhead in terms of payload data.

  All partial bytes (carry-overs) are always completed and used. There are
  no wasted bytes.

  The only overhead is from extra HTTP request metadata:
    - Each split generates 2 Range requests where normally 1 would suffice.
    - HTTP/1.1 headers: ~200–500 bytes per request.
    - For a typical 500 KB segment: 500 bytes / 500,000 bytes ≈ 0.1% overhead.
    - This is negligible.

  With HTTP/2 multiplexing, the header overhead is compressed further.

5.4  NUMBER OF POSSIBLE FINGERPRINTS
--------------------------------------
  Each burst downloads exactly (r × segment_size) bytes at the split point,
  where r is continuous in (0, 1). This is a REAL-VALUED observation.

  For a segment of size W bytes, the number of distinct observable split points
  is W (one per byte offset). In practice the server honours byte-exact Range
  responses, so the observable has W distinct values per split.

  Over a video with S segments and B ≈ S bursts, the fingerprint space is:
    fingerprint_space ≈ W^S

  Examples (W = 500,000 bytes = 500 KB average segment):
    S =  10 segments:    500,000^10   ≈ 10^57
    S =  50 segments:    500,000^50   ≈ 10^287
    S = 150 segments:    500,000^150  ≈ 10^862
    S = 900 segments:    500,000^900  ≈ 10^5173

And assuming S=8, we have 500,000^8 ≈ 10^45
  Compared with Strategy 1 for S=9: Fib(9) ≈ 34, and Strategy 2 for 6^8,
  Strategy 3 achieves a factor of ≈10^44 larger fingerprint
  space, making it computationally infeasible to build a classifier that works
  on individual fingerprints.

  Why the continuous distribution matters:
    Strategy 1 produces discrete burst sizes (sums of 0–2 segment sizes).
    A classifier can exploit the discrete structure to enumerate candidates.
    Strategy 3 produces burst sizes from a continuous distribution, so no
    two bursts from the same video are likely to produce the same byte count.
    The adversary cannot even reliably detect where one segment ends and the
    next begins, let alone match the sequence to a known fingerprint.


--------------------------------------------------------------------------------
  6. COMPARATIVE SUMMARY
--------------------------------------------------------------------------------

  +-----------------------+------------------+-----------------+----------------+
  | Property              | Strategy 1       | Strategy 2      | Strategy 3     |
  |                       | Heartbeat n∈{0,2}| Heartbeat+Decoy | Byte-Range     |
  +-----------------------+------------------+-----------------+----------------+
  | Download granularity  | Whole segments   | Whole segments  | Arbitrary bytes|
  | Burst size            | Discrete {0,1,2} | Discrete+decoy  | Continuous     |
  | Avg bandwidth overhead| ~0%              | +6.25% to +10%   | ~0%            |
  | Wasted bytes          | None             | Decoy bytes      | None           |
  | Fingerprint space (S) | Fib(S+1) ≈ φ^S   | (3·|D|)^S       | W^S            |
  |   S=150 example       | ~10^30           | ~10^371 (|D|=100)| ~10^862       |
  | Timing obfuscation    | Fixed heartbeat  | Fixed heartbeat  | Fixed heartbeat|
  | Segment boundary leak | Yes (burst=sum)  | Partial (decoy)  | No             |
  | Complexity of impl.   | Low              | Medium          | High           |
  | Risk of buffer stall  | Low (n≥1 in UF) | Low             | Low (carry-over|
  |                       |                  |                 | always complete)|
  +-----------------------+------------------+-----------------+----------------+

  UF = underflow zone (buffer < threshold).
  φ ≈ 1.618 (golden ratio), W = average segment size in bytes.

  Notes:
    - All three strategies share the same FIXED HEARTBEAT clock, which is the
      primary timing obfuscation. Without the heartbeat, burst intervals would
      still leak buffer dynamics.
    - Strategy 2's overhead is permanent and proportional to the decoy rate.
      For bandwidth-constrained networks (mobile, metered connections) this is
      a significant cost.
    - Strategy 3's ~10^862 fingerprint space effectively means that even if an
      adversary has the complete video segment-size database, they cannot match
      a recorded trace to its source without infeasible computation.


--------------------------------------------------------------------------------
  7. IMPLEMENTATION DETAILS — DASH.JS PORT
--------------------------------------------------------------------------------

7.1  ARCHITECTURE
-----------------
The dash.js port implements Strategies 1 and 3 in a buffer-zone-aware manner:

  Buffer < 8s   (UNDERFLOW zone):  Strategy 1 with n ∈ {1, 2}
                                    heartbeat = 0 (immediate: fill fast)
  Buffer 8–24s  (BUFFERED zone):   Strategy 3, splitting segments with byte range http
                                    heartbeat = segment_duration ms
  Buffer 24–28s (DRAIN zone):      No download 
  Buffer ≥ 28s  (HARD CAP):        No download 

7.2  KEY FILES
--------------
  src/streaming/controllers/ScheduleController.js
    - Drives the heartbeat timer and zone detection
    - Coordinates audio/video f-value sharing (leader/follower handshake)
    - Owns mitigation state: mitigation_burstActive, mitigation_burstSegmentsLeft,
      mitigation_byteRangeActive_, mitigation_generation_
    - startScheduleTimer(): sets the next tick (does NOT reset burst state)
    - clearScheduleTimer(): full abort (seek/quality-switch paths only)
    - mitigationBurstLoopDone(): called by StreamProcessor when a burst loop ends
    - mitigationNotifyAppend(): called after MSE append completes (heartbeat guard)

  src/streaming/StreamProcessor.js
    - runMitigationBurstLoop(f, heartbeatMs): implements the byte-range burst
      Part A: always completes carry-over first
      Part B: n = floor(f) complete segments, r = frac(f) partial segment
    - hasMitigationCarryOver(): boolean, used by carry-over priority guard
    - abortMitigationFetch(): cancels in-flight Range fetch on seek/reset

7.3  CARRY-OVER MECHANISM
--------------------------
When r > 0, the partial bytes (first r × size bytes of the next segment) are
stored in mitigation_carryRequest_ / mitigation_carryBytes_ / mitigation_carryByteOffset_.
At the NEXT burst's Part A, the stored bytes + the remaining tail are concatenated
into a complete segment and injected into the MSE SourceBuffer as if it had been
a normal 200 OK download.

A carry-over priority guard in _schedule() ensures that if the buffer drops
below the 8s threshold WHILE a carry-over is pending, the system completes the
carry-over (f=0, heartbeat=0) before entering the normal underflow strategy.
This prevents MSE gaps that would cause video skips.

7.4  GENERATION COUNTER
------------------------
mitigation_generation_ is incremented on every clearScheduleTimer() call
(seek, quality switch, destroy). Each runMitigationBurstLoop() captures the
generation at start and checks it in the finally block before calling
mitigationBurstLoopDone(). If the generation changed mid-fetch (seek happened
during an in-flight Range request), the stale loop exits silently without
rescheduling — preventing ghost downloads from interfering with the new playback
position.

7.5  SHARED DICE (AUDIO/VIDEO SYNCHRONISATION)
-----------------------------------------------
Audio and video are managed by separate ScheduleController instances. To ensure
both streams split at the SAME fractional offset r, a module-level Map
(_mitigationShared) acts as a handshake mailbox keyed by media context ID.

  Leader (whichever fires first):  draws f, stores it in _mitigationShared[ctx]
  Follower (the other stream):     reads f from _mitigationShared[ctx]

  After both have read, the entry is cleared for the next cycle.

Result: both audio and video use the same (n, r). Each then independently
multiplies r by its own segment size in bytes, so the byte split point differs
between streams (audio segment is smaller) but the FRACTIONAL position is the
same. On the network, both streams emit their carry-over and tail at the same
logical burst boundary — synchronised playback is preserved.


--------------------------------------------------------------------------------
  8. IMPLEMENTATION DETAILS — SHAKA PLAYER PORT
--------------------------------------------------------------------------------

The same Strategies 1 and 3 were also implemented in Shaka Player, which served
as the first prototype before the dash.js port was developed. Strategy 2 (decoy
downloads) was designed and analysed but not implemented in either player.

8.1  ARCHITECTURE
-----------------
Unlike the dash.js port — which splits control across ScheduleController.js and
StreamProcessor.js — the entire Shaka mitigation lives in a single file:

  lib/media/streaming_engine.js

All logic is embedded directly in the player's update_() scheduling loop under
a section labelled "Bloc 4: Randomised download decision for this cycle." There
is no separate controller class; the mitigation runs inline every time
StreamingEngine decides whether to fetch the next segment.

Buffer zones and thresholds are identical to the dash.js port:
  Buffer < 8s   (UNDERFLOW):  Strategy 1 — n ∈ {1, 2}, heartbeat = 0
  Buffer 8–24s  (NORMAL):     Strategy 3 — f ~ Uniform[0, 2], E[f] = 1.0
  Buffer 24–28s (DRAIN):      Strategy 3 — f ~ Uniform[0, 1], E[f] = 0.5
  Buffer ≥ 28s  (HARD CAP):   f = 0, no download

8.2  SHARED MAILBOX (AUDIO/VIDEO SYNC)
---------------------------------------
The shared dice is implemented directly on the StreamingEngine class:

  this.mitigation_sharedDecision_   // -1 = no decision posted yet
  this.mitigation_decisionMaker_    // stream type that acted as leader

The first stream to reach Bloc 4 each cycle ("Leader") draws f (or n) and
stores it in the mailbox. The second stream ("Follower") reads and clears it.
Both streams therefore apply the same fractional split to their own segment
sizes. The mailbox sits at class level because both audio and video
MediaState objects share the same StreamingEngine instance — a simpler
structure than the module-level Map used in the dash.js port.

8.3  UNDERFLOW ZONE — INTEGER BURST (STRATEGY 1)
-------------------------------------------------
When buffer < 8s, n ∈ {1, 2} is drawn (50-50) and a dedicated async closure
`runBurstLoop()` is launched. It calls Shaka's own `fetchAndAppend_()` pipeline
for each of the n segments — the full Shaka path including ABR quality
selection, init-segment handling, and MSE append. No byte-range requests are
used here; each segment arrives as a standard 200 OK.

The finally block of `runBurstLoop()` schedules the next heartbeat:
  heartbeat = 0              if buffer is still < 8s (fast-start)
  heartbeat = maxSegDuration if buffer ≥ 8s (normal pacing)

A `mitigation_inBurstLoop_` flag on each MediaState prevents re-entry while
an async burst is running — Shaka's equivalent of the generation counter used
in the dash.js port.

8.4  BUFFERED ZONE — BYTE-RANGE BURST (STRATEGY 3)
---------------------------------------------------
When buffer ≥ 8s the byte-range loop runs. The implementation follows the same
two-part structure as the dash.js port:

  Part A — carry-over completion:
    If a partial segment was stashed from the previous cycle (mitigation_carryRef_,
    mitigation_carryByteOffset_, mitigation_carryData_), fetch its remaining
    tail via mitigation_fetchRange_() and assemble the full segment before
    processing any new budget.

  Part B — new byte-budget allocation:
    The byte budget is mitigation_byteBudget = f × segSizeEstimate.
    Segments are fetched via mitigation_fetchRange_() until the budget is
    exhausted, with the last segment potentially split into a new carry-over.

  Note: the Shaka port uses the original BYTE-BUDGET model (f × segSize bytes)
  rather than the cleaner n+r model (floor(f) complete + frac(f) partial)
  developed later in the dash.js port. The practical effect is the same, but
  the n+r formulation is more explicit about the integer/fractional split.

8.5  mitigation_fetchRange_()
------------------------------
Byte-range requests go through a dedicated helper:

  async mitigation_fetchRange_(mediaState, reference, startOffset, endOffset)

It constructs a Range header using shaka.net.NetworkingUtils.createSegmentRequest()
with explicit byte offsets, then awaits the response via Shaka's NetworkingEngine.

If the server returns 200 instead of 206 (no Range support):
  - For separate-file segments (segBase === 0): the response is sliced manually
    to the requested byte window — the full content was already downloaded, so
    only the correct slice is passed to MSE.
  - For byte-range container files (segBase > 0): a warning is logged and the
    data is used as-is (server-side Range support is a DASH requirement for
    this case).

8.6  KEY DIFFERENCES BETWEEN SHAKA AND DASH.JS PORTS
------------------------------------------------------

  +---------------------------+---------------------+-------------------------+
  | Aspect                    | Shaka Player        | dash.js v5.2.1          |
  +---------------------------+---------------------+-------------------------+
  | Mitigation entry point    | update_() inline    | ScheduleController.js   |
  | Fetch implementation      | StreamProcessor.js  | StreamProcessor.js      |
  |                           | (Bloc 4)            |                         |
  | Underflow fetch path      | fetchAndAppend_()   | _scheduleNextRequest()  |
  |                           | (full Shaka ABR     | (normal dash.js path)   |
  |                           |  pipeline)          |                         |
  | Budget model (buffered)   | Byte-budget         | n + r (floor + frac)    |
  |                           | (f × segSizeEst)    | (more explicit)         |
  | Parallel fetches          | Sequential (await   | Parallel (Promise.all)  |
  |                           |  per fetch)         | — added in dash.js port |
  | Stale-loop protection     | inBurstLoop_ flag   | Generation counter      |
  | Shared mailbox location   | Class-level fields  | Module-level Map        |
  | 200 fallback handling     | Manual slice if     | Not needed (separate-   |
  |                           | server ignores Range|  file segments only)    |
  | Strategy 2 (decoy)        | Not implemented     | Not implemented         |
  +---------------------------+---------------------+-------------------------+

The most significant improvement in the dash.js port is parallel fetching:
all Range requests within a burst (carry-over tail + complete segments +
partial) are issued simultaneously via Promise.all. Results are injected into
MSE in presentation order afterwards. This prevents the network observer from
seeing the individual per-segment request/response chain inside a burst —
the burst appears as a single overlapping transfer, further obscuring the
segment boundaries.


--------------------------------------------------------------------------------
  9. REFERENCES AND FURTHER READING
--------------------------------------------------------------------------------

  [1] Schuster, R. et al. "Beauty and the Burst: Remote Identification of
      Encrypted Video Streams." USENIX Security 2017.

  [2] Reed, A., Kranch, M. "Identifying HTTPS-Protected Netflix Videos in
      Real-Time." CODASPY 2017.

  [3] Saponas, T.S. et al. "Devices That Tell on You: Privacy Trends in
      Consumer Ubiquitous Computing." USENIX Security 2007.

  [4] Hoang, N.P. et al. "Leveraging Encrypted SNI to Defeat Website
      Fingerprinting Attacks." (Related: SNI alone insufficient)

  [5] Original Shaka Player mitigation prototype from which this dash.js port
      was derived. Implements Randomised Heartbeat and Continuous Byte-Range
      strategies for MPEG-DASH playback.
      
  [6] Björklund, M., & Duvignau, R. (2025). Endangered Privacy:{Large-Scale} Monitoring of Video Streaming Services. In 34th USENIX Security Symposium (USENIX Security 25) (pp. 6581-6597).
  
  [7] Witwer, E., Hasselquist, D., Pulls, T., & Carlsson, N. (2026). Dodge: A Client-Side Framework for Application-Layer Video Fingerprinting Defenses. Proceedings on Privacy Enhancing Technologies YYYY (X), 1, 16

================================================================================
