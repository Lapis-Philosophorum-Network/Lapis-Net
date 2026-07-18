// Lapis Net Minimal-Browser MVP client. Plain vanilla JS, no framework, no build step - fetch()
// against the JSON routes installed by BrowserApi.kt. XSS hygiene: every place that renders
// author/text/comment content into the DOM MUST use textContent, never innerHTML - untrusted post
// text and comments must never be interpreted as markup.

// Mirrors TimelineBuilder.DEFAULT_CREDIBILITY_FILTER_THRESHOLD_MICROS on the server - used here
// only to choose a badge color, not to decide filtering (the server already decided filteredOut
// via /api/timeline's own visible() call before this client ever sees the response).
const RESOLVED_HIGH_THRESHOLD_MICROS = 250000;

// Mirrors MAX_POST_BODY_BYTES on the server (PostAnnouncement.kt) - the server enforces this as
// UTF-8 *bytes*, not JS string .length (UTF-16 code units), so non-ASCII text must be measured via
// TextEncoder here too. Using .length instead would let a user type up to this many *characters*
// of e.g. multi-byte emoji/CJK text and still get rejected by the server with a confusing 400.
const MAX_POST_BODY_BYTES = 2048;

function utf8ByteLength(text) {
  return new TextEncoder().encode(text).length;
}

const identityFingerprintEl = document.getElementById("identity-fingerprint");
const peerCountEl = document.getElementById("peer-count");
const connectForm = document.getElementById("connect-form");
const connectMultiaddrInput = document.getElementById("connect-multiaddr");
const connectStatusEl = document.getElementById("connect-status");
const composeTextEl = document.getElementById("compose-text");
const composeCountEl = document.getElementById("compose-count");
const composeSubmitButton = document.getElementById("compose-submit");
const composeStatusEl = document.getElementById("compose-status");
const includeFilteredCheckbox = document.getElementById("include-filtered");
const refreshButton = document.getElementById("refresh-button");
const timelineListEl = document.getElementById("timeline-list");
const timelineItemTemplate = document.getElementById("timeline-item-template");

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    const message = body && body.error ? body.error : `request failed: ${response.status}`;
    throw new Error(message);
  }
  return body;
}

function formatRelativeTime(epochSeconds) {
  const deltaSeconds = Math.floor(Date.now() / 1000) - epochSeconds;
  if (deltaSeconds < 5) return "just now";
  if (deltaSeconds < 60) return `${deltaSeconds}s ago`;
  const minutes = Math.floor(deltaSeconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function shortFingerprint(fingerprint) {
  if (fingerprint.length <= 16) return fingerprint;
  return `${fingerprint.slice(0, 8)}…${fingerprint.slice(-6)}`;
}

function credibilityBadgeText(post) {
  if (post.credibilityLevel === "NO_PATH") return "Unrated";
  const percent = Math.round((post.credibilityScoreMicros / 1000000) * 100);
  return post.credibilityScoreMicros >= RESOLVED_HIGH_THRESHOLD_MICROS
    ? `Trusted · ${percent}%`
    : `Low trust · ${percent}%`;
}

function credibilityBadgeClass(post) {
  // NO_PATH must always be visually distinct from a low RESOLVED score - never conflate "unknown"
  // with "distrusted". See CredibilityLevel's server-side doc comment for the full reasoning.
  if (post.credibilityLevel === "NO_PATH") return "no-path";
  return post.credibilityScoreMicros >= RESOLVED_HIGH_THRESHOLD_MICROS ? "resolved-high" : "resolved-low";
}

function ltrWeightText(post) {
  if (post.ltrRecordCount === 0 || post.ltrWeightMsat <= 0) return "No boosts yet";
  const sats = (post.ltrWeightMsat / 1000).toFixed(2);
  return `Boosted ${sats} sats by ${post.ltrRecordCount} supporter${post.ltrRecordCount === 1 ? "" : "s"}`;
}

// Flashes [element] briefly to give felt confirmation that an action (posting, rating)
// succeeded, instead of a silent state swap - see the UI/UX design review's "Duarte" note.
function flashItem(element) {
  if (!element) return;
  element.classList.add("lapis-flash");
  element.addEventListener("animationend", () => element.classList.remove("lapis-flash"), { once: true });
}

async function loadIdentity() {
  try {
    const identity = await fetchJson("/api/identity");
    identityFingerprintEl.textContent = identity.fingerprint;
  } catch (error) {
    identityFingerprintEl.textContent = "identity unavailable";
  }
}

async function loadPeers() {
  try {
    const peers = await fetchJson("/api/peers");
    peerCountEl.textContent = `${peers.peers.length} peer${peers.peers.length === 1 ? "" : "s"}`;
  } catch (error) {
    peerCountEl.textContent = "peers unavailable";
  }
}

function renderTimelineItem(post) {
  const fragment = timelineItemTemplate.content.cloneNode(true);
  const li = fragment.querySelector(".timeline-item");

  li.querySelector(".timeline-author").textContent = shortFingerprint(post.author);
  li.querySelector(".timeline-timestamp").textContent = formatRelativeTime(post.publishedAtEpochSeconds);
  li.querySelector(".timeline-text").textContent = post.text;
  li.querySelector(".timeline-ltr").textContent = ltrWeightText(post);

  const badge = li.querySelector(".timeline-credibility-badge");
  badge.textContent = credibilityBadgeText(post);
  badge.classList.add("credibility-badge", credibilityBadgeClass(post));
  // Static, developer-authored strings only - never user/peer content - so a plain title
  // assignment (not innerHTML) keeps the file's textContent-only XSS discipline intact.
  badge.title = post.credibilityLevel === "NO_PATH"
    ? "You have no trust path to this author yet - this is not a bad rating, just unknown."
    : "How much people you trust, directly or transitively, vouch for this author, from your point of view.";

  const trustForm = li.querySelector(".trust-form");
  const trustTargetInput = li.querySelector(".trust-target");
  const trustSlider = li.querySelector(".trust-slider");
  const trustSliderValue = li.querySelector(".trust-slider-value");
  const trustComment = li.querySelector(".trust-comment");
  const trustStatus = li.querySelector(".trust-status");

  trustTargetInput.value = post.authorPublicKeyHex;
  trustSlider.addEventListener("input", () => {
    trustSliderValue.textContent = `${trustSlider.value}%`;
  });

  trustForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    trustStatus.textContent = "submitting…";
    try {
      const trustMicros = Math.round((Number(trustSlider.value) / 100) * 1000000);
      await fetchJson("/api/trust", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targetPublicKeyHex: trustTargetInput.value,
          trustMicros,
          comment: trustComment.value,
        }),
      });
      trustStatus.textContent = "saved";
      // loadTimeline() wipes and rebuilds the whole list immediately after - without this
      // pause the flash animation would be cut off almost as soon as it starts.
      flashItem(li);
      await new Promise((resolve) => setTimeout(resolve, 500));
      await loadTimeline();
    } catch (error) {
      trustStatus.textContent = `failed: ${error.message}`;
    }
  });

  return fragment;
}

async function loadTimeline() {
  const includeFiltered = includeFilteredCheckbox.checked;
  timelineListEl.textContent = "";
  try {
    const posts = await fetchJson(`/api/timeline?includeFiltered=${includeFiltered}`);
    if (posts.length === 0) {
      const empty = document.createElement("li");
      empty.textContent = "No posts yet.";
      timelineListEl.appendChild(empty);
      return;
    }
    for (const post of posts) {
      timelineListEl.appendChild(renderTimelineItem(post));
    }
  } catch (error) {
    const errorItem = document.createElement("li");
    errorItem.textContent = `failed to load timeline: ${error.message}`;
    timelineListEl.appendChild(errorItem);
  }
}

composeTextEl.addEventListener("input", () => {
  composeCountEl.textContent = `${utf8ByteLength(composeTextEl.value)} / ${MAX_POST_BODY_BYTES}`;
});

composeSubmitButton.addEventListener("click", async () => {
  const text = composeTextEl.value.trim();
  if (text.length === 0) return;
  if (utf8ByteLength(text) > MAX_POST_BODY_BYTES) {
    composeStatusEl.textContent = `failed: text must be at most ${MAX_POST_BODY_BYTES} UTF-8 bytes`;
    return;
  }
  composeStatusEl.textContent = "posting…";
  try {
    await fetchJson("/api/posts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    composeTextEl.value = "";
    composeCountEl.textContent = `0 / ${MAX_POST_BODY_BYTES}`;
    composeStatusEl.textContent = "posted";
    await loadTimeline();
    flashItem(timelineListEl.querySelector(".timeline-item"));
  } catch (error) {
    composeStatusEl.textContent = `failed: ${error.message}`;
  }
});

connectForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const multiaddr = connectMultiaddrInput.value.trim();
  if (multiaddr.length === 0) return;
  connectStatusEl.textContent = "connecting…";
  try {
    await fetchJson("/api/peers/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ multiaddr }),
    });
    connectStatusEl.textContent = "connected";
    connectMultiaddrInput.value = "";
    await loadPeers();
  } catch (error) {
    connectStatusEl.textContent = `failed: ${error.message}`;
  }
});

includeFilteredCheckbox.addEventListener("change", loadTimeline);
refreshButton.addEventListener("click", () => {
  loadTimeline();
  loadPeers();
});

loadIdentity();
loadPeers();
loadTimeline();
