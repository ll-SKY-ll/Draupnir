// SPDX-License-Identifier: AFL-3.0
//
// Inspired by BasicFlooding.ts and WordList.ts from Draupnir.

import {
  StringEventID,
  StringUserID,
  StringRoomID,
  MatrixRoomID,
} from "@the-draupnir-project/matrix-basic-types";
import { Draupnir } from "../Draupnir";
import { DraupnirProtection } from "./Protection";
import { LogLevel } from "@vector-im/matrix-bot-sdk";
import {
  AbstractProtection,
  ActionResult,
  EDStatic,
  EventConsequences,
  Logger,
  Ok,
  OwnLifetime,
  ProtectedRoomsSet,
  Protection,
  ProtectionDescription,
  RoomEvent,
  UserConsequences,
  describeProtection,
  isError,
} from "matrix-protection-suite";
import { Type } from "@sinclair/typebox";
import { createHash } from "crypto";

const log = new Logger("DuplicateContentProtection");

const DEFAULT_MAX_REPEATS = 3;
const DEFAULT_WINDOW_SECONDS = 60;

// If an event's origin_server_ts is more than this far in the past, we treat
// it as "now" for windowing purposes. Same trick BasicFlooding uses to avoid
// federation backfill nuking the bucket. 30s is the same value it uses.
const TIMESTAMP_THRESHOLD_MS = 30000;

// Hard cap on distinct hashes per user per room. Real users post a few dozen
// distinct messages per window at the very most. If someone produces more
// distinct content than this, BasicFlooding is the right tool, not us.
const MAX_DISTINCT_HASHES_PER_USER_PER_ROOM = 200;

const DuplicateContentProtectionSettings = Type.Object(
  {
    maxRepeats: Type.Integer({
      description:
        "Number of identical messages from one user in one room within the window before action is taken.",
      default: DEFAULT_MAX_REPEATS,
      minimum: 2,
    }),
    windowSeconds: Type.Integer({
      description: "Sliding window in seconds.",
      default: DEFAULT_WINDOW_SECONDS,
      minimum: 1,
    }),
    includeMedia: Type.Boolean({
      description:
        "Also fingerprint media (images, video, audio, files, stickers) by mimetype, size, and dimensions. Catches re-uploads of identical files without downloading them.",
      default: true,
    }),
  },
  { title: "DuplicateContentProtectionSettings" }
);
type DuplicateContentProtectionSettings = EDStatic<
  typeof DuplicateContentProtectionSettings
>;

export type DuplicateContentProtectionCapabilities = {
  userConsequences: UserConsequences;
  eventConsequences: EventConsequences;
};

export type DuplicateContentProtectionDescription = ProtectionDescription<
  Draupnir,
  typeof DuplicateContentProtectionSettings,
  DuplicateContentProtectionCapabilities
>;

describeProtection<
  DuplicateContentProtectionCapabilities,
  Draupnir,
  typeof DuplicateContentProtectionSettings
>({
  name: "DuplicateContentProtection",
  description:
    "If a user posts the same message content more than `maxRepeats` times within `windowSeconds` in a single room, they will be banned for spam and their matching messages redacted. Per-room only (no cross-room aggregation). Does not publish the ban to any of your ban lists.",
  capabilityInterfaces: {
    userConsequences: "UserConsequences",
    eventConsequences: "EventConsequences",
  },
  defaultCapabilities: {
    userConsequences: "StandardUserConsequences",
    eventConsequences: "StandardEventConsequences",
  },
  configSchema: DuplicateContentProtectionSettings,
  factory: async (
    description,
    lifetime,
    protectedRoomsSet,
    draupnir,
    capabilities,
    rawSettings
  ) => {
    const parsedSettings =
      description.protectionSettings.parseConfig(rawSettings);
    if (isError(parsedSettings)) {
      return parsedSettings;
    }
    return Ok(
      new DuplicateContentProtection(
        description,
        lifetime,
        capabilities,
        protectedRoomsSet,
        draupnir,
        parsedSettings.ok.maxRepeats,
        parsedSettings.ok.windowSeconds,
        parsedSettings.ok.includeMedia
      )
    );
  },
});

type HashEntry = {
  timestamps: number[];
  eventIDs: StringEventID[];
  lastSeen: number;
};
type HashEntriesByContent = Map<string, HashEntry>;
type HashEntriesByUser = Map<StringUserID, HashEntriesByContent>;
type HashEntriesByRoom = Map<StringRoomID, HashEntriesByUser>;

/**
 * Normalise text before hashing so trivial variations don't bypass us.
 * Strips zero-width / bidi control chars (a popular bypass), collapses
 * whitespace, lowercases.
 */
function normaliseText(s: string): string {
  return s
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/**
 * Returns a stable fingerprint string for an event's content, or undefined
 * if there's nothing useful to fingerprint (state events, redactions,
 * empty bodies, unknown msgtypes, etc).
 */
function fingerprintEvent(
  event: RoomEvent,
  includeMedia: boolean
): string | undefined {
  const type = event["type"];
  const content = (event as { content?: Record<string, unknown> }).content;
  if (content === undefined || content === null) {
    return undefined;
  }

  if (type === "m.room.message") {
    const msgtype = content["msgtype"];
    if (typeof msgtype !== "string") {
      return undefined;
    }

    if (msgtype === "m.text" || msgtype === "m.notice" || msgtype === "m.emote") {
      const body = content["body"];
      if (typeof body !== "string") return undefined;
      const normalised = normaliseText(body);
      if (normalised.length === 0) return undefined;
      return `text:${sha256(normalised)}`;
    }

    if (
      includeMedia &&
      (msgtype === "m.image" ||
        msgtype === "m.video" ||
        msgtype === "m.audio" ||
        msgtype === "m.file")
    ) {
      return mediaFingerprint(msgtype, content);
    }
    return undefined;
  }

  if (type === "m.sticker" && includeMedia) {
    return mediaFingerprint("m.sticker", content);
  }

  return undefined;
}

function mediaFingerprint(
  kind: string,
  content: Record<string, unknown>
): string | undefined {
  const info = content["info"];
  if (typeof info !== "object" || info === null) return undefined;
  const i = info as Record<string, unknown>;

  const mimetype = typeof i["mimetype"] === "string" ? i["mimetype"] : "";
  const size = typeof i["size"] === "number" ? i["size"] : 0;
  const w = typeof i["w"] === "number" ? i["w"] : 0;
  const h = typeof i["h"] === "number" ? i["h"] : 0;
  const duration = typeof i["duration"] === "number" ? i["duration"] : 0;

  // Need at least *something* to identify with.
  if (size === 0 && mimetype === "") return undefined;

  return `${kind}:${mimetype}:${size}:${w}x${h}:${duration}`;
}

export class DuplicateContentProtection
  extends AbstractProtection<DuplicateContentProtectionDescription>
  implements DraupnirProtection<DuplicateContentProtectionDescription>
{
  private readonly hashEntries: HashEntriesByRoom = new Map();
  private readonly recentlyBanned: Set<StringUserID> = new Set();
  private readonly userConsequences: UserConsequences;
  private readonly eventConsequences: EventConsequences;

  public constructor(
    description: DuplicateContentProtectionDescription,
    lifetime: OwnLifetime<Protection<DuplicateContentProtectionDescription>>,
    capabilities: DuplicateContentProtectionCapabilities,
    protectedRoomsSet: ProtectedRoomsSet,
    private readonly draupnir: Draupnir,
    private readonly maxRepeats: number,
    private readonly windowSeconds: number,
    private readonly includeMedia: boolean
  ) {
    super(description, lifetime, capabilities, protectedRoomsSet, {});
    this.userConsequences = capabilities.userConsequences;
    this.eventConsequences = capabilities.eventConsequences;
  }

  public async handleTimelineEvent(
    room: MatrixRoomID,
    event: RoomEvent
  ): Promise<ActionResult<void>> {
    if (event["sender"] === this.draupnir.clientUserID) {
      return Ok(undefined);
    }
    if (event["type"] === "m.room.redaction") {
      return Ok(undefined);
    }

    const fingerprint = fingerprintEvent(event, this.includeMedia);
    if (fingerprint === undefined) {
      return Ok(undefined);
    }

    // If the event is way out of phase (federation backfill, replays),
    // rewrite to "now" so we don't wedge our window logic.
    if (Date.now() - event["origin_server_ts"] > TIMESTAMP_THRESHOLD_MS) {
      log.debug(
        `${event["event_id"]} is more than ${TIMESTAMP_THRESHOLD_MS}ms out of phase - rewriting event time to be 'now'`
      );
      event["origin_server_ts"] = Date.now();
    }

    const userMap = this.getUserMap(event.room_id);
    const hashMap = this.getHashMap(userMap, event.sender);
    const entry = this.getEntry(hashMap, fingerprint);

    const now = Date.now();
    entry.timestamps.push(event["origin_server_ts"]);
    entry.eventIDs.push(event["event_id"]);
    entry.lastSeen = now;

    // Drop timestamps that have fallen out of the window.
    const windowMs = this.windowSeconds * 1000;
    while (
      entry.timestamps.length > 0 &&
      now - (entry.timestamps[0] as number) > windowMs
    ) {
      entry.timestamps.shift();
      entry.eventIDs.shift();
    }

    if (entry.timestamps.length === 0) {
      hashMap.delete(fingerprint);
      this.enforceHashCap(hashMap);
      return Ok(undefined);
    }

    if (entry.timestamps.length >= this.maxRepeats) {
      await this.actOnDuplicate(room, event.sender, entry);
      // Clear the entry so we don't fire repeatedly on subsequent events
      // before the ban actually takes effect.
      hashMap.delete(fingerprint);
    }

    this.enforceHashCap(hashMap);
    return Ok(undefined);
  }

  private async actOnDuplicate(
    room: MatrixRoomID,
    sender: StringUserID,
    entry: HashEntry
  ): Promise<void> {
    const roomID = room.toRoomIDOrAlias();
    await this.draupnir.managementRoomOutput.logMessage(
      LogLevel.WARN,
      "DuplicateContentProtection",
      `Banning ${sender} in ${roomID} for posting the same content ${entry.timestamps.length} times within ${this.windowSeconds}s.`,
      roomID
    );

    if (this.draupnir.config.noop) {
      await this.draupnir.managementRoomOutput.logMessage(
        LogLevel.WARN,
        "DuplicateContentProtection",
        `Tried to ban ${sender} in ${roomID} but Draupnir is running in no-op mode`,
        roomID
      );
      return;
    }

    await this.userConsequences.consequenceForUserInRoom(
      roomID,
      sender,
      "duplicate-content spam"
    );

    if (this.recentlyBanned.has(sender)) {
      return;
    }
    this.recentlyBanned.add(sender);
    this.draupnir.unlistedUserRedactionQueue.addUser(sender);

    for (const eventID of entry.eventIDs) {
      await this.eventConsequences.consequenceForEvent(
        roomID,
        eventID,
        "duplicate-content spam"
      );
    }
  }

  private getUserMap(roomID: StringRoomID): HashEntriesByUser {
    const existing = this.hashEntries.get(roomID);
    if (existing !== undefined) return existing;
    const next: HashEntriesByUser = new Map();
    this.hashEntries.set(roomID, next);
    return next;
  }

  private getHashMap(
    userMap: HashEntriesByUser,
    userID: StringUserID
  ): HashEntriesByContent {
    const existing = userMap.get(userID);
    if (existing !== undefined) return existing;
    const next: HashEntriesByContent = new Map();
    userMap.set(userID, next);
    return next;
  }

  private getEntry(
    hashMap: HashEntriesByContent,
    fingerprint: string
  ): HashEntry {
    const existing = hashMap.get(fingerprint);
    if (existing !== undefined) return existing;
    const next: HashEntry = {
      timestamps: [],
      eventIDs: [],
      lastSeen: Date.now(),
    };
    hashMap.set(fingerprint, next);
    return next;
  }

  /**
   * Evict least-recently-seen hashes when a single user-room exceeds
   * MAX_DISTINCT_HASHES_PER_USER_PER_ROOM. This bounds memory; sustained
   * non-duplicate flooding should be caught by BasicFlooding instead.
   */
  private enforceHashCap(hashMap: HashEntriesByContent): void {
    if (hashMap.size <= MAX_DISTINCT_HASHES_PER_USER_PER_ROOM) return;
    const entries = [...hashMap.entries()].sort(
      ([, a], [, b]) => a.lastSeen - b.lastSeen
    );
    const toRemove = entries.length - MAX_DISTINCT_HASHES_PER_USER_PER_ROOM;
    for (let i = 0; i < toRemove; i++) {
      const entry = entries[i];
      if (entry !== undefined) {
        hashMap.delete(entry[0]);
      }
    }
  }
}