import type { JournalEntry, JournalSink } from "../journal.js";

// CaptureJournal records appended entries in memory, for engine and runner
// tests that assert what was journaled without touching the filesystem.
export class CaptureJournal implements JournalSink {
  readonly entries: JournalEntry[] = [];
  append(entry: JournalEntry): void {
    this.entries.push(entry);
  }
}
