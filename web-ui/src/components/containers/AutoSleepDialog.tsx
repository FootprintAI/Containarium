'use client';

import { useState, useEffect } from 'react';
import { Loader2, XCircle, Moon } from 'lucide-react';
import { Modal, ModalBtn, FormField, Input } from '@/src/components/ui/Modal';

interface AutoSleepDialogProps {
  open: boolean;
  onClose: () => void;
  username: string;
  initialEnabled: boolean;
  initialIdleThresholdMinutes: number;
  onSave: (enabled: boolean, idleThresholdMinutes: number) => Promise<void>;
}

export default function AutoSleepDialog({
  open, onClose, username, initialEnabled, initialIdleThresholdMinutes, onSave,
}: AutoSleepDialogProps) {
  const [enabled, setEnabled] = useState(false);
  const [threshold, setThreshold] = useState(15);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) {
      setEnabled(initialEnabled);
      setThreshold(initialIdleThresholdMinutes > 0 ? initialIdleThresholdMinutes : 15);
      setError(null);
    }
  }, [open, initialEnabled, initialIdleThresholdMinutes]);

  const hasChanges = enabled !== initialEnabled || (enabled && threshold !== initialIdleThresholdMinutes);

  const handleSave = async () => {
    if (enabled && (threshold < 1 || threshold > 1440)) {
      setError('Threshold must be between 1 and 1440 minutes');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onSave(enabled, threshold);
      onClose();
    } catch (err) {
      setError(`Failed to save: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={() => { if (!saving) onClose(); }}
      title={`Auto-sleep — ${username}`}
      footer={
        <>
          <ModalBtn onClick={onClose} disabled={saving}>Cancel</ModalBtn>
          <ModalBtn variant="primary" onClick={handleSave} disabled={saving || !hasChanges}>
            {saving && <Loader2 size={13} className="animate-spin" />}
            Save
          </ModalBtn>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-[var(--c-red)]">
            <XCircle size={14} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <p className="text-xs text-[var(--text-muted)] leading-relaxed">
          When enabled, this container is stopped automatically after the idle threshold elapses
          with no inbound traffic, freeing its RAM and CPU. Stopped containers stay stopped until
          you start them manually — automatic wake-on-request (HTTP) is not yet enabled.
        </p>

        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={enabled}
            onChange={e => setEnabled(e.target.checked)}
            disabled={saving}
            className="h-4 w-4 rounded border-[var(--border)] bg-[var(--surface-2)] text-[var(--accent)] focus:ring-[var(--accent)]"
          />
          <Moon size={14} className={enabled ? 'text-indigo-400' : 'text-[var(--text-muted)]'} />
          <span className="text-xs text-[var(--text)]">Auto-sleep enabled</span>
        </label>

        <FormField label="Idle threshold" hint="Minutes of inactivity before the container is stopped">
          <div className="flex items-center gap-2">
            <Input
              type="number"
              min={1}
              max={1440}
              value={threshold}
              onChange={e => setThreshold(parseInt(e.target.value, 10) || 0)}
              disabled={saving || !enabled}
              className="w-24"
            />
            <span className="text-xs text-[var(--text-muted)]">minutes</span>
          </div>
        </FormField>
      </div>
    </Modal>
  );
}
