'use client';

import { useState } from 'react';
import { Loader2, UserPlus, Trash2, XCircle, CheckCircle } from 'lucide-react';
import { Modal, ModalBtn, FormField, Input, Textarea } from '@/src/components/ui/Modal';
import { Collaborator, AddCollaboratorRequest } from '@/src/types/container';

interface CollaboratorsDialogProps {
  open: boolean;
  onClose: () => void;
  ownerUsername: string;
  collaborators: Collaborator[];
  isLoading: boolean;
  onAdd: (req: AddCollaboratorRequest) => Promise<{ sshCommand: string }>;
  onRemove: (collaboratorUsername: string) => Promise<void>;
}

function formatDate(ts: number): string {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

// Key types the backend's ValidateSSHPublicKey
// (pkg/core/container/ssh_validate.go) accepts via
// golang.org/x/crypto/ssh.ParseAuthorizedKey, enumerated exactly rather
// than matched by prefix — a bare "ssh-" or a typo'd "ecdsa-whatever"
// previously passed the old startsWith check with no key body at all
// (caught in review of #1914).
const SSH_KEY_TYPES = new Set([
  'ssh-rsa',
  'ssh-dss',
  'ssh-ed25519',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'sk-ssh-ed25519@openssh.com',
  'sk-ecdsa-sha2-nistp256@openssh.com',
  'ssh-rsa-cert-v01@openssh.com',
  'ssh-dss-cert-v01@openssh.com',
  'ssh-ed25519-cert-v01@openssh.com',
  'ecdsa-sha2-nistp256-cert-v01@openssh.com',
  'ecdsa-sha2-nistp384-cert-v01@openssh.com',
  'ecdsa-sha2-nistp521-cert-v01@openssh.com',
  'sk-ssh-ed25519-cert-v01@openssh.com',
  'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com',
]);

// A floor on the base64 body's length, not a real payload check (that's
// ssh.ParseAuthorizedKey's job, server-side) — just enough to catch an
// obviously truncated or missing body. Even a 256-bit ed25519 key's
// body is already ~68 base64 characters.
const MIN_KEY_BODY_LENGTH = 20;
const BASE64_RE = /^[A-Za-z0-9+/]+=*$/;

function isValidSSHPublicKey(key: string): boolean {
  const [type, body] = key.trim().split(/\s+/, 2);
  if (!type || !SSH_KEY_TYPES.has(type)) return false;
  if (!body || body.length < MIN_KEY_BODY_LENGTH) return false;
  return BASE64_RE.test(body);
}

/** One key per non-blank line, matching `containarium collaborator add --ssh-key`'s repeatable flag. */
function parseSSHPublicKeys(text: string): string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export default function CollaboratorsDialog({ open, onClose, ownerUsername, collaborators, isLoading, onAdd, onRemove }: CollaboratorsDialogProps) {
  const [newUsername, setNewUsername] = useState('');
  const [newSSHKey, setNewSSHKey] = useState('');
  const [grantSudo, setGrantSudo] = useState(false);
  const [grantContainerRuntime, setGrantContainerRuntime] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [removingUser, setRemovingUser] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);

  const handleAdd = async () => {
    const u = newUsername.trim();
    const keys = parseSSHPublicKeys(newSSHKey);
    if (!u) { setError('Username is required'); return; }
    if (keys.length === 0) { setError('At least one SSH public key is required'); return; }
    const invalid = keys.find((k) => !isValidSSHPublicKey(k));
    if (invalid) { setError(`Invalid SSH public key format: ${invalid.slice(0, 40)}${invalid.length > 40 ? '…' : ''}`); return; }
    setAdding(true); setError(null); setSuccess(null);
    try {
      const result = await onAdd({ collaboratorUsername: u, sshPublicKeys: keys, grantSudo, grantContainerRuntime });
      setSuccess(`Added ${u} with ${keys.length} key${keys.length === 1 ? '' : 's'}. SSH: ${result.sshCommand}`);
      setNewUsername(''); setNewSSHKey(''); setGrantSudo(false); setGrantContainerRuntime(false);
    } catch (err) {
      setError(`Failed to add collaborator: ${err instanceof Error ? err.message : err}`);
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (collaboratorUsername: string) => {
    setRemovingUser(collaboratorUsername); setError(null); setSuccess(null);
    try {
      await onRemove(collaboratorUsername);
      setSuccess(`Removed ${collaboratorUsername}`);
      setConfirmRemove(null);
    } catch (err) {
      setError(`Failed to remove: ${err instanceof Error ? err.message : err}`);
    } finally {
      setRemovingUser(null);
    }
  };

  const handleClose = () => {
    if (adding) return;
    setError(null); setSuccess(null); setNewUsername(''); setNewSSHKey('');
    setGrantSudo(false); setGrantContainerRuntime(false); setConfirmRemove(null);
    onClose();
  };

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={`Collaborators — ${ownerUsername}-container`}
      size="lg"
      footer={<ModalBtn onClick={handleClose} disabled={adding}>Close</ModalBtn>}
    >
      <div className="flex flex-col gap-5">
        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-[var(--c-red)]">
            <XCircle size={14} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}
        {success && (
          <div className="flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-[var(--c-emerald)]">
            <CheckCircle size={14} className="mt-0.5 shrink-0" />
            <span>{success}</span>
          </div>
        )}

        {/* Collaborator list */}
        {isLoading ? (
          <div className="flex justify-center py-6">
            <Loader2 size={20} className="animate-spin text-[var(--text-secondary)]" />
          </div>
        ) : collaborators.length === 0 ? (
          <p className="py-4 text-center text-xs text-[var(--text-muted)]">No collaborators yet</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-[var(--border-subtle)]">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[var(--border-subtle)] bg-[var(--surface-2)]">
                  {['Username', 'Account', 'Permissions', 'Added', 'By', ''].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-[var(--text-secondary)] last:text-right">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {collaborators.map(c => (
                  <tr key={c.id || c.collaboratorUsername} className="border-b border-[var(--border-subtle)] last:border-0">
                    <td className="px-3 py-2 text-[var(--text)]">{c.collaboratorUsername}</td>
                    <td className="px-3 py-2 font-mono text-[var(--text-secondary)]">{c.accountName}</td>
                    <td className="px-3 py-2">
                      <div className="flex gap-1 flex-wrap">
                        {c.hasSudo && <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] text-[var(--c-amber)]">sudo</span>}
                        {c.hasContainerRuntime && <span className="rounded-full border border-blue-500/30 bg-blue-500/10 px-2 py-0.5 text-[10px] text-[var(--c-blue)]">docker</span>}
                        {!c.hasSudo && !c.hasContainerRuntime && <span className="text-[var(--text-muted)]">su only</span>}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-[var(--text-muted)]">{formatDate(c.addedAt)}</td>
                    <td className="px-3 py-2 text-[var(--text-muted)]">{c.createdBy || '—'}</td>
                    <td className="px-3 py-2 text-right">
                      {confirmRemove === c.collaboratorUsername ? (
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => handleRemove(c.collaboratorUsername)}
                            disabled={removingUser === c.collaboratorUsername}
                            className="rounded bg-red-600 px-2 py-1 text-[10px] text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                          >
                            {removingUser === c.collaboratorUsername ? <Loader2 size={10} className="animate-spin" /> : 'Confirm'}
                          </button>
                          <button
                            onClick={() => setConfirmRemove(null)}
                            className="rounded border border-[var(--border)] px-2 py-1 text-[10px] text-[var(--text-secondary)] hover:bg-[var(--surface-2)] transition-colors"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setConfirmRemove(c.collaboratorUsername)}
                          className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--c-red)] hover:bg-red-500/10 transition-colors"
                        >
                          <Trash2 size={13} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="border-t border-[var(--border-subtle)]" />

        {/* Add form */}
        <div>
          <p className="mb-3 text-xs font-semibold text-[var(--text-secondary)]">Add Collaborator</p>
          <div className="flex flex-col gap-3">
            <FormField label="Username">
              <Input value={newUsername} onChange={e => setNewUsername(e.target.value)} placeholder="bob" disabled={adding} />
            </FormField>
            <FormField label="SSH Public Key(s) — one per line">
              <Textarea value={newSSHKey} onChange={e => setNewSSHKey(e.target.value)} placeholder={'ssh-ed25519 AAAA... machine-a\nssh-ed25519 AAAA... machine-b'} rows={3} disabled={adding} />
            </FormField>
            <div className="flex gap-4">
              <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)] cursor-pointer">
                <input type="checkbox" checked={grantSudo} onChange={e => setGrantSudo(e.target.checked)} disabled={adding} className="accent-[var(--accent)]" />
                Grant full sudo
              </label>
              <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)] cursor-pointer">
                <input type="checkbox" checked={grantContainerRuntime} onChange={e => setGrantContainerRuntime(e.target.checked)} disabled={adding} className="accent-[var(--accent)]" />
                Container runtime (docker)
              </label>
            </div>
            <div>
              <button
                onClick={handleAdd}
                disabled={adding || !newUsername.trim() || !newSSHKey.trim()}
                className="flex items-center gap-1.5 rounded-md bg-[var(--accent)] px-3.5 py-2 text-xs font-medium text-white hover:bg-[var(--accent-hover)] transition-colors disabled:opacity-50"
              >
                {adding ? <Loader2 size={13} className="animate-spin" /> : <UserPlus size={13} />}
                {adding ? 'Adding…' : 'Add'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </Modal>
  );
}
