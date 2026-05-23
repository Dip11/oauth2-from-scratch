import { Injectable } from '@nestjs/common';
import { createHash } from 'crypto';

/**
 * Stored record for a single refresh token.
 * Notice: we never store the raw token. Only its SHA-256 hash.
 */
type RefreshTokenRecord = {
  userId: string;
  familyId: string; // shared across the entire rotation chain originating from one login
  expiresAt: number; // epoch ms
  usedAt?: number; // when this specific token got rotated; presence means "already used"
};

@Injectable()
export class RefreshTokensStore {
  // key: SHA-256 hex of the raw token. value: the record.
  private readonly byHash = new Map<string, RefreshTokenRecord>();

  /**
   * Hash a raw token the same way every time. Stripping non-hex would also be
   * reasonable for safety, but our tokens are crypto-random hex already.
   */
  static hash(raw: string): string {
    return createHash('sha256').update(raw).digest('hex');
  }

  insert(raw: string, record: RefreshTokenRecord): void {
    this.byHash.set(RefreshTokensStore.hash(raw), record);
  }

  find(raw: string): RefreshTokenRecord | undefined {
    return this.byHash.get(RefreshTokensStore.hash(raw));
  }

  markUsed(raw: string, at: number = Date.now()): void {
    const rec = this.byHash.get(RefreshTokensStore.hash(raw));
    if (rec) rec.usedAt = at;
  }

  /**
   * Remove a single token (used on logout for this device).
   */
  delete(raw: string): void {
    this.byHash.delete(RefreshTokensStore.hash(raw));
  }

  /**
   * Revoke every token in a family. Called when we detect reuse — meaning
   * either the legitimate user replayed (and we don't know it) or an attacker
   * is using a stolen old token. Either way: burn the chain.
   */
  revokeFamily(familyId: string): void {
    for (const [hash, rec] of this.byHash) {
      if (rec.familyId === familyId) this.byHash.delete(hash);
    }
  }
}
