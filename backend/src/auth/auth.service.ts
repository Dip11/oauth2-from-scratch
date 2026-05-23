import { HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';
import { RefreshTokensStore } from './refresh-tokens.store';

type GoogleTokenResponse = {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  scope: string;
  token_type: 'Bearer';
  id_token: string;
};

type GoogleUserInfo = {
  sub: string;
  email: string;
  email_verified: boolean;
  name: string;
  picture: string;
};

type GithubTokenResponse = {
  access_token: string;
  scope: string;
  token_type: 'bearer';
};

type GithubUser = {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string;
};

type GithubEmail = {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: string | null;
};

type MicrosoftTokenResponse = {
  access_token: string;
  expires_in: number;
  scope: string;
  token_type: 'Bearer';
  id_token: string;
  refresh_token?: string;
};

// The shape returned by https://graph.microsoft.com/oidc/userinfo.
// Microsoft's standard OIDC claims — note: no `picture` for many accounts.
type MicrosoftUserInfo = {
  sub: string;
  name?: string;
  family_name?: string;
  given_name?: string;
  email?: string;
  picture?: string;
};

const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

@Injectable()
export class AuthService {
  constructor(
    private readonly config: ConfigService,
    private readonly refreshTokens: RefreshTokensStore,
  ) {}

  // ---------- Refresh tokens (our own session refresh, not Google's) ----------

  /**
   * Mint a fresh opaque refresh token and store its hash.
   * familyId defaults to a new chain (for fresh logins). For rotations,
   * the caller passes the existing familyId so we can detect reuse later.
   */
  issueRefreshToken(userId: string, familyId?: string): { raw: string; expiresAt: number } {
    const raw = randomBytes(32).toString('hex');
    const expiresAt = Date.now() + REFRESH_TOKEN_TTL_MS;
    this.refreshTokens.insert(raw, {
      userId,
      familyId: familyId ?? randomBytes(16).toString('hex'),
      expiresAt,
    });
    return { raw, expiresAt };
  }

  /**
   * Validate an incoming refresh token and rotate it.
   * - Not found: bogus or already-deleted token. Reject.
   * - Already used (usedAt set): REUSE — burn the entire family, reject.
   * - Expired: reject and clean up.
   * - Otherwise: mark used, mint a new one in the same family, return both.
   */
  rotateRefreshToken(raw: string): { userId: string; newRaw: string; newExpiresAt: number } {
    const record = this.refreshTokens.find(raw);
    if (!record) {
      throw new UnauthorizedException('Unknown refresh token');
    }

    if (record.usedAt !== undefined) {
      // Same token presented twice. Either replay attack or legitimate-but-unlucky.
      // Safer to burn the whole chain than to guess.
      this.refreshTokens.revokeFamily(record.familyId);
      throw new UnauthorizedException(
        'Refresh token reuse detected; session revoked',
      );
    }

    if (Date.now() > record.expiresAt) {
      this.refreshTokens.delete(raw);
      throw new UnauthorizedException('Refresh token expired');
    }

    // Happy path: mark old token used, mint new one in same family.
    this.refreshTokens.markUsed(raw);
    const next = this.issueRefreshToken(record.userId, record.familyId);
    return { userId: record.userId, newRaw: next.raw, newExpiresAt: next.expiresAt };
  }

  revokeRefreshToken(raw: string): void {
    this.refreshTokens.delete(raw);
  }

  // ---------- Google ----------

  buildGoogleAuthUrl(): { url: string; state: string } {
    const state = randomBytes(32).toString('hex');
    const params = new URLSearchParams({
      client_id: this.config.getOrThrow<string>('GOOGLE_CLIENT_ID'),
      redirect_uri: this.config.getOrThrow<string>('GOOGLE_CALLBACK_URL'),
      response_type: 'code',
      scope: 'openid email profile',
      state,
      access_type: 'offline',
      prompt: 'consent',
    });
    const url = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    return { url, state };
  }

  async exchangeGoogleCodeForTokens(code: string): Promise<GoogleTokenResponse> {
    const body = new URLSearchParams({
      code,
      client_id: this.config.getOrThrow<string>('GOOGLE_CLIENT_ID'),
      client_secret: this.config.getOrThrow<string>('GOOGLE_CLIENT_SECRET'),
      redirect_uri: this.config.getOrThrow<string>('GOOGLE_CALLBACK_URL'),
      grant_type: 'authorization_code',
    });

    const res = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (!res.ok) {
      throw new HttpException(
        `Google token exchange failed: ${await res.text()}`,
        HttpStatus.UNAUTHORIZED,
      );
    }
    return res.json() as Promise<GoogleTokenResponse>;
  }

  async fetchGoogleUserInfo(accessToken: string): Promise<GoogleUserInfo> {
    const res = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) {
      throw new HttpException('Failed to fetch Google userinfo', HttpStatus.UNAUTHORIZED);
    }
    return res.json() as Promise<GoogleUserInfo>;
  }

  // ---------- GitHub ----------

  buildGithubAuthUrl(): { url: string; state: string } {
    const state = randomBytes(32).toString('hex');
    const params = new URLSearchParams({
      client_id: this.config.getOrThrow<string>('GITHUB_CLIENT_ID'),
      redirect_uri: this.config.getOrThrow<string>('GITHUB_CALLBACK_URL'),
      // GitHub uses a different scope vocabulary; no 'openid' (GitHub isn't OIDC).
      scope: 'read:user user:email',
      state,
      // GitHub also supports allow_signup, login, etc. — defaults are fine.
    });
    const url = `https://github.com/login/oauth/authorize?${params.toString()}`;
    return { url, state };
  }

  async exchangeGithubCodeForTokens(code: string): Promise<GithubTokenResponse> {
    const body = new URLSearchParams({
      code,
      client_id: this.config.getOrThrow<string>('GITHUB_CLIENT_ID'),
      client_secret: this.config.getOrThrow<string>('GITHUB_CLIENT_SECRET'),
      redirect_uri: this.config.getOrThrow<string>('GITHUB_CALLBACK_URL'),
    });

    const res = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        // Without this, GitHub returns the token response as URL-encoded text.
        // With it, GitHub returns JSON. We want JSON.
        Accept: 'application/json',
      },
      body: body.toString(),
    });

    if (!res.ok) {
      throw new HttpException(
        `GitHub token exchange failed: ${await res.text()}`,
        HttpStatus.UNAUTHORIZED,
      );
    }
    return res.json() as Promise<GithubTokenResponse>;
  }

  async fetchGithubUserInfo(
    accessToken: string,
  ): Promise<{ id: string; email: string; name: string; picture: string }> {
    // 1. The main /user endpoint.
    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });
    if (!userRes.ok) {
      throw new HttpException('Failed to fetch GitHub user', HttpStatus.UNAUTHORIZED);
    }
    const user = (await userRes.json()) as GithubUser;

    // 2. If the user has hidden their primary email, /user returns email: null.
    //    We have to fetch /user/emails (allowed by the user:email scope) and pick
    //    the primary verified one ourselves. This is GitHub-specific weirdness.
    let email = user.email;
    if (!email) {
      const emailRes = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      });
      if (emailRes.ok) {
        const emails = (await emailRes.json()) as GithubEmail[];
        email = emails.find((e) => e.primary && e.verified)?.email ?? null;
      }
    }
    if (!email) {
      throw new HttpException(
        'GitHub account has no verified primary email',
        HttpStatus.UNAUTHORIZED,
      );
    }

    return {
      id: String(user.id), // GitHub gives a number — normalize to string for our store
      email,
      name: user.name ?? user.login, // fall back to GitHub login if real name is hidden
      picture: user.avatar_url,
    };
  }

  // ---------- Microsoft ----------

  buildMicrosoftAuthUrl(): { url: string; state: string } {
    const state = randomBytes(32).toString('hex');
    const tenant = this.config.getOrThrow<string>('MICROSOFT_TENANT');
    const params = new URLSearchParams({
      client_id: this.config.getOrThrow<string>('MICROSOFT_CLIENT_ID'),
      redirect_uri: this.config.getOrThrow<string>('MICROSOFT_CALLBACK_URL'),
      response_type: 'code',
      // OIDC scopes — gives us id_token + a token to call /oidc/userinfo on Graph.
      scope: 'openid profile email',
      response_mode: 'query', // default, but being explicit prevents surprises
      state,
      prompt: 'select_account', // always show the account picker
    });
    const url = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize?${params.toString()}`;
    return { url, state };
  }

  async exchangeMicrosoftCodeForTokens(
    code: string,
  ): Promise<MicrosoftTokenResponse> {
    const tenant = this.config.getOrThrow<string>('MICROSOFT_TENANT');
    const body = new URLSearchParams({
      code,
      client_id: this.config.getOrThrow<string>('MICROSOFT_CLIENT_ID'),
      client_secret: this.config.getOrThrow<string>('MICROSOFT_CLIENT_SECRET'),
      redirect_uri: this.config.getOrThrow<string>('MICROSOFT_CALLBACK_URL'),
      grant_type: 'authorization_code',
      // Microsoft accepts the scope here too; required if you want a refresh token.
      scope: 'openid profile email',
    });

    const res = await fetch(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      },
    );

    if (!res.ok) {
      throw new HttpException(
        `Microsoft token exchange failed: ${await res.text()}`,
        HttpStatus.UNAUTHORIZED,
      );
    }
    return res.json() as Promise<MicrosoftTokenResponse>;
  }

  async fetchMicrosoftUserInfo(
    accessToken: string,
  ): Promise<{ id: string; email: string; name: string; picture: string }> {
    // OIDC standard endpoint, hosted on Microsoft Graph.
    // Treat the access_token as opaque — Microsoft says it may not be a JWT.
    const res = await fetch('https://graph.microsoft.com/oidc/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) {
      throw new HttpException(
        `Failed to fetch Microsoft userinfo: ${await res.text()}`,
        HttpStatus.UNAUTHORIZED,
      );
    }
    const u = (await res.json()) as MicrosoftUserInfo;

    if (!u.email) {
      // Personal MS accounts sometimes don't expose email here even with the scope.
      // Fall back to decoding the id_token or calling Graph's /me if email is required.
      throw new HttpException(
        'Microsoft account did not return an email',
        HttpStatus.UNAUTHORIZED,
      );
    }

    return {
      id: u.sub,
      email: u.email,
      name: u.name ?? ([u.given_name, u.family_name].filter(Boolean).join(' ') || u.email),
      picture: u.picture ?? '', // Microsoft accounts often don't include a picture URL
    };
  }
}
