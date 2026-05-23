import {
  BadRequestException,
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import type { CookieOptions } from 'express';
import { AuthService } from './auth.service';
import { UsersStore } from './users.store';
import { JwtAuthGuard } from './jwt-auth.guard';

// Short-lived state cookie set during login init.
const STATE_COOKIE_OPTS: CookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: false,
  maxAge: 10 * 60_000,
  path: '/',
};

// Access token cookie: sent on every request to the backend.
// Short-lived because if it leaks the window of exposure is tiny.
const SESSION_COOKIE_OPTS: CookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: false,
  maxAge: 15 * 60 * 1000, // 15 minutes — match access JWT expiresIn
  path: '/',
};

// Refresh token cookie: ONLY attached on /auth/* requests (path-scoped).
// Long-lived; used solely to mint new access tokens at /auth/refresh.
const REFRESH_COOKIE_OPTS: CookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: false,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: '/auth', // <-- the path trick: browser only sends this to /auth/*
};

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly users: UsersStore,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  // ---------- Google ----------

  @Get('google/login')
  googleLogin(@Res() res: Response) {
    const { url, state } = this.authService.buildGoogleAuthUrl();
    res.cookie('oauth_state_google', state, STATE_COOKIE_OPTS);
    return res.redirect(url);
  }

  @Get('google/callback')
  async googleCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    if (error)
      throw new UnauthorizedException(`Google returned error: ${error}`);
    if (!code || !state) throw new BadRequestException('Missing code or state');

    const cookieState = req.cookies?.oauth_state_google;
    if (!cookieState || cookieState !== state) {
      throw new UnauthorizedException('Invalid state — possible CSRF');
    }
    res.clearCookie('oauth_state_google', { path: '/' });

    const tokens = await this.authService.exchangeGoogleCodeForTokens(code);
    const profile = await this.authService.fetchGoogleUserInfo(
      tokens.access_token,
    );

    const user = this.users.upsert({
      provider: 'google',
      providerId: profile.sub,
      email: profile.email,
      name: profile.name,
      picture: profile.picture,
    });

    return this.issueSessionAndRedirect(res, user.id, user.email);
  }

  // ---------- GitHub ----------

  @Get('github/login')
  githubLogin(@Res() res: Response) {
    const { url, state } = this.authService.buildGithubAuthUrl();
    res.cookie('oauth_state_github', state, STATE_COOKIE_OPTS);
    return res.redirect(url);
  }

  @Get('github/callback')
  async githubCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    if (error)
      throw new UnauthorizedException(`GitHub returned error: ${error}`);
    if (!code || !state) throw new BadRequestException('Missing code or state');

    const cookieState = req.cookies?.oauth_state_github;
    if (!cookieState || cookieState !== state) {
      throw new UnauthorizedException('Invalid state — possible CSRF');
    }
    res.clearCookie('oauth_state_github', { path: '/' });

    const tokens = await this.authService.exchangeGithubCodeForTokens(code);
    const profile = await this.authService.fetchGithubUserInfo(
      tokens.access_token,
    );

    const user = this.users.upsert({
      provider: 'github',
      providerId: profile.id,
      email: profile.email,
      name: profile.name,
      picture: profile.picture,
    });

    return this.issueSessionAndRedirect(res, user.id, user.email);
  }

  // ---------- Microsoft ----------

  @Get('microsoft/login')
  microsoftLogin(@Res() res: Response) {
    const { url, state } = this.authService.buildMicrosoftAuthUrl();
    res.cookie('oauth_state_microsoft', state, STATE_COOKIE_OPTS);
    return res.redirect(url);
  }

  @Get('microsoft/callback')
  async microsoftCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    if (error)
      throw new UnauthorizedException(`Microsoft returned error: ${error}`);
    if (!code || !state) throw new BadRequestException('Missing code or state');

    const cookieState = req.cookies?.oauth_state_microsoft;
    if (!cookieState || cookieState !== state) {
      throw new UnauthorizedException('Invalid state — possible CSRF');
    }
    res.clearCookie('oauth_state_microsoft', { path: '/' });

    const tokens = await this.authService.exchangeMicrosoftCodeForTokens(code);
    const profile = await this.authService.fetchMicrosoftUserInfo(
      tokens.access_token,
    );

    const user = this.users.upsert({
      provider: 'microsoft',
      providerId: profile.id,
      email: profile.email,
      name: profile.name,
      picture: profile.picture,
    });

    return this.issueSessionAndRedirect(res, user.id, user.email);
  }

  // ---------- Shared ----------

  @UseGuards(JwtAuthGuard)
  @Get('me')
  me(@Req() req: Request) {
    return req.user;
  }

  /**
   * Exchange a refresh token for a fresh access token (and a rotated refresh).
   * POST because it has side effects (rotation, possible family revocation).
   *
   * The browser only attaches the refresh cookie to /auth/* paths, so this
   * route is the only place it surfaces.
   */
  @Post('refresh')
  async refresh(@Req() req: Request, @Res() res: Response) {
    const presented = req.cookies?.refresh_token;
    if (!presented) {
      throw new UnauthorizedException('No refresh token');
    }

    // rotateRefreshToken throws UnauthorizedException on reuse / expiry / unknown.
    const { userId, newRaw } = this.authService.rotateRefreshToken(presented);

    const user = this.users.findById(userId);
    if (!user) {
      // User was deleted after the refresh token was minted. Treat as logged out.
      this.authService.revokeRefreshToken(presented);
      throw new UnauthorizedException('User no longer exists');
    }

    const sessionToken = await this.jwt.signAsync({
      sub: user.id,
      email: user.email,
    });

    res.cookie('session', sessionToken, SESSION_COOKIE_OPTS);
    res.cookie('refresh_token', newRaw, REFRESH_COOKIE_OPTS);
    return res.json({ ok: true });
  }

  @Get('logout')
  logout(@Req() req: Request, @Res() res: Response) {
    const refresh = req.cookies?.refresh_token;
    if (refresh) {
      // Best-effort revoke of this device's refresh token.
      this.authService.revokeRefreshToken(refresh);
    }
    res.clearCookie('session', { path: '/' });
    res.clearCookie('refresh_token', { path: '/auth' });
    return res.json({ ok: true });
  }

  /**
   * After any provider's callback has resolved to a User, the rest of the
   * flow is identical: issue an access JWT + a refresh token, drop both
   * cookies, send the browser to the frontend's /home page.
   */
  private async issueSessionAndRedirect(
    res: Response,
    sub: string,
    email: string,
  ): Promise<void> {
    const sessionToken = await this.jwt.signAsync({ sub, email });
    const { raw: refreshToken } = this.authService.issueRefreshToken(sub);

    res.cookie('session', sessionToken, SESSION_COOKIE_OPTS);
    res.cookie('refresh_token', refreshToken, REFRESH_COOKIE_OPTS);

    const frontendUrl = this.config.getOrThrow<string>('FRONTEND_URL');
    res.redirect(`${frontendUrl}/home`);
  }
}
