import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { UsersStore } from './users.store';

// Augment Express's Request type so we can do req.user safely.
declare module 'express' {
  interface Request {
    user?: { id: string; email: string; name: string; picture: string };
  }
}

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly users: UsersStore,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const token = req.cookies?.session;

    if (!token) {
      throw new UnauthorizedException('No session cookie');
    }

    let payload: { sub: string; email: string };
    try {
      payload = await this.jwt.verifyAsync(token);
    } catch {
      // Signature failed, token expired, malformed, etc.
      throw new UnauthorizedException('Invalid session');
    }

    const user = this.users.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User no longer exists');
    }

    // Make the user available to downstream controllers via req.user.
    req.user = user;
    return true;
  }
}
