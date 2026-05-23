import { Injectable } from '@nestjs/common';

export type Provider = 'google' | 'github' | 'microsoft';

export type User = {
  id: string; // composite: `${provider}:${providerId}` — globally unique across IdPs
  provider: Provider; // which IdP authenticated this user
  providerId: string; // the IdP's stable user ID (Google sub, GitHub id)
  email: string;
  name: string;
  picture: string;
};

@Injectable()
export class UsersStore {
  private readonly users = new Map<string, User>();

  upsert(input: Omit<User, 'id'>): User {
    const id = `${input.provider}:${input.providerId}`;
    const user: User = { id, ...input };
    this.users.set(id, user);
    return user;
  }

  findById(id: string): User | undefined {
    return this.users.get(id);
  }
}
