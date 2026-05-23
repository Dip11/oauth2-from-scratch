'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { apiFetch } from '../lib/api';

type User = {
  id: string;
  email: string;
  name: string;
  picture: string;
};

export default function HomePage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch('/auth/me')
      .then(async (res) => {
        if (res.status === 401) {
          router.replace('/login');
          return;
        }
        if (!res.ok) throw new Error(`Unexpected ${res.status}`);
        const data: User = await res.json();
        setUser(data);
      })
      .catch((err) => {
        console.error(err);
        router.replace('/login');
      })
      .finally(() => setLoading(false));
  }, [router]);

  async function handleLogout() {
    await apiFetch('/auth/logout');
    router.replace('/login');
  }

  if (loading) {
    return (
      <main className="min-h-screen flex items-center justify-center text-gray-500">
        Loading…
      </main>
    );
  }
  if (!user) return null;

  return (
    <main className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="bg-white p-8 rounded-2xl shadow-md w-full max-w-md text-center">
        <img
          src={user.picture}
          alt={user.name}
          className="w-20 h-20 rounded-full mx-auto mb-4"
        />
        <h1 className="text-2xl font-semibold">{user.name}</h1>
        <p className="text-gray-500 mb-6">{user.email}</p>
        <p className="text-xs text-gray-400 mb-6">
          User ID: <code>{user.id}</code>
        </p>
        <button
          onClick={handleLogout}
          className="w-full bg-gray-900 text-white py-2.5 rounded-lg hover:opacity-90"
        >
          Sign out
        </button>
      </div>
    </main>
  );
}
