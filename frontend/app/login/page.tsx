export default function LoginPage() {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL;

  return (
    <main className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="bg-white p-8 rounded-2xl shadow-md w-full max-w-sm text-center">
        <h1 className="text-2xl font-semibold mb-2">Welcome</h1>
        <p className="text-gray-500 mb-6">Sign in to continue.</p>

        {/* Full-page navs, NOT fetch(). The browser must visit the IdP's domain. */}
        <a
          href={`${apiUrl}/auth/google/login`}
          className="inline-flex items-center justify-center gap-2 w-full
                     bg-black text-white py-2.5 rounded-lg hover:opacity-90 mb-3"
        >
          Sign in with Google
        </a>

        <a
          href={`${apiUrl}/auth/github/login`}
          className="inline-flex items-center justify-center gap-2 w-full
                     bg-gray-800 text-white py-2.5 rounded-lg hover:opacity-90 mb-3"
        >
          Sign in with GitHub
        </a>

        <a
          href={`${apiUrl}/auth/microsoft/login`}
          className="inline-flex items-center justify-center gap-2 w-full
                     bg-blue-700 text-white py-2.5 rounded-lg hover:opacity-90"
        >
          Sign in with Microsoft
        </a>
      </div>
    </main>
  );
}
