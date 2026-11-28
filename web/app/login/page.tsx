import type { Metadata } from "next";
import { Suspense } from "react";

import { SiteHeader } from "@/components/site-header";

import { LoginForm } from "./login-form";

export const metadata: Metadata = { title: "Sign in · Tripwire" };

export default function LoginPage() {
  return (
    <>
      <SiteHeader />
      <main className="flex flex-1 items-start justify-center px-4 py-16">
        <Suspense>
          <LoginForm />
        </Suspense>
      </main>
    </>
  );
}
