"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";

import { api, ApiError, unwrap } from "@/lib/api/client";

export interface Me {
  username: string;
  role: "admin" | "readonly";
  can_write: boolean;
}

/** The signed-in console user; `null` when not signed in. */
export function useMe() {
  return useQuery({
    queryKey: ["me"],
    queryFn: async (): Promise<Me | null> => {
      try {
        return (await unwrap(api.GET("/v1/auth/me"))) as Me;
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
    staleTime: 60_000,
  });
}

export async function login(username: string, password: string): Promise<Me> {
  return (await unwrap(api.POST("/v1/auth/login", { body: { username, password } }))) as Me;
}

export function useLogout() {
  const qc = useQueryClient();
  return async () => {
    await api.POST("/v1/auth/logout");
    qc.clear();
  };
}
