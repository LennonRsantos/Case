import { useEffect, useMemo, useState } from "react";
import type { MediaItem } from "../types";
import { getOriginalLanguage } from "../services/tmdb";

export const ANIMATION_GENRE_ID = 16;

const CACHE_KEY = "catalog:origLang";

// tmdb key ("tv:123") -> original_language. Cached across sessions so each
// animation title costs at most one TMDB request, ever.
function readCache(): Record<string, string> {
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    return raw ? (JSON.parse(raw) as Record<string, string>) : {};
  } catch {
    return {};
  }
}

function writeCache(cache: Record<string, string>) {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify(cache));
  } catch {
    // Storage unavailable (private mode, quota) — detection still works this session.
  }
}

function tmdbKey(item: MediaItem): string | null {
  if (!item.tmdbId) return null;
  return `${item.type === "Série" ? "tv" : "movie"}:${item.tmdbId}`;
}

// Ids of catalog items that are anime: TMDB "Animação" genre plus Japanese
// as original language. Only animation items are ever looked up.
export function useAnimeIds(items: MediaItem[]): Set<string> {
  const [languages, setLanguages] = useState<Record<string, string>>(readCache);

  const animationItems = useMemo(
    () => items.filter((i) => i.genreIds?.includes(ANIMATION_GENRE_ID) && tmdbKey(i)),
    [items]
  );

  useEffect(() => {
    const missing = [
      ...new Set(animationItems.map(tmdbKey).filter((k): k is string => k !== null && !(k in languages))),
    ];
    if (missing.length === 0) return;

    let cancelled = false;
    Promise.allSettled(
      missing.map(async (key) => {
        const [mediaType, id] = key.split(":");
        return [key, await getOriginalLanguage(Number(id), mediaType as "movie" | "tv")] as const;
      })
    ).then((results) => {
      if (cancelled) return;
      const fetched = Object.fromEntries(
        results.flatMap((r) => (r.status === "fulfilled" ? [r.value] : []))
      );
      if (Object.keys(fetched).length === 0) return;
      setLanguages((prev) => {
        const next = { ...prev, ...fetched };
        writeCache(next);
        return next;
      });
    });

    return () => {
      cancelled = true;
    };
  }, [animationItems, languages]);

  return useMemo(
    () => new Set(animationItems.filter((i) => languages[tmdbKey(i)!] === "ja").map((i) => i.id)),
    [animationItems, languages]
  );
}
