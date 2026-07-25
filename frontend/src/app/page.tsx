"use client";

import { useState, FormEvent, useRef } from "react";
import Image from "next/image";
import { Html as HeroFuturistic } from "@/components/ui/hero-futuristic";
import { ScrollFXDemo } from "@/components/blocks/scroll-fx-demo";
import { ThreatCarousel } from "@/components/blocks/threat-carousel";
import { SlideTabs } from "@/components/ui/slide-tabs";
import AnimatedGlowingSearchBar from "@/components/ui/animated-glowing-search-bar";
import { SiteFooter } from "@/components/blocks/site-footer";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5000";

type Result = {
  url: string;
  prediction: "safe" | "phishing";
  safePercent: number;
};

export default function Home() {
  const scanRef = useRef<HTMLDivElement>(null);
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API_URL}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.error ?? "Something went wrong.");
        return;
      }

      setResult({
        url,
        prediction: data.prediction,
        safePercent: Math.round(data.probabilities.safe * 100),
      });
    } catch {
      setError("Could not reach the detection service.");
    } finally {
      setLoading(false);
    }
  }

  const isSafe = result?.prediction === "safe";

  return (
    <>
      <nav className="fixed top-4 inset-x-0 z-[70] pointer-events-none">
        <div className="pointer-events-auto w-fit mx-auto">
          <SlideTabs />
        </div>
      </nav>
      <div id="top">
        <HeroFuturistic
          onExploreClick={() =>
            document.getElementById("how-it-works")?.scrollIntoView({ behavior: "smooth" })
          }
        />
      </div>
      <div id="how-it-works">
        <ScrollFXDemo />
      </div>
      <main
        id="scan"
        ref={scanRef}
        className="flex-1 flex flex-col md:flex-row items-center gap-12 px-6 md:px-16 py-24"
      >
      <div className="w-full md:max-w-[480px] flex flex-col items-start text-left gap-8">
        <div className="flex flex-col gap-3">
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
            Check a URL
          </h2>
          <p className="text-[var(--muted)] text-base sm:text-lg">
            Paste a link below. We&apos;ll analyze it and tell you if it&apos;s safe.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="w-full flex flex-col items-start gap-4">
          <AnimatedGlowingSearchBar
            value={url}
            onChange={setUrl}
            placeholder="https://example.com"
            required
            className="w-full"
          />
          <button
            type="submit"
            disabled={loading}
            className="rounded-lg p-[1.5px] bg-gradient-to-r from-white to-[#ff3b3b] transition
                       hover:opacity-85 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <span className="block rounded-[calc(0.5rem-1.5px)] bg-black px-6 py-3 text-base font-semibold text-white">
              {loading ? "Checking…" : "Check URL"}
            </span>
          </button>
        </form>

        {error && (
          <p className="text-sm text-[var(--accent-unsafe)]">{error}</p>
        )}

        {result && (
          <div className="w-full flex flex-col items-start gap-4 border-t border-[var(--border)] pt-8">
            <p className="font-mono text-sm text-[var(--muted)] break-all">
              {result.url}
            </p>

            <p
              className="text-6xl font-bold tracking-tight"
              style={{ color: isSafe ? "var(--accent-safe)" : "var(--accent-unsafe)" }}
            >
              {isSafe ? result.safePercent : 100 - result.safePercent}%
            </p>

            <p className="text-lg">
              {isSafe
                ? "This URL looks safe."
                : "This URL looks unsafe — proceed with caution."}
            </p>

            <a
              href={result.url}
              target="_blank"
              rel="noreferrer"
              className={`mt-2 rounded-lg px-6 py-3 text-sm font-semibold transition ${
                isSafe
                  ? "bg-[#ff3b3b] text-white hover:bg-[#ff3b3b]/85"
                  : "border border-[var(--border)] text-white hover:border-white"
              }`}
            >
              {isSafe ? "Continue to site" : "Continue anyway"}
            </a>
          </div>
        )}
      </div>
      <div className="hidden md:flex flex-1 items-center justify-center">
        <Image
          src="/right.png"
          alt=""
          width={600}
          height={600}
          className="w-full max-w-[320px] h-auto object-contain"
          priority
        />
      </div>
      </main>
      <div id="threats">
        <ThreatCarousel />
      </div>
      <SiteFooter />
    </>
  );
}
