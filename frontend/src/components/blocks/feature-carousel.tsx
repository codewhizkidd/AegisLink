"use client";

import React from "react";
import { Carousel, Card } from "@/components/ui/apple-cards-carousel";

export function FeatureCarousel() {
  const cards = data.map((card, index) => (
    <Card key={card.src} card={card} index={index} />
  ));

  return (
    <div className="w-full h-full py-20">
      <h2 className="max-w-7xl pl-4 mx-auto text-xl md:text-5xl font-bold text-neutral-800 dark:text-neutral-200 font-sans">
        How ASTRO keeps you safe.
      </h2>
      <Carousel items={cards} />
    </div>
  );
}

const FeatureContent = ({ paragraphs }: { paragraphs: string[] }) => {
  return (
    <>
      {paragraphs.map((text, index) => (
        <div
          key={"feature-content" + index}
          className="bg-[#F5F5F7] dark:bg-neutral-800 p-8 md:p-14 rounded-3xl mb-4"
        >
          <p className="text-neutral-600 dark:text-neutral-400 text-base md:text-2xl font-sans max-w-3xl mx-auto">
            {text}
          </p>
        </div>
      ))}
    </>
  );
};

const data = [
  {
    category: "Machine Learning",
    title: "A trained classifier, not just a blocklist.",
    src: "https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
    content: (
      <FeatureContent
        paragraphs={[
          "ASTRO runs every link through a gradient boosting classifier trained on real phishing and legitimate URL datasets — not a static list of known-bad domains.",
          "That means it can flag brand-new phishing pages the moment they appear, before any blocklist has caught up.",
        ]}
      />
    ),
  },
  {
    category: "Heuristics",
    title: "30 structural signals, checked instantly.",
    src: "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
    content: (
      <FeatureContent
        paragraphs={[
          "IP addresses instead of domains, URL shorteners, @ symbols, mismatched HTTPS, excessive subdomains — each is a signal, and ASTRO checks all of them in one pass.",
          "These heuristics catch the structural tricks phishing pages rely on, independent of what the ML model decides.",
        ]}
      />
    ),
  },
  {
    category: "Domain Intelligence",
    title: "How old is this domain, really?",
    src: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
    content: (
      <FeatureContent
        paragraphs={[
          "Phishing domains are usually registered days before an attack. ASTRO pulls WHOIS data to check domain age and registration length as part of its risk assessment.",
          "A domain registered yesterday, pretending to be your bank, doesn't get the benefit of the doubt.",
        ]}
      />
    ),
  },
  {
    category: "Risk Score",
    title: "A number you can actually act on.",
    src: "https://images.unsplash.com/photo-1551288049-bebda4e38f71?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
    content: (
      <FeatureContent
        paragraphs={[
          "No cryptic labels. ASTRO returns a clear safe/unsafe percentage so you know exactly how much to trust a link before you click.",
          "Paste a URL, get a score in seconds — no account, no extension required.",
        ]}
      />
    ),
  },
  {
    category: "Real Time",
    title: "Built for the moment before you click.",
    src: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
    content: (
      <FeatureContent
        paragraphs={[
          "ASTRO analyzes links on demand — paste any URL and get a result immediately, rather than waiting on a scheduled crawl.",
          "That's the difference between catching a phishing attempt and reading about it after the fact.",
        ]}
      />
    ),
  },
  {
    category: "Open Source",
    title: "Built in the open, on GitHub.",
    src: "https://images.unsplash.com/photo-1618401471353-b98afee0b2eb?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
    content: (
      <FeatureContent
        paragraphs={[
          "The full detection pipeline — feature extraction, model, and API — is open source. Read the code, run it yourself, or contribute.",
        ]}
      />
    ),
  },
];
