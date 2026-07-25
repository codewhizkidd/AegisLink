"use client";

import React from "react";
import { Carousel, Card } from "@/components/ui/apple-cards-carousel";

export function ThreatCarousel() {
  const cards = data.map((card, index) => (
    <Card key={card.src} card={card} index={index} />
  ));

  return (
    <div className="w-full h-full py-20">
      <h2 className="max-w-7xl pl-4 mx-auto text-xl md:text-5xl font-bold text-neutral-800 dark:text-neutral-200 font-sans">
        Common phishing tactics to watch for.
      </h2>
      <Carousel items={cards} />
    </div>
  );
}

const ThreatContent = ({ paragraphs }: { paragraphs: string[] }) => {
  return (
    <>
      {paragraphs.map((text, index) => (
        <div
          key={"threat-content" + index}
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
    category: "Lookalike Domains",
    title: "paypa1.com is not paypal.com.",
    src: "https://images.unsplash.com/photo-1516321318423-f06f85e504b3?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
    content: (
      <ThreatContent
        paragraphs={[
          "Attackers register domains that look almost identical to the real thing — swapped letters, extra hyphens, or a different top-level domain like .info instead of .com.",
          "Always check the full domain before entering credentials, not just the brand name that appears in the link text.",
        ]}
      />
    ),
  },
  {
    category: "URL Shorteners",
    title: "You can't see where a shortened link goes.",
    src: "https://images.unsplash.com/photo-1526628953301-3e589a6a8b74?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
    content: (
      <ThreatContent
        paragraphs={[
          "Services like bit.ly or tinyurl hide the real destination. Phishing campaigns use them to bypass spam filters and to disguise malicious domains as trustworthy short links.",
          "ASTRO flags shortened links automatically — always resolve one before trusting it.",
        ]}
      />
    ),
  },
  {
    category: "Urgency & Fear",
    title: "'Your account will be suspended in 24 hours.'",
    src: "https://images.unsplash.com/photo-1584433144859-1fc3ab64a957?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
    content: (
      <ThreatContent
        paragraphs={[
          "Phishing emails manufacture urgency to short-circuit careful thinking — a locked account, an unpaid invoice, a security alert demanding immediate action.",
          "Legitimate organizations rarely threaten immediate account closure over email. Slow down and verify through a separate channel.",
        ]}
      />
    ),
  },
  {
    category: "Fake Login Pages",
    title: "It looks exactly like the real site.",
    src: "https://images.unsplash.com/photo-1563986768609-322da13575f3?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
    content: (
      <ThreatContent
        paragraphs={[
          "Modern phishing kits clone the CSS and branding of real login pages pixel-for-pixel. Visual trust is not proof of legitimacy — the URL is the only reliable signal.",
          "Newly registered domains impersonating major brands are one of the strongest heuristics ASTRO checks for.",
        ]}
      />
    ),
  },
  {
    category: "Newly Registered Domains",
    title: "Registered yesterday, targeting you today.",
    src: "https://images.unsplash.com/photo-1610563166150-b34df4f3bdff?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
    content: (
      <ThreatContent
        paragraphs={[
          "Most phishing domains are registered within days of an attack campaign and abandoned shortly after. Domain age is one of the clearest predictors of intent.",
          "ASTRO checks WHOIS registration data on every scan to catch this pattern.",
        ]}
      />
    ),
  },
];
