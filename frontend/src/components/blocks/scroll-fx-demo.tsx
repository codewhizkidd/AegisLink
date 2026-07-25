"use client";

import React from "react";
import { FullScreenScrollFX, FullScreenFXAPI } from "@/components/ui/full-screen-scroll-fx";

const sections = [
  {
    leftLabel: "Detect",
    title: <>Analyze</>,
    rightLabel: "Detect",
    background:
      "https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
  },
  {
    leftLabel: "Signals",
    title: <>Heuristics</>,
    rightLabel: "Signals",
    background:
      "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
  },
  {
    leftLabel: "Origin",
    title: <>Domain Age</>,
    rightLabel: "Origin",
    background:
      "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
  },
  {
    leftLabel: "Verdict",
    title: <>Risk Score</>,
    rightLabel: "Verdict",
    background:
      "https://images.unsplash.com/photo-1551288049-bebda4e38f71?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3",
  },
];

export function ScrollFXDemo() {
  const apiRef = React.useRef<FullScreenFXAPI>(null);

  return (
    <FullScreenScrollFX
      apiRef={apiRef}
      sections={sections}
      footer={<div>Scan Any URL</div>}
      showProgress
      durations={{ change: 0.7, snap: 800 }}
      colors={{
        pageBg: "#000000",
        stageBg: "#000000",
      }}
    />
  );
}
